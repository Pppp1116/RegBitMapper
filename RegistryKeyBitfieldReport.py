# coding: utf-8
"""
RegistryKeyBitfieldReport (Ghidra GUI friendly)

This script performs program-wide analysis to discover registry usage. It is
built to run directly from the Ghidra Script Manager (double-click execution)
and does not require any configuration. It keeps backward-compatible NDJSON
output while adding optional "extended" metadata.
"""

from __future__ import print_function

import json
import os
import re
import time
from collections import defaultdict, deque

from ghidra.app.script import GhidraScript
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.listing import Instruction
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import RefType

# ---------------------------------------------------------------------------
# Utility data containers
# ---------------------------------------------------------------------------

class ApiCallSite(object):
    def __init__(self, addr, func_name, api_name, op_type, arg_index=None, width=None):
        self.addr = addr
        self.func_name = func_name
        self.api_name = api_name
        self.op_type = op_type
        self.arg_index = arg_index
        self.width = width
        self.resolved_key = None
        self.extended = {}

    def to_dict(self):
        base = {
            "address": str(self.addr),
            "function": self.func_name,
            "api": self.api_name,
            "operation": self.op_type,
            "arg_index": self.arg_index,
            "width": self.width,
            "resolved_key": self.resolved_key,
        }
        if self.extended:
            base["extended"] = self.extended
        return base


class TaintRecord(object):
    def __init__(self, key_info, width=32, used_mask=None, ignored_mask=None, history=None, confidence=1.0, source="registry"):
        self.key_info = key_info
        self.width = width or 32
        self.used_mask = used_mask if used_mask is not None else ((1 << self.width) - 1)
        self.ignored_mask = ignored_mask if ignored_mask is not None else 0
        self.history = history or []
        self.confidence = confidence
        self.source = source

    def clone(self):
        return TaintRecord(
            self.key_info,
            self.width,
            self.used_mask,
            self.ignored_mask,
            list(self.history),
            self.confidence,
            self.source,
        )

    def _mask_limit(self):
        return (1 << self.width) - 1

    def apply_and(self, mask, note):
        limit = self._mask_limit()
        self.used_mask &= mask & limit
        self.ignored_mask |= (~mask) & limit
        self.history.append(("and", mask, note))

    def apply_or(self, mask, note):
        limit = self._mask_limit()
        self.used_mask |= mask & limit
        self.history.append(("or", mask, note))

    def apply_xor(self, mask, note):
        limit = self._mask_limit()
        self.used_mask |= mask & limit
        self.history.append(("xor", mask, note))

    def apply_not(self, note):
        limit = self._mask_limit()
        self.used_mask = (~self.used_mask) & limit
        self.history.append(("not", None, note))

    def apply_shift(self, bits, direction, note):
        if direction == "l":
            self.used_mask <<= bits
            self.ignored_mask <<= bits
        else:
            self.used_mask >>= bits
            self.ignored_mask >>= bits
        limit = self._mask_limit()
        self.used_mask &= limit
        self.ignored_mask &= limit
        self.history.append(("shift" + direction, bits, note))

    def mark_compare(self, mask, note):
        if mask is None:
            return
        limit = self._mask_limit()
        self.used_mask &= mask & limit
        self.history.append(("cmp", mask, note))

    def merge(self, other):
        if other is None or other.key_info != self.key_info:
            return self
        merged = TaintRecord(self.key_info, width=max(self.width, other.width))
        merged.used_mask = self.used_mask | other.used_mask
        merged.ignored_mask = self.ignored_mask | other.ignored_mask
        merged.history = list(self.history) + list(other.history)
        merged.confidence = min(self.confidence, other.confidence)
        merged.source = self.source or other.source
        return merged


class DecisionPoint(object):
    def __init__(self, addr, condition, taint_record, func_name=None, history=None, extended=None):
        self.addr = addr
        self.condition = condition
        self.taint_record = taint_record
        self.func_name = func_name
        self.history = history or []
        self.extended = extended or {}

    def _bits_from_mask(self, mask, width):
        if mask is None or width is None:
            return []
        return [i for i in range(width) if mask & (1 << i)]

    def to_dict(self):
        base = {
            "address": str(self.addr),
            "condition": self.condition,
            "function": self.func_name,
            "used_bits": self._bits_from_mask(self.taint_record.used_mask, self.taint_record.width),
            "ignored_bits": self._bits_from_mask(self.taint_record.ignored_mask, self.taint_record.width),
            "width": self.taint_record.width,
        }
        ext = dict(self.extended)
        if self.history:
            ext["history"] = self.history
        ext["confidence"] = self.taint_record.confidence
        if ext:
            base["extended"] = ext
        return base


class RegistryKeyInfo(object):
    def __init__(self, key_string):
        self.key_string = key_string
        self.hive, self.subkey, self.value_name = self._split_key(key_string)
        self.api_calls = []
        self.decisions = []
        self.used_mask = None
        self.ignored_mask = None
        self.width = None
        self.extended = {"unreferenced_seed": False}

    def _split_key(self, key_string):
        parts = key_string.split("\\", 1)
        hive = parts[0] if parts else None
        rest = parts[1] if len(parts) > 1 else ""
        subkey = rest
        value_name = None
        if rest and "\\" in rest:
            sub_parts = rest.rsplit("\\", 1)
            subkey = sub_parts[0]
            value_name = sub_parts[1]
        return hive, subkey, value_name

    def add_api_call(self, call):
        self.api_calls.append(call)

    def add_decision(self, decision):
        self.decisions.append(decision)

    def update_masks(self, taint):
        if taint is None:
            return
        if self.width is None:
            self.width = taint.width
        if self.used_mask is None:
            self.used_mask = taint.used_mask
        else:
            self.used_mask |= taint.used_mask
        if self.ignored_mask is None:
            self.ignored_mask = taint.ignored_mask
        else:
            self.ignored_mask |= taint.ignored_mask

    def _bits_from_mask(self, mask, width):
        if mask is None or width is None:
            return []
        return [i for i in range(width) if mask & (1 << i)]

    def to_ndjson(self):
        base = {
            "key": self.key_string,
            "hive": self.hive,
            "subkey": self.subkey,
            "value_name": self.value_name,
            "api_calls": [c.to_dict() for c in self.api_calls],
            "decisions": [d.to_dict() for d in self.decisions],
            "bit_usage": {
                "width": self.width,
                "used_bits": self._bits_from_mask(self.used_mask, self.width),
                "ignored_bits": self._bits_from_mask(self.ignored_mask, self.width),
            } if self.width else None,
        }
        if self.extended:
            base["extended"] = self.extended
        return base

    def to_markdown(self):
        lines = ["### %s" % self.key_string, ""]
        lines.append("* Hive: %s" % (self.hive or ""))
        lines.append("* Subkey: %s" % (self.subkey or ""))
        lines.append("* Value: %s" % (self.value_name or ""))
        if self.width:
            lines.append("* Width: %d" % self.width)
            lines.append("* Used bits: %s" % self._bits_from_mask(self.used_mask, self.width))
            lines.append("* Ignored bits: %s" % self._bits_from_mask(self.ignored_mask, self.width))
        if self.api_calls:
            lines.append("* API calls:")
            for call in self.api_calls:
                lines.append("  - %s at %s (%s)" % (call.api_name, call.addr, call.func_name))
        if self.decisions:
            lines.append("* Decision points:")
            for dec in self.decisions:
                lines.append("  - %s using bits %s" % (
                    dec.addr,
                    dec._bits_from_mask(dec.taint_record.used_mask, dec.taint_record.width),
                ))
        if self.extended.get("unreferenced_seed"):
            lines.append("* Warning: seed not tied to any call")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main script implementation
# ---------------------------------------------------------------------------

class RegistryKeyBitfieldReport(GhidraScript):
    REGEX_REGISTRY_STRING = re.compile(
        r"(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKCC|HKEY_CURRENT_CONFIG)",
        re.IGNORECASE,
    )
    GUID_PATTERN = re.compile(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}")
    URL_PATTERN = re.compile(r"^[a-zA-Z]+://")
    DEFAULT_DEPTH = 256
    X64_FASTCALL_ORDER = ["RCX", "RDX", "R8", "R9"]

    def run(self):
        # Defensive guard for GUI execution
        if self.currentProgram is None:
            print("No active program; aborting.")
            return

        self.monitor.setMessage("RegistryKeyBitfieldReport running…")
        self.api = FlatProgramAPI(self.currentProgram, self.monitor)
        self.args = self._parse_args()
        self.string_index = {}
        self.registry_infos = {}
        self.func_summaries = {}
        self.call_depths = {}
        self.pattern_cache = None
        self.seeds_seen = set()
        self.output_dir = self._get_output_dir()
        try:
            if not os.path.isdir(self.output_dir):
                os.makedirs(self.output_dir)
        except Exception:
            pass

        self._log("Collecting registry strings…")
        self._collect_registry_strings()
        self._log("Building API pattern registry…")
        self._build_api_pattern_registry()
        self._log("Scanning registry APIs…")
        self._scan_registry_calls()
        self._log("Running program-wide analysis…")
        self._analyze_program()
        self._log("Verifying seed coverage…")
        self._mark_unreferenced_seeds()
        self._log("Writing outputs…")
        self._write_outputs()
        self._log("Done.")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _parse_args(self):
        defaults = {
            "depth": self.DEFAULT_DEPTH,
            "debug": False,
            "debug_trace": False,
            "output_dir": None,
            "additional_apis": "",
        }
        args = defaults.copy()
        raw_args = self.getScriptArgs()
        if raw_args:
            for arg in raw_args:
                if "=" not in arg:
                    continue
                k, v = arg.split("=", 1)
                if k == "depth":
                    try:
                        args[k] = int(v)
                    except Exception:
                        pass
                elif k in ("debug", "debug_trace"):
                    args[k] = v.lower() in ("1", "true", "yes", "on")
                elif k in ("output_dir", "additional_apis"):
                    args[k] = v
        return args

    def _get_output_dir(self):
        custom = self.args.get("output_dir")
        if custom:
            return os.path.abspath(custom)
        home = os.path.expanduser("~")
        program_name = self.currentProgram.getName() if self.currentProgram else "program"
        return os.path.abspath(os.path.join(home, "regkeys", program_name))

    def _log(self, msg):
        if self.args.get("debug"):
            print(msg)

    def _trace(self, msg):
        if self.args.get("debug_trace"):
            print(msg)

    # ------------------------------------------------------------------
    # Registry string collection
    # ------------------------------------------------------------------
    def _collect_registry_strings(self):
        listing = self.currentProgram.getListing()
        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext():
            if self.monitor.isCancelled():
                break
            data = data_iter.next()
            try:
                if data.hasStringValue():
                    s = str(data.getValue())
                else:
                    continue
            except Exception:
                continue
            if not s:
                continue
            if self._is_registry_like_string(s):
                addr = data.getMinAddress()
                self.string_index[addr] = s
                if s not in self.registry_infos:
                    self.registry_infos[s] = RegistryKeyInfo(s)
        self._log("Indexed %d registry-like strings" % len(self.string_index))

    def _is_registry_like_string(self, s):
        if not s or len(s) < 3:
            return False
        if self.URL_PATTERN.match(s):
            return False
        if "\\" not in s:
            return False
        if not self.REGEX_REGISTRY_STRING.search(s):
            return False
        return True

    # ------------------------------------------------------------------
    # API registry
    # ------------------------------------------------------------------
    def _build_api_pattern_registry(self):
        # Build a regex that covers discovered external symbols and defaults
        names = set()
        external_manager = self.currentProgram.getExternalManager()
        try:
            symbols = external_manager.getExternalSymbols()
            while symbols.hasNext():
                sym = symbols.next()
                nm = sym.getLabel()
                if nm:
                    names.add(nm)
        except Exception:
            pass
        default_patterns = [r"Reg.*", r"Nt.*", r"Zw.*", r"Rtl.*", r"Cm.*"]
        if self.args.get("additional_apis"):
            default_patterns.append(self.args["additional_apis"])
        combined = "|".join(default_patterns + [re.escape(n) for n in names if self._looks_registry_api(n)])
        try:
            self.pattern_cache = re.compile("^(%s)" % combined, re.IGNORECASE)
        except Exception:
            self.pattern_cache = re.compile(r"^(Reg.*|Nt.*|Zw.*|Rtl.*|Cm.*)", re.IGNORECASE)

    def _looks_registry_api(self, name):
        low = name.lower()
        return low.startswith("reg") or low.startswith("nt") or low.startswith("zw") or "registry" in low or "cm" in low

    def _is_registry_api(self, name):
        if not name:
            return False
        if self.pattern_cache and self.pattern_cache.match(name):
            return True
        return False

    # ------------------------------------------------------------------
    # API call scanning
    # ------------------------------------------------------------------
    def _scan_registry_calls(self):
        fm = self.currentProgram.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            if self.monitor.isCancelled():
                break
            inst_iter = self.currentProgram.getListing().getInstructions(func.getBody(), True)
            while inst_iter.hasNext():
                if self.monitor.isCancelled():
                    break
                inst = inst_iter.next()
                if not inst.getFlowType().isCall():
                    continue
                callee_name = self._resolve_callee_name(inst, fm)
                if not self._is_registry_api(callee_name):
                    continue
                key_info, resolved_key = self._resolve_call_key(inst)
                api_call = ApiCallSite(inst.getMinAddress(), func.getName(), callee_name, "call")
                api_call.resolved_key = resolved_key
                api_call.extended = self._capture_call_arguments(inst)
                if key_info is not None:
                    key_info.add_api_call(api_call)
                elif resolved_key:
                    info = self.registry_infos.get(resolved_key)
                    if info is None:
                        info = RegistryKeyInfo(resolved_key)
                        self.registry_infos[resolved_key] = info
                    info.add_api_call(api_call)
        self._log("Finished scanning registry API call sites")

    def _resolve_callee_name(self, inst, fm):
        refs = inst.getReferencesFrom()
        callee_name = None
        for ref in refs:
            if ref.getReferenceType().isCall():
                callee_func = fm.getFunctionAt(ref.getToAddress())
                if callee_func:
                    callee_name = callee_func.getName()
                else:
                    sym = self.api.getSymbolAt(ref.getToAddress())
                    if sym:
                        callee_name = sym.getName()
                break
        return callee_name

    def _resolve_call_key(self, inst):
        refs = inst.getReferencesFrom()
        for ref in refs:
            to_addr = ref.getToAddress()
            if to_addr in self.string_index:
                s = self.string_index[to_addr]
                return self.registry_infos.get(s), s
        try:
            pcode = inst.getPcode()
        except Exception:
            return None, None
        for op in pcode:
            if op is None:
                continue
            for i in range(op.getNumInputs()):
                vn = op.getInput(i)
                addr = None
                if vn.isConstant():
                    try:
                        addr = self.api.toAddr(vn.getOffset())
                    except Exception:
                        addr = None
                elif vn.isAddress():
                    addr = vn.getAddress()
                if addr in self.string_index:
                    s = self.string_index[addr]
                    return self.registry_infos.get(s), s
        return None, None

    def _capture_call_arguments(self, inst):
        args = {}
        try:
            pcode = inst.getPcode()
        except Exception:
            return args
        for op in pcode:
            if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND):
                for idx in range(op.getNumInputs()):
                    vn = op.getInput(idx)
                    try:
                        args[idx] = str(vn)
                    except Exception:
                        pass
        return args

    # ------------------------------------------------------------------
    # Analysis engine
    # ------------------------------------------------------------------
    def _analyze_program(self):
        fm = self.currentProgram.getFunctionManager()
        func_iter = fm.getFunctions(True)
        for func in func_iter:
            if self.monitor.isCancelled():
                break
            self._analyze_function(func, depth=0, incoming_state={})

    def _analyze_function(self, func, depth, incoming_state):
        if func is None:
            return {}
        if depth > self.args.get("depth", self.DEFAULT_DEPTH):
            return {}
        func_key = func.getEntryPoint()
        prev_depth = self.call_depths.get(func_key)
        if prev_depth is not None and prev_depth <= depth:
            return self.func_summaries.get(func_key, {})
        self.call_depths[func_key] = depth

        listing = self.currentProgram.getListing()
        bbm = BasicBlockModel(self.currentProgram)
        try:
            blocks_iter = bbm.getCodeBlocksContaining(func.getBody(), self.monitor)
            blocks = [b for b in blocks_iter]
        except Exception:
            blocks = []
        if not blocks:
            blocks = self._fallback_blocks(func)

        block_states_in = {}
        worklist = deque()
        for blk in blocks:
            block_states_in[blk] = dict(incoming_state)
            worklist.append(blk)

        iteration_guard = 0
        max_iter = max(len(blocks) * 32, 128)

        while worklist:
            if self.monitor.isCancelled():
                break
            blk = worklist.popleft()
            iteration_guard += 1
            if iteration_guard > max_iter:
                break
            state = dict(block_states_in.get(blk, {}))
            inst_iter = listing.getInstructions(blk, True)
            last_inst = None
            while inst_iter.hasNext():
                if self.monitor.isCancelled():
                    break
                inst = inst_iter.next()
                last_inst = inst
                self._propagate_taint(inst, state, func, depth)
            for succ in blk.getDestinations(self.monitor):
                succ_block = succ.getDestinationBlock()
                if succ_block is None:
                    continue
                prev_state = block_states_in.get(succ_block)
                merged = self._merge_states(prev_state, state)
                if merged != prev_state:
                    block_states_in[succ_block] = merged
                    worklist.append(succ_block)
            if last_inst is not None:
                self._capture_decision(last_inst, state, func)

        self.func_summaries[func_key] = {"__ret__": self._summarize_return(func, block_states_in)}
        return self.func_summaries[func_key]

    def _fallback_blocks(self, func):
        try:
            bb = BasicBlockModel(self.currentProgram)
            return [bb.getCodeBlockAt(func.getEntryPoint(), self.monitor)]
        except Exception:
            return []

    def _merge_states(self, prev_state, new_state):
        if prev_state is None:
            return dict(new_state)
        merged = dict(prev_state)
        changed = False
        for k, v in new_state.items():
            if k not in merged:
                merged[k] = v
                changed = True
            else:
                m = merged[k].merge(v)
                if m.used_mask != merged[k].used_mask or m.ignored_mask != merged[k].ignored_mask:
                    merged[k] = m
                    changed = True
        return merged if changed else prev_state

    def _propagate_taint(self, inst, state, func, depth):
        try:
            pcode = inst.getPcode()
        except Exception:
            pcode = []
        for op in pcode:
            opc = op.getOpcode()
            if opc in (PcodeOp.COPY, PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.PTRSUB, PcodeOp.PTRADD, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.MULTIEQUAL):
                self._taint_copy(op, state)
            elif opc in (PcodeOp.LOAD,):
                self._seed_from_string_load(op, state)
            elif opc in (PcodeOp.STORE,):
                self._taint_store(op, state)
            elif opc in (PcodeOp.BOOL_AND, PcodeOp.BOOL_OR, PcodeOp.BOOL_XOR, PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_NEGATE):
                self._taint_bitwise(op, state)
            elif opc in (PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_SGE, PcodeOp.INT_SGREATER, PcodeOp.INT_GE, PcodeOp.INT_GREATER):
                self._taint_compare(op, state)
            elif opc in (PcodeOp.CALL, PcodeOp.CALLIND):
                self._handle_call(op, state, func, depth)
            elif opc == PcodeOp.RETURN:
                pass
        self._assembly_fallback(inst, state)

    def _taint_copy(self, op, state):
        dest = op.getOutput()
        if dest is None:
            return
        src = op.getInput(0) if op.getNumInputs() > 0 else None
        if src is None:
            return
        tr = state.get(self._varnode_key(src))
        if tr:
            state[self._varnode_key(dest)] = tr.clone()

    def _taint_store(self, op, state):
        if op.getNumInputs() < 3:
            return
        val = op.getInput(2)
        ptr = op.getInput(1)
        tr = state.get(self._varnode_key(val))
        if tr and ptr is not None:
            slot = self._pointer_slot(ptr)
            if slot:
                state[slot] = tr.clone()

    def _taint_bitwise(self, op, state):
        dest = op.getOutput()
        if dest is None:
            return
        inp0 = op.getInput(0) if op.getNumInputs() > 0 else None
        inp1 = op.getInput(1) if op.getNumInputs() > 1 else None
        base_tr = state.get(self._varnode_key(inp0)) or state.get(self._varnode_key(inp1))
        if base_tr is None:
            return
        tr = base_tr.clone()
        opc = op.getOpcode()
        if inp1 is not None and inp1.isConstant():
            const = inp1.getOffset()
            if opc == PcodeOp.INT_AND:
                tr.apply_and(const, str(op))
            elif opc == PcodeOp.INT_OR:
                tr.apply_or(const, str(op))
            elif opc == PcodeOp.INT_XOR:
                tr.apply_xor(const, str(op))
            elif opc in (PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT):
                tr.apply_shift(const, "l" if opc == PcodeOp.INT_LEFT else "r", str(op))
        elif opc == PcodeOp.INT_NEGATE:
            tr.apply_not(str(op))
        tr.history.append(("bitop", opc, str(op)))
        state[self._varnode_key(dest)] = tr

    def _taint_compare(self, op, state):
        dest = op.getOutput()
        if dest is None:
            return
        inp0 = op.getInput(0) if op.getNumInputs() > 0 else None
        inp1 = op.getInput(1) if op.getNumInputs() > 1 else None
        tr = state.get(self._varnode_key(inp0)) or state.get(self._varnode_key(inp1))
        if tr is None:
            return
        clone = tr.clone()
        if inp0 is not None and inp0.isConstant():
            clone.mark_compare(inp0.getOffset(), str(op))
        elif inp1 is not None and inp1.isConstant():
            clone.mark_compare(inp1.getOffset(), str(op))
        clone.history.append(("cmp", str(op), None))
        state[self._varnode_key(dest)] = clone

    def _seed_from_string_load(self, op, state):
        if op.getOpcode() not in (PcodeOp.LOAD, PcodeOp.COPY):
            return
        dest = op.getOutput()
        pointer = None
        if op.getOpcode() == PcodeOp.LOAD and op.getNumInputs() > 1:
            pointer = op.getInput(1)
        elif op.getOpcode() == PcodeOp.COPY and op.getNumInputs() > 0:
            pointer = op.getInput(0)
        if dest is None or pointer is None:
            return
        addr = None
        if pointer.isConstant():
            try:
                addr = self.api.toAddr(pointer.getOffset())
            except Exception:
                addr = None
        elif pointer.isAddress():
            addr = pointer.getAddress()
        if addr and addr in self.string_index:
            key_str = self.string_index[addr]
            self.seeds_seen.add(key_str)
            key_info = self.registry_infos.get(key_str)
            if key_info is None:
                key_info = RegistryKeyInfo(key_str)
                self.registry_infos[key_str] = key_info
            tr = TaintRecord(key_info, width=max(dest.getSize() * 8, 8))
            tr.history.append(("seed-string", key_str, str(op)))
            state[self._varnode_key(dest)] = tr

    def _handle_call(self, op, state, func, depth):
        callee_func = None
        callee_name = None
        fm = self.currentProgram.getFunctionManager()
        if op.getOpcode() == PcodeOp.CALL and op.getNumInputs() > 0:
            callee_addr = op.getInput(0).getAddress()
            callee_func = fm.getFunctionAt(callee_addr)
            callee_name = callee_func.getName() if callee_func else None
        elif op.getOpcode() == PcodeOp.CALLIND:
            callee_func, callee_name = self._resolve_indirect_callee(op, fm)

        arg_taints = []
        for i in range(1, op.getNumInputs()):
            vn = op.getInput(i)
            arg_taints.append(state.get(self._varnode_key(vn)))
        dest = op.getOutput()

        if callee_name and self._is_registry_api(callee_name):
            tr = self._seed_taint_from_registry_call(callee_name, op, arg_taints, dest, state)
            if tr and dest is not None:
                state[self._varnode_key(dest)] = tr
            if tr and callee_func is not None:
                self._taint_return_to_callers(func, tr)
            return

        if callee_func and (dest is not None or any(arg_taints)):
            entry_state = {}
            for idx in range(min(len(arg_taints), len(self.X64_FASTCALL_ORDER))):
                reg_name = self.X64_FASTCALL_ORDER[idx]
                vn_key = ("register", reg_name, None)
                tr = arg_taints[idx]
                if tr:
                    entry_state[vn_key] = tr.clone()
            if depth < self.args.get("depth", self.DEFAULT_DEPTH):
                callee_summary = self._analyze_function(callee_func, depth + 1, entry_state)
                ret_taint = self._taint_from_summary(callee_summary)
                if ret_taint and dest is not None:
                    state[self._varnode_key(dest)] = ret_taint.clone()
            elif any(arg_taints) and dest is not None:
                state[self._varnode_key(dest)] = arg_taints[0].clone()

    def _resolve_indirect_callee(self, call_op, fm):
        inst_addr = call_op.getSeqnum().getTarget()
        inst = self.api.getInstructionAt(inst_addr)
        callee_name = None
        func = None
        if inst:
            refs = inst.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType().isCall():
                    func = fm.getFunctionAt(ref.getToAddress())
                    if func:
                        callee_name = func.getName()
                    else:
                        sym = self.api.getSymbolAt(ref.getToAddress())
                        if sym:
                            callee_name = sym.getName()
                    break
        return func, callee_name

    def _seed_taint_from_registry_call(self, name, call_op, arg_taints, out_vn, state):
        base_tr = None
        for tr in arg_taints:
            if tr is not None:
                base_tr = tr
                break
        if base_tr is None:
            resolved = self._resolve_constant_string(call_op)
            if resolved:
                info = self.registry_infos.get(resolved)
                if info is None:
                    info = RegistryKeyInfo(resolved)
                    self.registry_infos[resolved] = info
                base_tr = TaintRecord(info, width=32, source="registry-api")
                base_tr.history.append(("api-seed", name, resolved))
        if base_tr is None:
            synthetic = "unknown:%s@%s" % (name, call_op.getSeqnum().getTarget())
            info = self.registry_infos.get(synthetic)
            if info is None:
                info = RegistryKeyInfo(synthetic)
                self.registry_infos[synthetic] = info
            base_tr = TaintRecord(info, width=32, source="registry-api")
            base_tr.history.append(("api-synthetic", name, None))
        if out_vn is not None:
            return base_tr.clone()
        return None

    def _resolve_constant_string(self, call_op, arg_index=None):
        for op in [call_op]:
            for i in range(op.getNumInputs()):
                if arg_index is not None and i != arg_index:
                    continue
                vn = op.getInput(i)
                addr = None
                if vn.isConstant():
                    try:
                        addr = self.api.toAddr(vn.getOffset())
                    except Exception:
                        addr = None
                elif vn.isAddress():
                    addr = vn.getAddress()
                if addr in self.string_index:
                    return self.string_index[addr]
        return None

    def _taint_return_to_callers(self, func, tr):
        if func is None or tr is None:
            return
        func_key = func.getEntryPoint()
        summary = self.func_summaries.get(func_key)
        if summary is None:
            self.func_summaries[func_key] = {"__ret__": tr.clone()}
        else:
            summary["__ret__"] = tr.clone()

    def _taint_from_summary(self, summary):
        if summary is None:
            return None
        if isinstance(summary, dict):
            return summary.get("__ret__")
        return None

    def _assembly_fallback(self, inst, state):
        if not isinstance(inst, Instruction):
            return
        mnem = inst.getMnemonicString().upper()
        ops = [str(op) for op in inst.getOpObjects(None)] if hasattr(inst, "getOpObjects") else []
        if mnem in ("TEST", "CMP") and len(ops) >= 2:
            try:
                mask = int(str(ops[1]).replace("0x", ""), 16)
            except Exception:
                return
            src_vn = inst.getDefaultOperandRepresentationList()[0] if hasattr(inst, "getDefaultOperandRepresentationList") else None
            if src_vn is None:
                return
            vn_key = ("asm", inst.getMinAddress(), 0)
            tr = state.get(vn_key)
            if tr:
                tr.mark_compare(mask, "asm-%s" % mnem)
                tr.history.append(("asm-cmp", mnem, mask))
        if mnem in ("SHL", "SAL", "SHR", "SAR") and len(ops) >= 2:
            try:
                bits = int(str(ops[1]).replace("0x", ""), 16)
            except Exception:
                return
            for k, tr in list(state.items()):
                if isinstance(k, tuple) and k[0] == "asm" and k[1] == inst.getMinAddress():
                    tr.apply_shift(bits, "l" if mnem in ("SHL", "SAL") else "r", "asm-shift")

    def _capture_decision(self, inst, state, func):
        flow = inst.getFlowType()
        if not flow.isConditional():
            return
        pcode = []
        try:
            pcode = inst.getPcode()
        except Exception:
            pass
        for op in pcode:
            if op.getOpcode() in (PcodeOp.CBRANCH, PcodeOp.BRANCHIND, PcodeOp.BRANCH):
                cond_vn = op.getInput(1) if op.getNumInputs() > 1 else None
                taint = state.get(self._varnode_key(cond_vn)) if cond_vn else None
                if taint is None:
                    continue
                dp = DecisionPoint(inst.getMinAddress(), str(inst), taint.clone(), func_name=func.getName())
                taint.key_info.add_decision(dp)
                taint.key_info.update_masks(taint)

    # ------------------------------------------------------------------
    # Seed coverage check
    # ------------------------------------------------------------------
    def _mark_unreferenced_seeds(self):
        for key_str, info in self.registry_infos.items():
            if key_str not in self.seeds_seen:
                if not info.api_calls and not info.decisions:
                    info.extended["unreferenced_seed"] = True

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    def _write_outputs(self):
        program_name = self.currentProgram.getName() if self.currentProgram else "program"
        ndjson_path = os.path.join(self.output_dir, "%s.registry_bitfields.ndjson" % program_name)
        md_path = os.path.join(self.output_dir, "%s.registry_bitfields.md" % program_name)
        try:
            with open(ndjson_path, "w") as f:
                for key in sorted(self.registry_infos.keys()):
                    info = self.registry_infos[key]
                    f.write(json.dumps(info.to_ndjson()))
                    f.write("\n")
        except Exception as e:
            self._log("Failed to write NDJSON: %s" % e)
        try:
            with open(md_path, "w") as f:
                f.write("# Registry Bitfield Report\n\n")
                for key in sorted(self.registry_infos.keys()):
                    info = self.registry_infos[key]
                    f.write(info.to_markdown())
                    f.write("\n")
        except Exception as e:
            self._log("Failed to write Markdown: %s" % e)

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------
    def _varnode_key(self, vn):
        if vn is None:
            return None
        try:
            if vn.isRegister():
                return ("register", vn.getAddress(), vn.getSize())
            if vn.isConstant():
                return ("const", vn.getOffset(), vn.getSize())
            if vn.isUnique():
                return ("unique", vn.getOffset(), vn.getSize())
            if vn.isAddrTied():
                return ("ram", vn.getAddress(), vn.getSize())
        except Exception:
            pass
        return ("vn", str(vn), None)

    def _pointer_slot(self, vn):
        if vn is None:
            return None
        try:
            if vn.isConstant():
                return ("ptr", ("const", vn.getOffset()), vn.getSize())
            if vn.isAddress():
                return ("ptr", ("addr", vn.getAddress().getOffset()), vn.getSize())
        except Exception:
            pass
        return None

    def _summarize_return(self, func, block_states):
        # Try to find a tainted register used at RET
        ret_tr = None
        ep = func.getEntryPoint()
        listing = self.currentProgram.getListing()
        inst_iter = listing.getInstructions(func.getBody(), True)
        last_ret = None
        while inst_iter.hasNext():
            inst = inst_iter.next()
            if inst.getFlowType().isReturn():
                last_ret = inst
                break
        if last_ret is None:
            return None
        try:
            pcode = last_ret.getPcode()
        except Exception:
            pcode = []
        for op in pcode:
            if op.getOpcode() == PcodeOp.RETURN and op.getNumInputs() > 1:
                vn = op.getInput(1)
                for blk, st in block_states.items():
                    tr = st.get(self._varnode_key(vn))
                    if tr:
                        if ret_tr is None:
                            ret_tr = tr.clone()
                        else:
                            ret_tr = ret_tr.merge(tr)
        return ret_tr


# Entry point for Ghidra headless compatibility
if __name__ == "__main__":
    script = RegistryKeyBitfieldReport()
    script.run()
