# coding: utf-8
"""
RegistryKeyBitfieldReport (Jython)

Production-grade Jython implementation of the RegistryKeyBitfieldReport script for
Ghidra 12. The script scans for registry-related strings, correlates them with
Windows registry APIs, performs lightweight taint tracking, and reports how registry
values influence conditional branches (bit usage).

The NDJSON/Markdown schema remains backward compatible with the historical Java
implementation while allowing non-breaking extensions via extra fields.
"""

from __future__ import print_function

import json
import os
import re
import time
from collections import defaultdict, deque

from ghidra.app.script import GhidraScript
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import RefType

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class ApiCallSite(object):
    """Represents a registry-related API call site."""

    def __init__(self, addr, func_name, api_name, op_type, arg_index=None, width=None):
        self.addr = addr
        self.func_name = func_name
        self.api_name = api_name
        self.op_type = op_type
        self.arg_index = arg_index
        self.width = width
        self.resolved_key = None

    def to_dict(self):
        return {
            "address": str(self.addr),
            "function": self.func_name,
            "api": self.api_name,
            "operation": self.op_type,
            "arg_index": self.arg_index,
            "width": self.width,
            "resolved_key": self.resolved_key,
        }


class TaintRecord(object):
    """Tracks taint originating from a registry key/value."""

    def __init__(self, key_info, width=32, used_mask=None, ignored_mask=None, history=None):
        self.key_info = key_info
        self.width = width
        self.used_mask = used_mask if used_mask is not None else ((1 << width) - 1)
        self.ignored_mask = ignored_mask if ignored_mask is not None else 0
        self.history = history or []

    def clone(self):
        return TaintRecord(self.key_info, self.width, self.used_mask, self.ignored_mask, list(self.history))

    def apply_and(self, mask):
        self.used_mask &= mask & ((1 << self.width) - 1)
        self.ignored_mask |= (~mask) & ((1 << self.width) - 1)
        self.history.append(("and", mask))

    def apply_shift(self, bits, direction):
        if direction == "l":
            self.used_mask <<= bits
        elif direction == "r":
            self.used_mask >>= bits
        self.used_mask &= ((1 << self.width) - 1)
        self.history.append(("shift" + direction, bits))

    def merge(self, other):
        if other is None:
            return self
        merged = TaintRecord(self.key_info, width=max(self.width, other.width))
        merged.used_mask = self.used_mask | other.used_mask
        merged.ignored_mask = self.ignored_mask | other.ignored_mask
        merged.history = list(self.history) + list(other.history)
        return merged


class DecisionPoint(object):
    """Represents a conditional branch influenced by registry-derived data."""

    def __init__(self, addr, condition, taint_record, func_name=None):
        self.addr = addr
        self.condition = condition
        self.taint_record = taint_record
        self.func_name = func_name

    def to_dict(self):
        bits = self._bits_from_mask(self.taint_record.used_mask, self.taint_record.width)
        ignored = self._bits_from_mask(self.taint_record.ignored_mask, self.taint_record.width)
        return {
            "address": str(self.addr),
            "condition": self.condition,
            "function": self.func_name,
            "used_bits": bits,
            "ignored_bits": ignored,
            "width": self.taint_record.width,
        }

    def _bits_from_mask(self, mask, width):
        out = []
        for i in range(width):
            if mask & (1 << i):
                out.append(i)
        return out


class RegistryKeyInfo(object):
    """Aggregates information about a registry key/value."""

    def __init__(self, key_string):
        self.key_string = key_string
        self.hive, self.subkey, self.value_name = self._split_key(key_string)
        self.api_calls = []
        self.decisions = []
        self.used_mask = None
        self.ignored_mask = None
        self.width = None

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

    def to_ndjson(self):
        return {
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

    def _bits_from_mask(self, mask, width):
        if mask is None or width is None:
            return []
        out = []
        for i in range(width):
            if mask & (1 << i):
                out.append(i)
        return out

    def to_markdown(self):
        lines = []
        lines.append("### %s" % self.key_string)
        lines.append("")
        lines.append("* Hive: %s" % (self.hive or ""))
        lines.append("* Subkey: %s" % (self.subkey or ""))
        lines.append("* Value: %s" % (self.value_name or ""))
        if self.width:
            used = self._bits_from_mask(self.used_mask, self.width)
            ignored = self._bits_from_mask(self.ignored_mask, self.width)
            lines.append("* Width: %d" % self.width)
            lines.append("* Used bits: %s" % used)
            lines.append("* Ignored bits: %s" % ignored)
        if self.api_calls:
            lines.append("* API calls:")
            for call in self.api_calls:
                lines.append("  - %s at %s (%s)" % (call.api_name, call.addr, call.func_name))
        if self.decisions:
            lines.append("* Decision points:")
            for dec in self.decisions:
                lines.append("  - %s using bits %s" % (dec.addr, dec._bits_from_mask(dec.taint_record.used_mask, dec.taint_record.width)))
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main script
# ---------------------------------------------------------------------------

class RegistryKeyBitfieldReport(GhidraScript):
    REGEX_DEFAULT_APIS = re.compile(r"^(Reg.*|Zw.*|Nt.*|Cm.*)(Key|Value)")
    REGEX_REGISTRY_STRING = re.compile(r"^(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKCC|HKEY_CURRENT_CONFIG)", re.IGNORECASE)
    GUID_PATTERN = re.compile(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}")
    URL_PATTERN = re.compile(r"^[a-zA-Z]+://")

    def run(self):
        self.api = FlatProgramAPI(self.currentProgram, self.monitor)
        self.args = self._parse_args()
        self.string_index = {}  # Address -> string
        self.registry_infos = {}  # string -> RegistryKeyInfo
        self.output_dir = self._get_output_dir()
        if not os.path.isdir(self.output_dir):
            os.makedirs(self.output_dir)

        self._log("Arguments: %s" % self.args)
        self._log("Collecting registry-like strings...")
        self._collect_registry_strings()
        self._log("Scanning for registry API calls...")
        self._scan_registry_calls()
        self._log("Running taint analysis around decision points...")
        self._analyze_branches()
        self._log("Writing outputs...")
        self._write_outputs()
        self._log("Done.")

    # ------------------------------------------------------------------
    # Argument parsing and helpers
    # ------------------------------------------------------------------
    def _parse_args(self):
        defaults = {
            "depth": 256,
            "mask_window": 8,
            "terminal_walk_depth": 64,
            "debug": False,
            "debug_trace": False,
            "unlimited_recursion": False,
            "additional_apis": "",
        }
        args = defaults.copy()
        raw_args = self.getScriptArgs()
        if raw_args:
            for arg in raw_args:
                if "=" in arg:
                    k, v = arg.split("=", 1)
                    if k in ["depth", "mask_window", "terminal_walk_depth"]:
                        try:
                            args[k] = int(v)
                        except Exception:
                            pass
                    elif k in ["debug", "debug_trace", "unlimited_recursion"]:
                        args[k] = v.lower() in ("1", "true", "yes", "on")
                    elif k == "additional_apis":
                        args[k] = v
                    elif k == "output_dir":
                        args[k] = v
        return args

    def _log(self, msg):
        if self.args.get("debug"):
            print(msg)

    def _trace(self, msg):
        if self.args.get("debug_trace"):
            print(msg)

    def _get_output_dir(self):
        custom = self.args.get("output_dir")
        if custom:
            return custom
        home = os.path.expanduser("~")
        program_name = self.currentProgram.getName() if self.currentProgram else "program"
        return os.path.join(home, "regkeys", program_name)

    # ------------------------------------------------------------------
    # String collection
    # ------------------------------------------------------------------
    def _collect_registry_strings(self):
        listing = self.currentProgram.getListing()
        data_iter = listing.getDefinedData(True)
        count = 0
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
                count += 1
        self._log("Indexed %d registry-like strings" % count)

    def _is_registry_like_string(self, s):
        if not s or len(s) < 4:
            return False
        if self.URL_PATTERN.match(s):
            return False
        if "\\" not in s:
            return False
        if not self.REGEX_REGISTRY_STRING.search(s):
            return False
        return True

    # ------------------------------------------------------------------
    # API call scanning
    # ------------------------------------------------------------------
    def _scan_registry_calls(self):
        addl = self.args.get("additional_apis") or ""
        addl_pattern = None
        if addl:
            try:
                addl_pattern = re.compile(addl)
            except Exception:
                addl_pattern = None
        fm = self.currentProgram.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            if self.monitor.isCancelled():
                break
            inst_iter = self.currentProgram.getListing().getInstructions(func.getBody(), True)
            while inst_iter.hasNext():
                inst = inst_iter.next()
                if not inst.getFlowType().isCall():
                    continue
                callee_name = self._resolve_callee_name(inst, fm)
                if not callee_name:
                    continue
                if not self._is_registry_api(callee_name, addl_pattern):
                    continue
                key_info, resolved_key = self._resolve_call_key(inst)
                api_call = ApiCallSite(inst.getMinAddress(), func.getName(), callee_name, "call")
                api_call.resolved_key = resolved_key
                if key_info is not None:
                    key_info.add_api_call(api_call)
                elif resolved_key:
                    # ensure placeholder if string collected but not mapped yet
                    if resolved_key not in self.registry_infos:
                        self.registry_infos[resolved_key] = RegistryKeyInfo(resolved_key)
                    self.registry_infos[resolved_key].add_api_call(api_call)
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

    def _is_registry_api(self, name, addl_pattern):
        if self.REGEX_DEFAULT_APIS.match(name):
            return True
        if addl_pattern and addl_pattern.match(name):
            return True
        return False

    def _resolve_call_key(self, inst):
        refs = inst.getReferencesFrom()
        for ref in refs:
            to_addr = ref.getToAddress()
            if to_addr in self.string_index:
                s = self.string_index[to_addr]
                if s not in self.registry_infos:
                    self.registry_infos[s] = RegistryKeyInfo(s)
                return self.registry_infos[s], s
        try:
            pcode = inst.getPcode()
        except Exception:
            return None, None
        for op in pcode:
            for inp in op.getInputs():
                if inp is None:
                    continue
                if inp.isAddress() and inp.getAddress() in self.string_index:
                    key_str = self.string_index[inp.getAddress()]
                    if key_str not in self.registry_infos:
                        self.registry_infos[key_str] = RegistryKeyInfo(key_str)
                    return self.registry_infos[key_str], key_str
                if inp.isConstant():
                    try:
                        const_addr = self.api.toAddr(inp.getOffset())
                    except Exception:
                        const_addr = None
                    if const_addr and const_addr in self.string_index:
                        key_str = self.string_index[const_addr]
                        if key_str not in self.registry_infos:
                            self.registry_infos[key_str] = RegistryKeyInfo(key_str)
                        return self.registry_infos[key_str], key_str
        return None, None

    # ------------------------------------------------------------------
    # Branch / taint analysis
    # ------------------------------------------------------------------
    def _varnode_key(self, vn):
        if vn is None:
            return None
        try:
            space = vn.getAddress().getAddressSpace().getName()
            return (space, vn.getOffset(), vn.getSize())
        except Exception:
            return (str(vn), vn.getSize())

    def _propagate_taint(self, inst, state):
        try:
            pcode_ops = inst.getPcode()
        except Exception:
            return
        for op in pcode_ops:
            opc = op.getOpcode()
            if opc == PcodeOp.COPY:
                self._copy_taint(op, state)
            elif opc == PcodeOp.LOAD:
                self._handle_load(op, state)
            elif opc == PcodeOp.STORE:
                self._handle_store(op, state)
            elif opc in (PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR):
                self._handle_bitwise(op, state)
            elif opc in (PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT):
                self._handle_shift(op, state)
            elif opc in (PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
                self._handle_ext(op, state)
            else:
                self._handle_passthrough(op, state)
            self._seed_from_string_load(op, state)

    def _copy_taint(self, op, state):
        src = op.getInput(0)
        dest = op.getOutput()
        tr = state.get(self._varnode_key(src))
        if tr:
            state[self._varnode_key(dest)] = tr

    def _handle_load(self, op, state):
        dest = op.getOutput()
        ptr = op.getInput(1)
        tr = state.get(self._varnode_key(ptr))
        if tr:
            state[self._varnode_key(dest)] = tr

    def _handle_store(self, op, state):
        value = op.getInput(2)
        dest_ptr = op.getInput(1)
        tr = state.get(self._varnode_key(value))
        if tr:
            state[self._varnode_key(dest_ptr)] = tr

    def _handle_bitwise(self, op, state):
        dest = op.getOutput()
        src0 = op.getInput(0)
        src1 = op.getInput(1)
        tr = state.get(self._varnode_key(src0))
        if tr:
            tr = tr.clone()
            if src1.isConstant():
                tr.apply_and(src1.getOffset())
            state[self._varnode_key(dest)] = tr

    def _handle_shift(self, op, state):
        dest = op.getOutput()
        src0 = op.getInput(0)
        src1 = op.getInput(1)
        tr = state.get(self._varnode_key(src0))
        if tr and src1.isConstant():
            tr = tr.clone()
            direction = "l" if op.getOpcode() == PcodeOp.INT_LEFT else "r"
            tr.apply_shift(src1.getOffset(), direction)
            state[self._varnode_key(dest)] = tr

    def _handle_ext(self, op, state):
        dest = op.getOutput()
        src = op.getInput(0)
        tr = state.get(self._varnode_key(src))
        if tr:
            tr = tr.clone()
            tr.width = dest.getSize() * 8
            state[self._varnode_key(dest)] = tr

    def _handle_passthrough(self, op, state):
        if op.getOutput() is None:
            return
        src = op.getInput(0) if op.getInput(0) else None
        dest = op.getOutput()
        tr = state.get(self._varnode_key(src))
        if tr:
            state[self._varnode_key(dest)] = tr

    def _seed_from_string_load(self, op, state):
        if op.getOpcode() != PcodeOp.LOAD:
            return
        dest = op.getOutput()
        ptr = op.getInput(1)
        addr = None
        if ptr.isConstant():
            try:
                addr = self.api.toAddr(ptr.getOffset())
            except Exception:
                addr = None
        elif ptr.isAddress():
            addr = ptr.getAddress()
        if addr and addr in self.string_index:
            key_str = self.string_index[addr]
            key_info = self.registry_infos.get(key_str)
            if key_info:
                tr = TaintRecord(key_info, width=dest.getSize() * 8)
                state[self._varnode_key(dest)] = tr

    def _get_condition_varnodes(self, inst):
        varnodes = []
        try:
            pcode = inst.getPcode()
        except Exception:
            return varnodes
        for op in pcode:
            if op.getOpcode() == PcodeOp.CBRANCH:
                inputs = op.getInputs()
                if inputs:
                    varnodes.append(inputs[0])
        return varnodes

    def _analyze_bit_usage(self, inst, taint_record):
        window = self.args.get("mask_window", 8)
        listing = self.currentProgram.getListing()
        current = inst
        steps = 0
        taint = taint_record.clone()
        while steps < window:
            prev = listing.getInstructionBefore(current.getMinAddress())
            if prev is None:
                break
            try:
                pcode_ops = prev.getPcode()
            except Exception:
                break
            for op in pcode_ops:
                if op.getOpcode() == PcodeOp.INT_AND:
                    inp0 = op.getInput(0)
                    inp1 = op.getInput(1)
                    if inp1.isConstant():
                        taint.apply_and(inp1.getOffset())
                elif op.getOpcode() in (PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_LEFT):
                    inp0 = op.getInput(0)
                    inp1 = op.getInput(1)
                    if inp1.isConstant():
                        direction = "l" if op.getOpcode() == PcodeOp.INT_LEFT else "r"
                        taint.apply_shift(inp1.getOffset(), direction)
            current = prev
            steps += 1
        return taint

    def _analyze_branches(self):
        try:
            bbm = BasicBlockModel(self.currentProgram)
            _ = bbm  # silence unused warning
        except Exception:
            self._log("BasicBlockModel unavailable; continuing without CFG walk")
        code = self.currentProgram.getListing()
        func_iter = self.currentProgram.getFunctionManager().getFunctions(True)
        for func in func_iter:
            if self.monitor.isCancelled():
                break
            inst_iter = code.getInstructions(func.getBody(), True)
            state = {}
            for inst in inst_iter:
                if self.monitor.isCancelled():
                    break
                self._propagate_taint(inst, state)
                if inst.getFlowType().isConditional():
                    cond_varnodes = self._get_condition_varnodes(inst)
                    for vn in cond_varnodes:
                        tr = state.get(self._varnode_key(vn))
                        if tr:
                            analyzed = self._analyze_bit_usage(inst, tr)
                            dp = DecisionPoint(inst.getMinAddress(), str(inst), analyzed, func_name=func.getName())
                            analyzed.key_info.add_decision(dp)
                            analyzed.key_info.update_masks(analyzed)
        self._log("Branch analysis complete")

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    def _write_outputs(self):
        program_name = self.currentProgram.getName() if self.currentProgram else "program"
        ndjson_path = os.path.join(self.output_dir, "%s.registry_bitfields.ndjson" % program_name)
        md_path = os.path.join(self.output_dir, "%s.registry_bitfields.md" % program_name)
        with open(ndjson_path, "w") as f:
            for key in sorted(self.registry_infos.keys()):
                info = self.registry_infos[key]
                f.write(json.dumps(info.to_ndjson()))
                f.write("\n")
        with open(md_path, "w") as f:
            f.write("# Registry Bitfield Report\n\n")
            for key in sorted(self.registry_infos.keys()):
                info = self.registry_infos[key]
                f.write(info.to_markdown())
                f.write("\n")


# Instantiate script entry point
if __name__ == "__main__":
    script = RegistryKeyBitfieldReport()
    script.run()
