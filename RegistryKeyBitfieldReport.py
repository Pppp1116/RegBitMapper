# coding: utf-8
"""
RegistryKeyBitfieldReport (Jython)

Production-ready implementation for Ghidra 12 (GUI and headless).
The script scans for registry-related strings, correlates them with
Windows registry APIs, performs interprocedural taint tracking, and
reports how registry values influence conditional branches (bit usage).

NDJSON/Markdown output remains backward compatible; new metadata lives
under the "extended" key only.
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
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Instruction
from ghidra.program.model.pcode import PcodeOp
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
    """Tracks taint originating from a registry key/value."""

    def __init__(self, key_info, width=32, used_mask=None, ignored_mask=None, history=None, confidence=1.0, source="registry"):
        self.key_info = key_info
        self.width = width
        self.used_mask = used_mask if used_mask is not None else ((1 << width) - 1)
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

    def apply_and(self, mask, note):
        limit_mask = ((1 << self.width) - 1)
        self.used_mask &= mask & limit_mask
        self.ignored_mask |= (~mask) & limit_mask
        self.history.append(("and", mask, note))

    def apply_or(self, mask, note):
        limit_mask = ((1 << self.width) - 1)
        self.used_mask |= mask & limit_mask
        self.history.append(("or", mask, note))

    def apply_xor(self, mask, note):
        limit_mask = ((1 << self.width) - 1)
        self.used_mask |= mask & limit_mask
        self.history.append(("xor", mask, note))

    def apply_not(self, note):
        limit_mask = ((1 << self.width) - 1)
        self.used_mask = (~self.used_mask) & limit_mask
        self.history.append(("not", None, note))

    def apply_shift(self, bits, direction, note):
        if direction == "l":
            self.used_mask <<= bits
            self.ignored_mask <<= bits
        elif direction == "r":
            self.used_mask >>= bits
            self.ignored_mask >>= bits
        limit_mask = ((1 << self.width) - 1)
        self.used_mask &= limit_mask
        self.ignored_mask &= limit_mask
        self.history.append(("shift" + direction, bits, note))

    def mark_compare(self, mask, note):
        if mask is None:
            return
        limit_mask = ((1 << self.width) - 1)
        self.used_mask &= mask & limit_mask
        self.history.append(("cmp", mask, note))

    def merge(self, other):
        if other is None:
            return self
        if other.key_info != self.key_info:
            return self
        merged = TaintRecord(self.key_info, width=max(self.width, other.width))
        merged.used_mask = self.used_mask | other.used_mask
        merged.ignored_mask = self.ignored_mask | other.ignored_mask
        merged.history = list(self.history) + list(other.history)
        merged.confidence = min(self.confidence, other.confidence)
        merged.source = self.source or other.source
        return merged


class DecisionPoint(object):
    """Represents a conditional branch influenced by registry-derived data."""

    def __init__(self, addr, condition, taint_record, func_name=None, history=None, extended=None):
        self.addr = addr
        self.condition = condition
        self.taint_record = taint_record
        self.func_name = func_name
        self.history = history or []
        self.extended = extended or {}

    def to_dict(self):
        bits = self._bits_from_mask(self.taint_record.used_mask, self.taint_record.width)
        ignored = self._bits_from_mask(self.taint_record.ignored_mask, self.taint_record.width)
        base = {
            "address": str(self.addr),
            "condition": self.condition,
            "function": self.func_name,
            "used_bits": bits,
            "ignored_bits": ignored,
            "width": self.taint_record.width,
        }
        ext = dict(self.extended)
        if self.history:
            ext["history"] = self.history
        ext["confidence"] = self.taint_record.confidence
        if ext:
            base["extended"] = ext
        return base

    def _bits_from_mask(self, mask, width):
        out = []
        if mask is None or width is None:
            return out
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
        self.extended = {}

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
                lines.append(
                    "  - %s using bits %s" % (
                        dec.addr,
                        dec._bits_from_mask(dec.taint_record.used_mask, dec.taint_record.width),
                    )
                )
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main script
# ---------------------------------------------------------------------------

class RegistryKeyBitfieldReport(GhidraScript):
    REGEX_DEFAULT_APIS = re.compile(r"^(Reg.*|Zw.*|Nt.*|Cm.*)(Key|Value)")
    REGEX_REGISTRY_STRING = re.compile(
        r"^(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKCC|HKEY_CURRENT_CONFIG)",
        re.IGNORECASE,
    )
    GUID_PATTERN = re.compile(r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}")
    URL_PATTERN = re.compile(r"^[a-zA-Z]+://")
    X64_FASTCALL_ORDER = ["RCX", "RDX", "R8", "R9"]
    REGISTRY_API_TABLE = {
        "regqueryvalueexa": {"key_arg": 1, "data_out_arg": 4, "value_arg": 1, "data_width": 32, "ret_is_data": False},
        "regqueryvalueexw": {"key_arg": 1, "data_out_arg": 4, "value_arg": 1, "data_width": 32, "ret_is_data": False},
        "regqueryvalueex": {"key_arg": 1, "data_out_arg": 4, "value_arg": 1, "data_width": 32, "ret_is_data": False},
        "reggetvaluea": {"key_arg": 1, "subkey_arg": 2, "value_arg": 3, "data_out_arg": 5, "data_width": 32, "ret_is_data": False},
        "reggetvaluew": {"key_arg": 1, "subkey_arg": 2, "value_arg": 3, "data_out_arg": 5, "data_width": 32, "ret_is_data": False},
        "regsetvalueexa": {"key_arg": 1, "value_arg": 2, "data_out_arg": 4, "data_width": 32, "ret_is_data": False},
        "regsetvalueexw": {"key_arg": 1, "value_arg": 2, "data_out_arg": 4, "data_width": 32, "ret_is_data": False},
        "regsetvalueex": {"key_arg": 1, "value_arg": 2, "data_out_arg": 4, "data_width": 32, "ret_is_data": False},
        "regopenkeyexa": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "ret_is_data": True, "data_width": 64},
        "regopenkeyexw": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "ret_is_data": True, "data_width": 64},
        "regopenkey": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "ret_is_data": True, "data_width": 64},
        "regcreatekeyexa": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "ret_is_data": True, "data_width": 64},
        "regcreatekeyexw": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "ret_is_data": True, "data_width": 64},
        "regcreatekeyex": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "ret_is_data": True, "data_width": 64},
        "regcreatekey": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "ret_is_data": True, "data_width": 64},
        "zwqueryvaluekey": {"key_arg": 1, "value_arg": 2, "data_out_arg": 3, "data_width": 64, "ret_is_data": False},
        "zwqueryvalue": {"key_arg": 1, "value_arg": 2, "data_out_arg": 3, "data_width": 64, "ret_is_data": False},
        "zwopenkey": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "data_width": 64, "ret_is_data": True},
        "zwcreatekey": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "data_width": 64, "ret_is_data": True},
        "ntopenkey": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "data_width": 64, "ret_is_data": True},
        "ntcreatekey": {"key_arg": 1, "subkey_arg": 2, "data_out_arg": None, "data_width": 64, "ret_is_data": True},
        "ntqueryvaluekey": {"key_arg": 1, "value_arg": 2, "data_out_arg": 3, "data_width": 64, "ret_is_data": False},
        "cmregistercallback": {"key_arg": 1, "data_out_arg": None, "ret_is_data": True, "data_width": 64},
    }

    def run(self):
        self.api = FlatProgramAPI(self.currentProgram, self.monitor)
        self.args = self._parse_args()
        self.addl_pattern = self._compile_additional_apis(self.args.get("additional_apis"))
        self.string_index = {}  # Address -> string
        self.registry_infos = {}  # string -> RegistryKeyInfo
        self.output_dir = self._get_output_dir()
        self.func_summaries = {}
        self.call_depths = {}
        if not os.path.isdir(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except Exception:
                pass

        self._log("Arguments: %s" % self.args)
        self._log("Collecting registry-like strings...")
        self._collect_registry_strings()
        self._log("Scanning for registry API calls...")
        self._scan_registry_calls()
        self._log("Running program-wide taint analysis...")
        self._analyze_program()
        self._log("Writing outputs...")
        self._write_outputs()
        self._log("Done.")

    # ------------------------------------------------------------------
    # Argument parsing and helpers
    # ------------------------------------------------------------------
    def _parse_args(self):
        defaults = {
            "depth": 256,
            "mask_window": 16,
            "terminal_walk_depth": 128,
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

    def _compile_additional_apis(self, pattern):
        if not pattern:
            return None
        try:
            return re.compile(pattern)
        except Exception:
            return None

    def _log(self, msg):
        if self.args.get("debug"):
            print(msg)

    def _trace(self, msg):
        if self.args.get("debug_trace"):
            print(msg)

    def _get_output_dir(self):
        custom = self.args.get("output_dir")
        if custom:
            return os.path.abspath(custom)
        home = os.path.expanduser("~")
        program_name = self.currentProgram.getName() if self.currentProgram else "program"
        return os.path.abspath(os.path.join(home, "regkeys", program_name))

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
        if self.GUID_PATTERN.search(s):
            return True
        return True

    # ------------------------------------------------------------------
    # API call scanning
    # ------------------------------------------------------------------
    def _scan_registry_calls(self):
        addl_pattern = self.addl_pattern
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
                if not callee_name:
                    continue
                if not self._is_registry_api(callee_name, addl_pattern):
                    continue
                key_info, resolved_key = self._resolve_call_key(inst)
                api_call = ApiCallSite(inst.getMinAddress(), func.getName(), callee_name, "call")
                api_call.resolved_key = resolved_key
                api_call.extended = self._capture_call_arguments(inst)
                if key_info is not None:
                    key_info.add_api_call(api_call)
                elif resolved_key:
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
            if op is None:
                continue
            try:
                inputs = op.getInputs()
            except Exception:
                continue
            if not inputs:
                continue
            for inp in inputs:
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
        # Assembly-level operand inspection (helps when p-code is missing or optimized away)
        key_str = self._extract_string_from_operands(inst)
        if key_str:
            if key_str not in self.registry_infos:
                self.registry_infos[key_str] = RegistryKeyInfo(key_str)
            return self.registry_infos[key_str], key_str
        return None, None

    def _capture_call_arguments(self, inst):
        args = []
        try:
            pcode = inst.getPcode()
        except Exception:
            return {"args": []}
        for op in pcode:
            if op is None:
                continue
            if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND):
                for i in range(1, op.getNumInputs()):
                    args.append(str(op.getInput(i)))
        asm_ops = []
        try:
            for i in range(inst.getNumOperands()):
                asm_ops.append(inst.getDefaultOperandRepresentation(i))
        except Exception:
            pass
        return {"args": args, "asm_operands": asm_ops}

    def _extract_string_from_operands(self, inst):
        try:
            for i in range(inst.getNumOperands()):
                op_obj = inst.getOpObjects(i)
                if op_obj is None:
                    continue
                for obj in op_obj:
                    try:
                        if isinstance(obj, Address) and obj in self.string_index:
                            return self.string_index[obj]
                    except Exception:
                        continue
        except Exception:
            return None
        return None

    # ------------------------------------------------------------------
    # Taint helpers
    # ------------------------------------------------------------------
    def _varnode_key(self, vn):
        if vn is None:
            return None
        try:
            space = vn.getAddress().getAddressSpace().getName()
            return (space, vn.getOffset(), vn.getSize())
        except Exception:
            try:
                return (str(vn), vn.getSize())
            except Exception:
                return (str(vn), None)

    def _pointer_slot(self, vn):
        if vn is None:
            return None
        key = self._varnode_key(vn)
        if key is None:
            return None
        if isinstance(key, tuple) and len(key) >= 2:
            return ('mem', key)
        return None

    def _merge_state(self, dst_state, src_state):
        changed = False
        for k, v in src_state.items():
            cur = dst_state.get(k)
            if cur is None:
                dst_state[k] = v
                changed = True
            else:
                merged = cur.merge(v)
                if merged.used_mask != cur.used_mask or merged.ignored_mask != cur.ignored_mask or len(merged.history) != len(cur.history):
                    dst_state[k] = merged
                    changed = True
        return changed

    # ------------------------------------------------------------------
    # Pcode handling
    # ------------------------------------------------------------------
    def _propagate_taint(self, inst, state, func, depth):
        try:
            pcode = inst.getPcode()
        except Exception:
            return
        if pcode is None:
            return
        for op in pcode:
            if self.monitor.isCancelled():
                break
            if op is None:
                continue
            opc = op.getOpcode()
            if opc == PcodeOp.CALL or opc == PcodeOp.CALLIND:
                self._handle_call(op, state, func, depth)
                continue
            if opc == PcodeOp.RETURN:
                continue
            self._seed_from_string_load(op, state)
            if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_SEXT, PcodeOp.INT_ZEXT):
                self._taint_copy(op, state)
            elif opc in (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.PTRADD, PcodeOp.PTRSUB):
                self._taint_copy(op, state, op_label="addsub")
            elif opc == PcodeOp.LOAD:
                self._taint_copy(op, state, is_load=True)
            elif opc == PcodeOp.STORE:
                self._taint_store(op, state)
            elif opc in (PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_NEGATE):
                self._taint_bitwise(op, state)
            elif opc in (PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL):
                self._taint_compare(op, state)

    def _taint_copy(self, op, state, is_load=False, op_label="copy"):
        dest = op.getOutput()
        if dest is None:
            return
        src_index = 1 if is_load else 0
        src = None
        if op.getNumInputs() > src_index:
            src = op.getInput(src_index)
        if src is None:
            return
        key = self._varnode_key(src)
        tr = state.get(key)
        if tr is None and is_load:
            ptr_slot = self._pointer_slot(src)
            if ptr_slot:
                tr = state.get(ptr_slot)
        if tr:
            new_tr = tr.clone()
            new_tr.history.append((op_label, str(op), None))
            state[self._varnode_key(dest)] = new_tr

    def _taint_store(self, op, state):
        if op.getNumInputs() < 3:
            return
        val = op.getInput(2)
        ptr = op.getInput(1)
        tr = state.get(self._varnode_key(val))
        if tr and ptr is not None:
            ptr_slot = self._pointer_slot(ptr)
            if ptr_slot:
                state[ptr_slot] = tr.clone()

    def _taint_bitwise(self, op, state):
        dest = op.getOutput()
        if dest is None:
            return
        inp0 = op.getInput(0) if op.getNumInputs() > 0 else None
        inp1 = op.getInput(1) if op.getNumInputs() > 1 else None
        base_tr = state.get(self._varnode_key(inp0))
        if base_tr is None:
            base_tr = state.get(self._varnode_key(inp1))
        if base_tr is None:
            return
        tr = base_tr.clone()
        opc = op.getOpcode()
        if opc == PcodeOp.INT_AND and inp1 is not None and inp1.isConstant():
            tr.apply_and(inp1.getOffset(), str(op))
        elif opc == PcodeOp.INT_OR and inp1 is not None and inp1.isConstant():
            tr.apply_or(inp1.getOffset(), str(op))
        elif opc == PcodeOp.INT_XOR and inp1 is not None and inp1.isConstant():
            tr.apply_xor(inp1.getOffset(), str(op))
        elif opc in (PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT) and inp1 is not None and inp1.isConstant():
            direction = "l" if opc == PcodeOp.INT_LEFT else "r"
            tr.apply_shift(inp1.getOffset(), direction, str(op))
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
        tr0 = state.get(self._varnode_key(inp0))
        tr1 = state.get(self._varnode_key(inp1))
        tr = tr0 or tr1
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
        addr = None
        if pointer is None:
            return
        if pointer.isConstant():
            try:
                addr = self.api.toAddr(pointer.getOffset())
            except Exception:
                addr = None
        elif pointer.isAddress():
            addr = pointer.getAddress()
        if addr and addr in self.string_index:
            key_str = self.string_index[addr]
            key_info = self.registry_infos.get(key_str)
            if key_info is None:
                key_info = RegistryKeyInfo(key_str)
                self.registry_infos[key_str] = key_info
            tr = TaintRecord(key_info, width=(dest.getSize() * 8))
            tr.history.append(("seed", key_str, str(op)))
            state[self._varnode_key(dest)] = tr

    def _seed_taint_from_registry_call(self, name, call_op, arg_taints, out_vn, state):
        mapping = self._registry_api_mapping(name)
        key_arg = mapping.get("key_arg")
        subkey_arg = mapping.get("subkey_arg")
        value_arg = mapping.get("value_arg")
        data_arg = mapping.get("data_out_arg")
        buf_width = mapping.get("data_width", 32)
        ret_is_data = mapping.get("ret_is_data", False)
        key_info = None
        resolved_key = None
        arg_candidates = [key_arg, subkey_arg, value_arg]
        for idx in arg_candidates:
            if idx is not None and idx < len(arg_taints):
                tr = arg_taints[idx]
                if tr:
                    key_info = tr.key_info
                    break
        if key_info is None:
            for idx in arg_candidates:
                resolved_key = self._resolve_constant_string(call_op, idx)
                if resolved_key:
                    break
        if resolved_key:
            key_info = self.registry_infos.get(resolved_key)
            if key_info is None:
                key_info = RegistryKeyInfo(resolved_key)
                self.registry_infos[resolved_key] = key_info
        if key_info is None:
            return None
        base_tr = TaintRecord(key_info, width=buf_width)
        base_tr.history.append(("api-seed", name, resolved_key))
        if data_arg is not None and data_arg < call_op.getNumInputs():
            data_vn = call_op.getInput(data_arg)
            if data_vn is not None:
                tr = base_tr.clone()
                tr.history.append(("api-read", name, data_arg))
                state[self._varnode_key(data_vn)] = tr
        if ret_is_data and out_vn is not None:
            tr_ret = base_tr.clone()
            tr_ret.history.append(("api-ret", name, None))
            return tr_ret
        return None

    def _resolve_constant_string(self, call_op, arg_index):
        if arg_index is None:
            return None
        if arg_index >= call_op.getNumInputs():
            return None
        vn = call_op.getInput(arg_index)
        addr = None
        if vn.isConstant():
            try:
                addr = self.api.toAddr(vn.getOffset())
            except Exception:
                addr = None
        elif vn.isAddress():
            addr = vn.getAddress()
        if addr and addr in self.string_index:
            return self.string_index[addr]
        return None

    def _registry_api_mapping(self, name):
        lname = name.lower()
        mapping = {"key_arg": 1, "data_out_arg": 4, "data_width": 32, "ret_is_data": False}
        for api_name, info in self.REGISTRY_API_TABLE.items():
            if api_name in lname:
                mapping.update(info)
                break
        return mapping

    # ------------------------------------------------------------------
    # Program-wide analysis
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
        if not self.args.get("unlimited_recursion") and depth > self.args.get("depth", 256):
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
        block_states_out = {}
        worklist = deque()
        for blk in blocks:
            block_states_in[blk] = dict(incoming_state)
            worklist.append(blk)
        visited_guard = 0
        max_iterations = max(len(blocks) * 32, 128)
        guard_hit = False
        while worklist:
            if self.monitor.isCancelled():
                break
            visited_guard += 1
            if visited_guard > max_iterations and not guard_hit:
                guard_hit = True
                self._log("Iteration cap exceeded in %s; continuing conservatively" % func.getName())
            blk = worklist.popleft()
            state = dict(block_states_in.get(blk, {}))
            inst_iter = listing.getInstructions(blk, True)
            last_inst = None
            while inst_iter.hasNext():
                if self.monitor.isCancelled():
                    break
                inst = inst_iter.next()
                last_inst = inst
                self._propagate_taint(inst, state, func, depth)
                if inst.getFlowType().isConditional():
                    self._record_decision(inst, func, state)
            block_states_out[blk] = state
            dest_blocks = self._successor_blocks(blk, last_inst, bbm)
            for dest_blk in dest_blocks:
                incoming = block_states_in.get(dest_blk)
                if incoming is None:
                    block_states_in[dest_blk] = dict(state)
                    worklist.append(dest_blk)
                else:
                    if self._merge_state(incoming, state):
                        worklist.append(dest_blk)
        self.func_summaries[func_key] = block_states_out
        return block_states_out

    def _fallback_blocks(self, func):
        listing = self.currentProgram.getListing()
        body = func.getBody()
        blocks = []
        addrs = []
        inst_iter = listing.getInstructions(body, True)
        while inst_iter.hasNext():
            if self.monitor.isCancelled():
                break
            inst = inst_iter.next()
            addrs.append(inst.getMinAddress())
        if not addrs:
            return blocks
        blocks.append(body)
        return blocks

    def _successor_blocks(self, blk, last_inst, bbm):
        dests = []
        if last_inst is None:
            return dests
        refs = last_inst.getReferencesFrom()
        for ref in refs:
            if ref is None:
                continue
            if ref.getReferenceType().isConditional() or ref.getReferenceType().isFlow() or ref.getReferenceType().isJump():
                dests.append(ref.getToAddress())
        fallthrough = last_inst.getFallThrough()
        if fallthrough:
            dests.append(fallthrough)
        out_blocks = []
        for dest in dests:
            try:
                dest_blk = bbm.getCodeBlockAt(dest, self.monitor)
            except Exception:
                dest_blk = None
            if dest_blk:
                out_blocks.append(dest_blk)
        return out_blocks

    def _record_decision(self, inst, func, state):
        cond_varnodes = self._get_condition_varnodes(inst)
        for vn in cond_varnodes:
            tr = state.get(self._varnode_key(vn))
            if tr:
                analyzed = self._analyze_bit_usage(inst, tr)
                ext = {
                    "source": tr.source,
                    "interprocedural": True if len(tr.history) > 0 else False,
                    "from_handle": True if "api-ret" in [h[0] for h in tr.history] else False,
                    "operation_history": list(tr.history),
                    "compare_mnemonic": inst.getMnemonicString() if inst else None,
                }
                dp = DecisionPoint(inst.getMinAddress(), str(inst), analyzed, func_name=func.getName(), history=analyzed.history, extended=ext)
                analyzed.key_info.add_decision(dp)
                analyzed.key_info.update_masks(analyzed)

    def _get_condition_varnodes(self, inst):
        varnodes = []
        try:
            pcode = inst.getPcode()
        except Exception:
            return varnodes
        if pcode is None:
            return varnodes
        for op in pcode:
            if op is None:
                continue
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
            if self.monitor.isCancelled():
                break
            prev = listing.getInstructionBefore(current.getMinAddress())
            if prev is None:
                break
            # Prefer p-code but also inspect assembly when needed
            try:
                pcode_ops = prev.getPcode()
            except Exception:
                pcode_ops = None
            if pcode_ops:
                for op in pcode_ops:
                    if op is None:
                        continue
                    opc = op.getOpcode()
                    if opc == PcodeOp.INT_AND:
                        inp1 = op.getInput(1)
                        if inp1 is not None and inp1.isConstant():
                            taint.apply_and(inp1.getOffset(), str(op))
                    elif opc in (PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_LEFT):
                        inp1 = op.getInput(1)
                        if inp1 is not None and inp1.isConstant():
                            direction = "l" if opc == PcodeOp.INT_LEFT else "r"
                            taint.apply_shift(inp1.getOffset(), direction, str(op))
                    elif opc == PcodeOp.INT_OR:
                        inp1 = op.getInput(1)
                        if inp1 is not None and inp1.isConstant():
                            taint.apply_or(inp1.getOffset(), str(op))
                    elif opc == PcodeOp.INT_XOR:
                        inp1 = op.getInput(1)
                        if inp1 is not None and inp1.isConstant():
                            taint.apply_xor(inp1.getOffset(), str(op))
                    elif opc == PcodeOp.INT_NEGATE:
                        taint.apply_not(str(op))
                    elif opc in (PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL):
                        inp0 = op.getInput(0)
                        inp1 = op.getInput(1)
                        if inp1 is not None and inp1.isConstant():
                            taint.mark_compare(inp1.getOffset(), str(op))
                        elif inp0 is not None and inp0.isConstant():
                            taint.mark_compare(inp0.getOffset(), str(op))
            # Assembly inspection for masking/compare instructions (x86/x64)
            try:
                mnem = prev.getMnemonicString().upper()
                ops = [prev.getDefaultOperandRepresentation(i) for i in range(prev.getNumOperands())]
                if mnem in ("TEST", "AND") and len(ops) > 1:
                    try:
                        mask = int(str(ops[1]).replace("0x", ""), 16)
                        taint.apply_and(mask, "asm-%s" % mnem)
                    except Exception:
                        pass
                elif mnem in ("OR", "XOR") and len(ops) > 1:
                    try:
                        mask = int(str(ops[1]).replace("0x", ""), 16)
                        if mnem == "OR":
                            taint.apply_or(mask, "asm-OR")
                        else:
                            taint.apply_xor(mask, "asm-XOR")
                    except Exception:
                        pass
                elif mnem in ("SHL", "SAL", "SHR", "SAR") and len(ops) > 1:
                    try:
                        bits = int(str(ops[1]).replace("0x", ""), 16)
                        direction = "l" if mnem in ("SHL", "SAL") else "r"
                        taint.apply_shift(bits, direction, "asm-%s" % mnem)
                    except Exception:
                        pass
                elif mnem in ("CMP", "SUB") and len(ops) > 1:
                    try:
                        mask = int(str(ops[1]).replace("0x", ""), 16)
                        taint.mark_compare(mask, "asm-%s" % mnem)
                    except Exception:
                        pass
            except Exception:
                pass
            current = prev
            steps += 1
        taint.history.append(("decision", str(inst), None))
        return taint

    # ------------------------------------------------------------------
    # Call handling / interprocedural
    # ------------------------------------------------------------------
    def _handle_call(self, op, state, func, depth):
        callee_addr = None
        callee_func = None
        callee_name = None
        fm = self.currentProgram.getFunctionManager()
        if op.getOpcode() == PcodeOp.CALL:
            if op.getNumInputs() > 0:
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
        if callee_name and self._is_registry_api(callee_name, self.addl_pattern):
            tr = self._seed_taint_from_registry_call(callee_name, op, arg_taints, dest, state)
            if tr and dest is not None:
                state[self._varnode_key(dest)] = tr
            if tr and callee_func is not None:
                self._taint_return_to_callers(func, tr)
            return
        # Interprocedural propagation: if args tainted, push into callee summary
        if callee_func and (dest is not None or any(arg_taints)):
            if self.monitor.isCancelled():
                return
            entry_state = {}
            for idx in range(min(len(arg_taints), len(self.X64_FASTCALL_ORDER))):
                reg_name = self.X64_FASTCALL_ORDER[idx]
                vn_key = ("register", reg_name, None)
                tr = arg_taints[idx]
                if tr:
                    entry_state[vn_key] = tr.clone()
            if self.args.get("unlimited_recursion") or depth < self.args.get("depth", 256):
                callee_summary = self._analyze_function(callee_func, depth + 1, entry_state)
                ret_taint = self._taint_from_summary(callee_summary)
                if ret_taint and dest is not None:
                    state[self._varnode_key(dest)] = ret_taint.clone()
            elif any(arg_taints) and dest is not None:
                # Conservative propagation when depth exceeded
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
        if call_op.getNumInputs() > 0:
            target_vn = call_op.getInput(0)
            if target_vn.isConstant():
                try:
                    callee_addr = self.api.toAddr(target_vn.getOffset())
                    func = fm.getFunctionAt(callee_addr)
                    if func and callee_name is None:
                        callee_name = func.getName()
                except Exception:
                    return None, callee_name
            else:
                slot = self._pointer_slot(target_vn)
                if slot:
                    refs = self.api.getReferencesTo(self.api.toAddr(slot[1][1])) if len(slot) > 1 else []
                    for ref in refs:
                        if ref.getReferenceType() and ref.getReferenceType().isData():
                            tgt_func = fm.getFunctionAt(ref.getFromAddress())
                            if tgt_func and callee_name is None:
                                callee_name = tgt_func.getName()
        return func, callee_name

    def _taint_return_to_callers(self, func, tr):
        if func is None or tr is None:
            return
        func_key = func.getEntryPoint()
        summary = self.func_summaries.get(func_key)
        if summary is None:
            self.func_summaries[func_key] = {'__ret__': tr.clone()}
        else:
            summary['__ret__'] = tr.clone()

    def _taint_from_summary(self, summary):
        if summary is None:
            return None
        if isinstance(summary, dict):
            tr = summary.get('__ret__')
            if tr:
                return tr
        # If full block states stored, merge any return markers
        if isinstance(summary, dict):
            for k, v in summary.items():
                if isinstance(v, dict) and '__ret__' in v:
                    return v['__ret__']
        return None

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


# Instantiate script entry point
if __name__ == "__main__":
    script = RegistryKeyBitfieldReport()
    script.run()
