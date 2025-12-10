# coding: utf-8
"""
RegistryKeyBitfieldReport (PyGhidra / Python 3.x)

This script targets **Ghidra 12** using the **PyGhidra CPython bridge**. It is
not a Jython script and must not subclass ``GhidraScript``. Example invocation:

py -3.11 -m pyghidra ^
  --project-path "C:\\GhidraProjects\\RegMap" ^
  --project-name "MyProj" ^
  "C:\\path\\to\\target.exe" ^
  "C:\\path\\to\\RegistryKeyBitfieldReport.py" ^
  mode=taint debug=true trace=false

Arguments (key=value):
  mode  : "taint" (registry/config seeded) or "full" (analyze all flows with synthetic fallback).
  debug : verbose summaries (true/false/1/0/yes/no/on/off).
  trace : per-step traces (true/false/1/0/yes/no/on/off).

Assembly is authoritative for addresses/mnemonics/disassembly. P-code is used
as the internal IR for semantics and dataflow. The analysis runs in two modes:
  * taint: starts from registry/config roots and propagates from there.
  * full : walks all functions, tracks registry/config origins when present,
    and seeds a synthetic root when no registry APIs are detected so downstream
    tools still have at least one root.

Mode differences:
  * taint mode reports only facts that originate from discovered roots (no
    untainted decisions/slots are attached to any root).
  * full mode walks all functions, keeps registry-aware origins, and seeds a
    synthetic root when no registry APIs are detected.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict, deque
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:  # pragma: no cover - executed inside Ghidra
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.program.model.listing import Instruction
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.symbol import RefType
    from ghidra.util.task import TaskMonitor
    try:
        from ghidra.util.task import TaskMonitorAdapter
    except Exception:
        TaskMonitorAdapter = None
    try:
        from ghidra.util.task import DummyTaskMonitor
    except Exception:
        DummyTaskMonitor = None
except Exception:  # pragma: no cover
    FlatProgramAPI = None
    BasicBlockModel = None
    Instruction = None
    PcodeOp = None
    RefType = None
    TaskMonitor = None
    TaskMonitorAdapter = None
    DummyTaskMonitor = None
    AddressSet = None

try:  # pragma: no cover - ensure currentProgram exists in PyGhidra
    currentProgram  # type: ignore[name-defined]
except NameError:  # pragma: no cover
    currentProgram = None

# ---------------------------------------------------------------------------
# Argument parsing and logging
# ---------------------------------------------------------------------------


def _parse_bool(val: str) -> bool:
    if val is None:
        return False
    val = val.strip().lower()
    return val in {"1", "true", "yes", "on"}


def _get_script_args() -> List[str]:
    try:
        getter = globals().get("getScriptArgs")
        if getter:
            return list(getter() or [])
    except Exception:
        return []
    return []


def parse_args(raw_args: List[str], context_hint: str) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    for arg in raw_args:
        if "=" not in arg:
            continue
        k, v = arg.split("=", 1)
        parsed[k.strip().lower()] = v
    mode = parsed.get("mode")
    if mode not in {"taint", "full"}:
        if context_hint == "headless" and raw_args:
            print("[error] mode argument missing or invalid (expected mode=taint|full)", file=sys.stderr)
            sys.exit(1)
        parsed["mode"] = "taint"
    parsed["debug"] = _parse_bool(parsed.get("debug", "false"))
    parsed["trace"] = _parse_bool(parsed.get("trace", "false"))
    if "max_steps" in parsed:
        try:
            parsed["max_steps"] = int(parsed.get("max_steps", "0"))
        except Exception:
            print("[warn] max_steps is not an integer; using default", file=sys.stderr)
            parsed.pop("max_steps", None)
    if "max_function_iterations" in parsed:
        try:
            parsed["max_function_iterations"] = int(parsed.get("max_function_iterations", "0"))
        except Exception:
            print("[warn] max_function_iterations is not an integer; using default", file=sys.stderr)
            parsed.pop("max_function_iterations", None)
    return parsed


def _ensure_environment(context_hint: str) -> bool:
    if FlatProgramAPI is None or BasicBlockModel is None or TaskMonitor is None:
        print(
            "RegistryKeyBitfieldReport must be run inside Ghidra 12 with the PyGhidra CPython bridge (core APIs required).",
            file=sys.stderr,
        )
        if context_hint == "headless":
            sys.exit(1)
        return False
    if currentProgram is None:
        print("[error] currentProgram is not available; open a program before running the script.", file=sys.stderr)
        if context_hint == "headless":
            sys.exit(1)
        return False
    return True


try:
    _SYS_RAW_ARGS = list(sys.argv[1:])
except Exception:
    _SYS_RAW_ARGS = []


def _filter_kv_args(arg_list: List[str]) -> List[str]:
    return [a for a in arg_list if isinstance(a, str) and "=" in a]


def _has_mode(arg_list: List[str]) -> bool:
    return any(a.strip().lower().startswith("mode=") for a in arg_list)


script_manager_args = _filter_kv_args(_get_script_args())
cli_args = _filter_kv_args(_SYS_RAW_ARGS)
if script_manager_args:
    INVOCATION_CONTEXT = "script_manager"
    args = parse_args(script_manager_args, INVOCATION_CONTEXT)
elif __name__ == "__main__" or _has_mode(cli_args):
    INVOCATION_CONTEXT = "headless"
    if cli_args and not _has_mode(cli_args):
        print("[error] headless execution requires mode=taint|full", file=sys.stderr)
        sys.exit(1)
    args = parse_args(cli_args, INVOCATION_CONTEXT)
else:
    INVOCATION_CONTEXT = "script_manager"
    args = {"mode": "taint", "debug": False, "trace": False}
DEBUG_ENABLED = args.get("debug", False)
TRACE_ENABLED = args.get("trace", False)


def _resolve_dummy_monitor():
    if TaskMonitor is None:
        return None
    candidate = getattr(TaskMonitor, "DUMMY", None)
    if candidate is not None:
        return candidate
    if TaskMonitorAdapter is not None:
        return getattr(TaskMonitorAdapter, "DUMMY", None)
    if DummyTaskMonitor is not None:
        try:
            return DummyTaskMonitor()
        except Exception:
            return None
    class _NoOpMonitor:
        def checkCanceled(self):
            return False

        def isCancelled(self):
            return False

        def setMessage(self, msg):
            return None

        def setProgress(self, val):
            return None

    return _NoOpMonitor()


DUMMY_MONITOR = _resolve_dummy_monitor()


def log_info(msg: str) -> None:
    print(msg, file=sys.stderr)


def log_debug(msg: str) -> None:
    if DEBUG_ENABLED:
        print(msg, file=sys.stderr)


def log_trace(msg: str) -> None:
    if TRACE_ENABLED:
        print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Abstract domain data structures
# ---------------------------------------------------------------------------


@dataclass
class PointerPattern:
    base_id: Optional[str] = None
    offset: Optional[int] = None
    stride: Optional[int] = None
    index_var: Optional[Any] = None
    unknown: bool = False

    def adjust_offset(self, delta: int) -> None:
        if self.offset is None:
            self.offset = delta
        else:
            self.offset += delta

    def clone(self) -> "PointerPattern":
        return PointerPattern(
            base_id=self.base_id,
            offset=self.offset,
            stride=self.stride,
            index_var=self.index_var,
            unknown=self.unknown,
        )

    def merge(self, other: "PointerPattern") -> "PointerPattern":
        if other is None:
            return self
        if self.unknown or other.unknown:
            return PointerPattern(base_id=self.base_id or other.base_id, unknown=True)
        if self.base_id != other.base_id:
            return PointerPattern(base_id=self.base_id or other.base_id, unknown=True)
        merged = PointerPattern(base_id=self.base_id)
        merged.offset = self.offset if self.offset == other.offset else None
        merged.stride = self.stride if self.stride == other.stride else None
        merged.index_var = self.index_var if self.index_var == other.index_var else None
        merged.unknown = merged.offset is None or merged.stride is None or merged.index_var is None
        return merged


@dataclass
class AbstractValue:
    tainted: bool = False
    origins: Set[str] = field(default_factory=set)
    bit_width: int = 32
    used_bits: Set[int] = field(default_factory=set)
    candidate_bits: Set[int] = field(default_factory=set)
    pointer_pattern: Optional[PointerPattern] = None

    def clone(self) -> "AbstractValue":
        return AbstractValue(
            tainted=self.tainted,
            origins=set(self.origins),
            bit_width=self.bit_width,
            used_bits=set(self.used_bits),
            candidate_bits=set(self.candidate_bits),
            pointer_pattern=self.pointer_pattern.clone() if self.pointer_pattern else None,
        )

    def mark_bits_used(self, mask: int) -> None:
        for i in range(self.bit_width):
            if mask & (1 << i):
                self.candidate_bits.add(i)
                self.used_bits.add(i)

    def mark_all_bits_used(self) -> None:
        for i in range(self.bit_width):
            self.candidate_bits.add(i)
            self.used_bits.add(i)

    def merge(self, other: "AbstractValue") -> "AbstractValue":
        if other is None:
            return self
        merged = AbstractValue()
        merged.tainted = self.tainted or other.tainted
        merged.origins = set(self.origins | other.origins)
        merged.bit_width = max(self.bit_width, other.bit_width)
        merged.used_bits = set(self.used_bits | other.used_bits)
        merged.candidate_bits = set(self.candidate_bits | other.candidate_bits)
        if self.pointer_pattern and other.pointer_pattern:
            merged.pointer_pattern = self.pointer_pattern.merge(other.pointer_pattern)
        elif self.pointer_pattern:
            merged.pointer_pattern = self.pointer_pattern.clone()
        elif other.pointer_pattern:
            merged.pointer_pattern = other.pointer_pattern.clone()
        else:
            merged.pointer_pattern = None
        return merged

    def state_signature(self) -> Tuple:
        pointer_sig = None
        if self.pointer_pattern is not None:
            pointer_sig = (
                self.pointer_pattern.base_id,
                self.pointer_pattern.offset,
                self.pointer_pattern.stride,
                bool(self.pointer_pattern.index_var is not None),
                self.pointer_pattern.unknown,
            )
        return (
            self.tainted,
            frozenset(self.origins),
            self.bit_width,
            frozenset(self.used_bits),
            frozenset(self.candidate_bits),
            pointer_sig,
        )


@dataclass
class StructSlot:
    base_id: str
    offset: int
    stride: Optional[int] = None
    index_var: Optional[Any] = None
    value: AbstractValue = field(default_factory=AbstractValue)


@dataclass
class Decision:
    address: str
    mnemonic: str
    disasm: str
    origins: Set[str]
    used_bits: Set[int]
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "mnemonic": self.mnemonic,
            "disasm": self.disasm,
            "origins": sorted(self.origins),
            "used_bits": sorted(self.used_bits),
            "details": self.details,
        }


@dataclass
class FunctionSummary:
    name: str
    entry: str
    param_influence: Dict[int, Set[str]] = field(default_factory=lambda: defaultdict(set))
    return_influence: Set[str] = field(default_factory=set)
    slot_writes: List[Dict[str, Any]] = field(default_factory=list)
    decisions: List[Decision] = field(default_factory=list)
    _decision_signatures: Set[Tuple] = field(default_factory=set, init=False, repr=False)

    @staticmethod
    def _decision_signature(decision: Decision) -> Tuple:
        return (
            decision.address,
            tuple(sorted(decision.origins)),
            tuple(sorted(decision.used_bits)),
            tuple(sorted(decision.details.items())),
        )

    def add_decision(self, decision: Decision) -> None:
        sig = self._decision_signature(decision)
        if sig in self._decision_signatures:
            return
        self._decision_signatures.add(sig)
        self.decisions.append(decision)

    def merge_from(self, other: "FunctionSummary") -> bool:
        changed = False
        for idx, roots in other.param_influence.items():
            before = set(self.param_influence.get(idx, set()))
            after = before | roots
            if after != before:
                self.param_influence[idx] = after
                changed = True
        before_ret = set(self.return_influence)
        after_ret = before_ret | other.return_influence
        if after_ret != before_ret:
            self.return_influence = after_ret
            changed = True
        for slot in other.slot_writes:
            if slot not in self.slot_writes:
                self.slot_writes.append(slot)
                changed = True
        for dec in other.decisions:
            sig = self._decision_signature(dec)
            if sig not in self._decision_signatures:
                self._decision_signatures.add(sig)
                self.decisions.append(dec)
                changed = True
        return changed


@dataclass
class GlobalState:
    roots: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    struct_slots: Dict[Tuple[str, int], StructSlot] = field(default_factory=dict)
    decisions: List[Decision] = field(default_factory=list)
    function_summaries: Dict[str, FunctionSummary] = field(default_factory=dict)
    analysis_stats: Dict[str, Any] = field(default_factory=lambda: defaultdict(int))
    overrides: List[Dict[str, Any]] = field(default_factory=list)
    registry_strings: Dict[str, Dict[str, Any]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def boolify(val: bool) -> bool:
    return bool(val)


def varnode_key(vn) -> Tuple:
    if vn is None:
        return (None,)
    if vn.isRegister():
        return ("reg", str(vn.getAddress()), vn.getSize())
    if vn.isUnique():
        return ("tmp", int(vn.getOffset()), vn.getSize())
    if vn.isConstant():
        return ("const", int(vn.getOffset()), vn.getSize())
    if vn.isAddrTied():
        return ("mem", str(vn.getAddress()), vn.getSize())
    return ("unk", str(vn), vn.getSize())


def pointer_base_identifier(func, vn) -> str:
    key = varnode_key(vn)
    func_name = func.getName() if func else "<unknown>"
    return f"{func_name}::{key}"


def new_value_from_varnode(vn) -> AbstractValue:
    width = vn.getSize() * 8 if vn else 32
    val = AbstractValue(bit_width=width)
    if vn and vn.isConstant():
        val.tainted = False
    return val


def opcode_name(op: PcodeOp) -> str:
    try:
        return op.getMnemonic()
    except Exception:
        return str(op.getOpcode())


# ---------------------------------------------------------------------------
# Registry root detection
# ---------------------------------------------------------------------------


REGISTRY_PREFIXES = ["Reg", "Zw", "Nt", "Cm", "Rtl"]

REGISTRY_HIVE_ALIASES = {
    "HKLM": ["HKLM", "HKEY_LOCAL_MACHINE", "\\Registry\\Machine"],
    "HKCU": ["HKCU", "HKEY_CURRENT_USER", "\\Registry\\User"],
    "HKCR": ["HKCR", "HKEY_CLASSES_ROOT"],
    "HKU": ["HKU", "HKEY_USERS"],
    "HKCC": ["HKCC", "HKEY_CURRENT_CONFIG"],
}

REGISTRY_STRING_PREFIX_RE = re.compile(
    r"^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|\\\\Registry\\\\Machine|\\\\Registry\\\\User)",
    re.IGNORECASE,
)


def is_registry_api(name: str) -> bool:
    if not name:
        return False
    lowered = name.lower()
    for pref in REGISTRY_PREFIXES:
        if lowered.startswith(pref.lower()):
            return True
    return False


def parse_registry_string(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    raw = raw.strip("\x00")
    m = REGISTRY_STRING_PREFIX_RE.match(raw)
    hive_key = None
    path = None
    value_name = None
    if m:
        prefix = m.group(1)
        for short, aliases in REGISTRY_HIVE_ALIASES.items():
            for alias in aliases:
                if prefix.lower().startswith(alias.lower()):
                    hive_key = short
                    break
            if hive_key:
                break
        hive_key = hive_key or prefix
        path = raw[len(prefix) :].lstrip("\\/")
    else:
        lowered = raw.lower()
        partial_prefixes = [
            "system\\currentcontrolset\\",
            "system\\controlset",
            "software\\",
            "control\\",
        ]
        partial_tuple = tuple(partial_prefixes)
        if any(pref in lowered for pref in partial_prefixes) or lowered.startswith(partial_tuple):
            path = raw.lstrip("\\/")
    if path is None:
        return None
    value_name = None
    if path and "\\" in path:
        parts = path.split("\\")
        if parts[-1]:
            value_name = parts[-1]
    return {"hive": hive_key, "path": path, "value_name": value_name, "raw": raw}


def collect_registry_string_candidates(program) -> Dict[str, Dict[str, Any]]:
    listing = program.getListing()
    candidates: Dict[str, Dict[str, Any]] = {}
    it = listing.getDefinedData(True)
    max_scan = 100_000
    scanned = 0
    while it.hasNext():
        scanned += 1
        if max_scan and scanned > max_scan:
            log_debug("[debug] registry string candidate scan capped for performance")
            break
        data = it.next()
        try:
            if not data.hasStringValue():
                continue
            val_obj = data.getValue()
            if hasattr(val_obj, "getString"):
                sval = val_obj.getString()
            else:
                sval = str(val_obj)
        except Exception:
            continue
        meta = parse_registry_string(sval)
        if meta:
            candidates[str(data.getAddress())] = meta
    return candidates


# ---------------------------------------------------------------------------
# Core analysis engine
# ---------------------------------------------------------------------------


class FunctionAnalyzer:
    def __init__(self, api: FlatProgramAPI, program, global_state: GlobalState, mode: str):
        self.api = api
        self.global_state = global_state
        self.mode = mode
        self.max_steps = 10_000_000
        self.max_function_iterations = 1_000_000
        self.program = program
        # Reuse a single BasicBlockModel for the program (safe for Ghidra 12).
        self.block_model = BasicBlockModel(self.program)

    def _get_function_for_inst(self, inst: Instruction):
        try:
            fm = self.program.getFunctionManager()
            return fm.getFunctionContaining(inst.getAddress())
        except Exception:
            return None

    def _resolve_string_from_vn(self, vn) -> Optional[Dict[str, Any]]:
        try:
            addr = None
            if vn is None:
                return None
            if hasattr(vn, "isAddress") and vn.isAddress():
                addr = vn.getAddress()
            elif vn.isAddrTied():
                addr = vn.getAddress()
            elif vn.isConstant():
                addr = self.api.toAddr(vn.getOffset())
            if addr is None:
                return None
            addr_str = str(addr)
            if addr_str in self.global_state.registry_strings:
                return self.global_state.registry_strings[addr_str]
            data = self.program.getListing().getDataContaining(addr)
            if data and data.hasStringValue():
                try:
                    val_obj = data.getValue()
                    sval = val_obj.getString() if hasattr(val_obj, "getString") else str(val_obj)
                    meta = parse_registry_string(sval)
                    if meta:
                        self.global_state.registry_strings[addr_str] = meta
                        return meta
                except Exception:
                    return self._decode_string_at_address(addr, addr_str)
            return self._decode_string_at_address(addr, addr_str)
        except Exception:
            return None
        return None

    def _decode_string_at_address(self, addr, addr_str: str) -> Optional[Dict[str, Any]]:
        try:
            mem = self.program.getMemory()
            buf = bytearray(512)
            read = mem.getBytes(addr, buf)
            if read is None:
                return None
            trimmed = bytes(buf[: int(read) if isinstance(read, (int, float)) else len(buf)])
            candidates: List[str] = []
            for codec, terminator in (("utf-16-le", b"\x00\x00"), ("utf-8", b"\x00"), ("latin-1", b"\x00")):
                try:
                    segment = trimmed.split(terminator)[0]
                    if not segment:
                        continue
                    sval = segment.decode(codec, errors="ignore")
                    if sval:
                        candidates.append(sval)
                except Exception:
                    continue
            for sval in candidates:
                meta = parse_registry_string(sval)
                if meta:
                    self.global_state.registry_strings[addr_str] = meta
                    return meta
        except Exception:
            return None
        return None

    def analyze_all(self) -> None:
        fm = self.program.getFunctionManager()
        worklist = deque(fm.getFunctions(True))
        iteration_guard = 0
        # NOTE: call-depth limiting is not currently implemented; the call_depth_limit
        # flag in analysis_stats remains a placeholder for future enhancements.
        while worklist and iteration_guard < self.max_function_iterations:
            func = worklist.popleft()
            iteration_guard += 1
            summary = self.analyze_function(func)
            self.global_state.analysis_stats["functions_analyzed"] += 1
            existing = self.global_state.function_summaries.get(func.getName())
            if existing is None:
                self.global_state.function_summaries[func.getName()] = summary
                worklist.extend(func.getCalledFunctions(DUMMY_MONITOR))
            else:
                if existing.merge_from(summary):
                    worklist.extend(func.getCalledFunctions(DUMMY_MONITOR))
        if iteration_guard >= self.max_function_iterations:
            log_debug("[warn] function iteration limit hit")
            self.global_state.analysis_stats["function_iterations_limit"] = True

    # ------------------------------------------------------------------
    # Function level fixed-point over basic blocks
    # ------------------------------------------------------------------

    def analyze_function(self, func) -> FunctionSummary:
        log_trace(f"[trace] analyzing function {func.getName()} at {func.getEntryPoint()}")
        summary = FunctionSummary(func.getName(), str(func.getEntryPoint()))
        body = func.getBody()
        listing = self.program.getListing()
        blocks = list(self.block_model.getCodeBlocksContaining(body, DUMMY_MONITOR))
        preds: Dict[Any, List[Any]] = defaultdict(list)
        succs: Dict[Any, List[Any]] = defaultdict(list)
        for blk in blocks:
            it = blk.getDestinations(DUMMY_MONITOR)
            while it.hasNext():
                dest = it.next()
                succs[blk].append(dest.getDestinationBlock())
                preds[dest.getDestinationBlock()].append(blk)
        in_states: Dict[Any, Dict[Tuple, AbstractValue]] = {blk: {} for blk in blocks}
        worklist: deque = deque(blocks)
        steps = 0
        while worklist and steps < self.max_steps:
            blk = worklist.popleft()
            steps += 1
            state = self._merge_predecessors(blk, preds, in_states)
            new_state = self._run_block(func, blk, state, listing, summary)
            if self._state_changed(in_states.get(blk, {}), new_state):
                in_states[blk] = new_state
                for succ in succs.get(blk, []):
                    if succ not in worklist:
                        worklist.append(succ)
        if steps >= self.max_steps:
            log_debug(f"[warn] worklist limit hit in function {func.getName()}")
            self.global_state.analysis_stats["worklist_limit"] = True
        self._finalize_summary_from_slots(summary)
        return summary

    def _merge_predecessors(self, blk, preds: Dict[Any, List[Any]], in_states: Dict[Any, Dict[Tuple, AbstractValue]]):
        merged: Dict[Tuple, AbstractValue] = {}
        for pred in preds.get(blk, []):
            for key, val in in_states.get(pred, {}).items():
                if key not in merged:
                    merged[key] = val.clone()
                else:
                    merged[key] = merged[key].merge(val)
        return merged

    def _state_changed(self, old: Dict[Tuple, AbstractValue], new: Dict[Tuple, AbstractValue]) -> bool:
        if set(old.keys()) != set(new.keys()):
            return True
        for k, v in new.items():
            o = old.get(k)
            if o is None:
                return True
            if v.state_signature() != o.state_signature():
                return True
        return False

    def _run_block(self, func, blk, state: Dict[Tuple, AbstractValue], listing, summary: FunctionSummary) -> Dict[Tuple, AbstractValue]:
        states = {k: v.clone() for k, v in state.items()}
        addr_set = AddressSet()
        try:
            addr_set.addRange(blk.getFirstStartAddress(), blk.getMaxAddress())
        except Exception:
            return states
        it = listing.getInstructions(addr_set, True)
        while it.hasNext():
            inst = it.next()
            try:
                pcode_ops = inst.getPcode()
            except Exception:
                pcode_ops = None
            if not pcode_ops:
                continue
            for op in pcode_ops:
                self._process_pcode(func, inst, op, states, summary)
        return states

    # ------------------------------------------------------------------
    # P-code processing
    # ------------------------------------------------------------------

    def _get_val(self, vn, states: Dict[Tuple, AbstractValue]) -> AbstractValue:
        key = varnode_key(vn)
        if key not in states:
            states[key] = new_value_from_varnode(vn)
        return states[key]

    def _set_val(self, vn, val: AbstractValue, states: Dict[Tuple, AbstractValue]) -> None:
        key = varnode_key(vn)
        states[key] = val
        log_trace(f"[trace] set {key} -> tainted={val.tainted} origins={sorted(val.origins)} bits={sorted(val.candidate_bits)}")

    def _process_pcode(self, func, inst: Instruction, op: PcodeOp, states: Dict[Tuple, AbstractValue], summary: FunctionSummary) -> None:
        opname = opcode_name(op)
        out = op.getOutput()
        inputs = [op.getInput(i) for i in range(op.getNumInputs())]
        if opname in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"}:
            self._handle_copy(out, inputs, states)
        elif opname in {"INT_ADD", "INT_SUB"}:
            self._handle_addsub(out, inputs, states, opname)
        elif opname in {"INT_MULT", "INT_DIV"}:
            self._handle_multdiv(out, inputs, states)
        elif opname == "INT_AND":
            self._handle_and(out, inputs, states)
        elif opname in {"INT_OR", "INT_XOR"}:
            self._handle_orxor(out, inputs, states)
        elif opname in {"INT_LEFT", "INT_RIGHT", "INT_SRIGHT"}:
            self._handle_shift(out, inputs, states, opname)
        elif opname == "LOAD":
            self._handle_load(out, inputs, states)
        elif opname == "STORE":
            self._handle_store(inst, inputs, states)
        elif opname == "PTRADD":
            self._handle_ptradd(func, out, inputs, states)
        elif opname in {"BRANCH", "CBRANCH"}:
            self._handle_branch(func, inst, opname, inputs, states, summary)
        elif opname == "MULTIEQUAL":
            self._handle_multiequal(out, inputs, states)
        elif opname == "CALL":
            self._handle_call(func, inst, op, inputs, states, summary)
        elif opname == "RETURN":
            self._handle_return(inputs, states, summary)
        else:
            self._handle_unknown(out, inputs, states)

    # Individual handlers
    def _handle_copy(self, out, inputs, states):
        if out is None or not inputs:
            return
        src = self._get_val(inputs[0], states)
        val = src.clone()
        val.bit_width = out.getSize() * 8
        self._set_val(out, val, states)

    def _handle_addsub(self, out, inputs, states, opname):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.bit_width = out.getSize() * 8
        val.used_bits = set(a.used_bits | b.used_bits)
        val.candidate_bits = set(a.candidate_bits | b.candidate_bits)
        if a.pointer_pattern and inputs[1].isConstant():
            pp = a.pointer_pattern.clone()
            delta = int(inputs[1].getOffset())
            pp.adjust_offset(delta if opname == "INT_ADD" else -delta)
            val.pointer_pattern = pp
        elif b.pointer_pattern and inputs[0].isConstant():
            pp = b.pointer_pattern.clone()
            delta = int(inputs[0].getOffset())
            pp.adjust_offset(delta if opname == "INT_ADD" else -delta)
            val.pointer_pattern = pp
        elif a.pointer_pattern and b.pointer_pattern:
            val.pointer_pattern = a.pointer_pattern.merge(b.pointer_pattern)
        self._set_val(out, val, states)

    def _handle_multdiv(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.bit_width = out.getSize() * 8
        val.used_bits = set(a.used_bits | b.used_bits)
        val.candidate_bits = set(a.candidate_bits | b.candidate_bits)
        val.pointer_pattern = PointerPattern(unknown=True) if (a.pointer_pattern or b.pointer_pattern) else None
        self._set_val(out, val, states)

    def _handle_and(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.bit_width = out.getSize() * 8
        val.used_bits = set(a.used_bits | b.used_bits)
        val.candidate_bits = set(a.candidate_bits | b.candidate_bits)
        mask_src = None
        other = None
        if inputs[0].isConstant():
            mask_src = inputs[0]
            other = b
        elif inputs[1].isConstant():
            mask_src = inputs[1]
            other = a
        if mask_src is not None and other is not None:
            mask_val = int(mask_src.getOffset())
            other_bits = AbstractValue(bit_width=other.bit_width)
            other_bits.mark_bits_used(mask_val)
            val.used_bits |= other_bits.used_bits
            val.candidate_bits |= other_bits.candidate_bits
        self._set_val(out, val, states)

    def _handle_orxor(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.bit_width = out.getSize() * 8
        val.used_bits = set(a.used_bits | b.used_bits)
        val.candidate_bits = set(a.candidate_bits | b.candidate_bits)
        self._set_val(out, val, states)

    def _handle_shift(self, out, inputs, states, opname):
        if out is None or len(inputs) < 2:
            return
        base = self._get_val(inputs[0], states)
        amt = inputs[1]
        val = AbstractValue()
        val.tainted = base.tainted or self._get_val(amt, states).tainted
        val.origins = set(base.origins | self._get_val(amt, states).origins)
        val.bit_width = out.getSize() * 8
        shift = amt.getOffset() if amt.isConstant() else None
        if shift is None:
            val.mark_all_bits_used()
        else:
            for b in base.candidate_bits or set(range(base.bit_width)):
                if opname == "INT_LEFT":
                    val.candidate_bits.add(min(val.bit_width - 1, b + shift))
                else:
                    new_b = b - shift
                    if new_b < 0:
                        new_b = 0
                    val.candidate_bits.add(new_b)
            val.used_bits |= set(val.candidate_bits)
        self._set_val(out, val, states)

    def _handle_load(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        addr_val = self._get_val(inputs[1], states)
        val = AbstractValue(bit_width=out.getSize() * 8)
        if addr_val.pointer_pattern and addr_val.pointer_pattern.base_id and addr_val.pointer_pattern.offset is not None:
            key = (addr_val.pointer_pattern.base_id, addr_val.pointer_pattern.offset)
            slot = self.global_state.struct_slots.get(key)
            if slot:
                val = slot.value.clone()
        self._set_val(out, val, states)

    def _handle_store(self, inst, inputs, states):
        if len(inputs) < 3:
            return
        addr_val = self._get_val(inputs[1], states)
        src_val = self._get_val(inputs[2], states)
        if addr_val.pointer_pattern and addr_val.pointer_pattern.base_id and addr_val.pointer_pattern.offset is not None:
            key = (addr_val.pointer_pattern.base_id, addr_val.pointer_pattern.offset)
            slot = self.global_state.struct_slots.get(key)
            if slot is None:
                slot = StructSlot(
                    addr_val.pointer_pattern.base_id,
                    addr_val.pointer_pattern.offset,
                    addr_val.pointer_pattern.stride,
                    addr_val.pointer_pattern.index_var,
                    value=src_val.clone(),
                )
                self.global_state.struct_slots[key] = slot
            else:
                slot.value = slot.value.merge(src_val)
            inst_func = self._get_function_for_inst(inst)
            func_name = inst_func.getName() if inst_func else "unknown"
            self.global_state.function_summaries.setdefault(
                func_name, FunctionSummary(func_name, str(inst.getAddress()))
            ).slot_writes.append(
                {
                    "base_id": slot.base_id,
                    "offset": slot.offset,
                    "origins": sorted(slot.value.origins),
                }
            )
            if slot.value.tainted and not src_val.tainted:
                self.global_state.overrides.append(
                    {
                        "address": str(inst.getAddress()),
                        "function": func_name,
                        "source_origins": sorted(src_val.origins),
                        "notes": "struct slot override",
                    }
                )

    def _handle_ptradd(self, func, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        base = self._get_val(inputs[0], states)
        offset = inputs[1]
        val = base.clone()
        if val.pointer_pattern is None:
            val.pointer_pattern = PointerPattern(base_id=pointer_base_identifier(func, inputs[0]))
        if offset.isConstant():
            val.pointer_pattern.adjust_offset(int(offset.getOffset()))
        else:
            val.pointer_pattern.index_var = varnode_key(offset)
            val.pointer_pattern.unknown = True
        self._set_val(out, val, states)

    def _handle_branch(self, func, inst, opname, inputs, states, summary: FunctionSummary):
        if not inputs:
            return
        cond_val = self._get_val(inputs[0], states)
        if self.mode == "taint" and not cond_val.origins:
            log_trace(f"[trace] skipping untainted branch at {inst.getAddress()}")
            return
        if not cond_val.candidate_bits:
            cond_val.mark_all_bits_used()
            branch_detail = {"type": "branch", "bit_heuristic": "all_bits_marked"}
        else:
            branch_detail = {"type": "branch"}
        decision = Decision(
            address=str(inst.getAddress()),
            mnemonic=inst.getMnemonicString(),
            disasm=inst.toString(),
            origins=set(cond_val.origins),
            used_bits=set(cond_val.used_bits or cond_val.candidate_bits),
            details=branch_detail,
        )
        decision.details["branch_kind"] = "unconditional" if opname == "BRANCH" else "conditional"
        summary.add_decision(decision)
        self.global_state.decisions.append(decision)

    def _handle_multiequal(self, out, inputs, states):
        if out is None:
            return
        merged = AbstractValue()
        for inp in inputs:
            merged = merged.merge(self._get_val(inp, states))
        merged.bit_width = out.getSize() * 8
        self._set_val(out, merged, states)

    def _handle_call(self, func, inst, op: PcodeOp, inputs, states, summary: FunctionSummary):
        call_args = inputs[1:] if inputs else []
        string_args: List[Dict[str, Any]] = []
        for inp in call_args:
            meta = self._resolve_string_from_vn(inp)
            if meta:
                string_args.append(meta)

        def _derive_registry_fields() -> Tuple[Optional[str], Optional[str], Optional[str]]:
            hive = path = value_name = None
            if string_args:
                hive = string_args[0].get("hive")
                path = string_args[0].get("path")
                value_name = string_args[0].get("value_name")
                if len(string_args) > 1:
                    value_candidate = string_args[1].get("value_name") or string_args[1].get("raw")
                    if value_candidate:
                        value_name = value_candidate
            return hive, path, value_name

        def _seed_root(root_id: str, api_label: str, entry_point: Optional[str]) -> None:
            hive, path, value_name = _derive_registry_fields()
            root_meta = self.global_state.roots.setdefault(
                root_id,
                {
                    "id": root_id,
                    "type": "registry",
                    "api_name": api_label,
                    "address": str(inst.getAddress()),
                    "entry": entry_point,
                    "hive": hive,
                    "path": path,
                    "value_name": value_name,
                },
            )
            if entry_point and not root_meta.get("entry"):
                root_meta["entry"] = entry_point
            if hive and not root_meta.get("hive"):
                root_meta["hive"] = hive
            if path and not root_meta.get("path"):
                root_meta["path"] = path
            if value_name and not root_meta.get("value_name"):
                root_meta["value_name"] = value_name
            if op.getOutput() is not None:
                val = self._get_val(op.getOutput(), states)
                val.tainted = True
                val.origins.add(root_id)
                val.bit_width = op.getOutput().getSize() * 8
                self._set_val(op.getOutput(), val, states)
        for idx, inp in enumerate(call_args):
            arg_val = self._get_val(inp, states)
            if arg_val.origins:
                summary.param_influence[idx] |= set(arg_val.origins)
        callee_name = None
        callee_func = None
        callee_refs = [r for r in inst.getReferencesFrom() if r.getReferenceType().isCall()]
        if callee_refs:
            to_addr = callee_refs[0].getToAddress()
            callee_func = self.program.getFunctionManager().getFunctionAt(to_addr)
            if callee_func:
                callee_name = callee_func.getName()
        if callee_name:
            callee_summary = self.global_state.function_summaries.get(callee_name)
            if callee_summary:
                for idx, roots in callee_summary.param_influence.items():
                    if idx < len(call_args):
                        val = self._get_val(call_args[idx], states)
                        summary.param_influence[idx] |= set(roots)
                        val.origins |= roots
                        val.tainted = val.tainted or bool(roots)
                if callee_summary.return_influence and op.getOutput() is not None:
                    val = AbstractValue(
                        tainted=True,
                        origins=set(callee_summary.return_influence),
                        bit_width=op.getOutput().getSize() * 8,
                    )
                    self._set_val(op.getOutput(), val, states)
                for slot in callee_summary.slot_writes:
                    key = (slot.get("base_id"), slot.get("offset"))
                    slot_val = self.global_state.struct_slots.get(key)
                    if slot_val:
                        slot_val.value.origins |= set(slot.get("origins", []))
                    else:
                        origins = set(slot.get("origins", []))
                        if key[0] is not None and key[1] is not None:
                            self.global_state.struct_slots[key] = StructSlot(
                                key[0], key[1], value=AbstractValue(origins=origins, tainted=bool(origins))
                            )
            if is_registry_api(callee_name):
                root_id = f"api_{callee_name}_{inst.getAddress()}"
                entry_point = str(callee_func.getEntryPoint()) if callee_func else None
                _seed_root(root_id, callee_name, entry_point)
            elif string_args:
                root_id = f"api_like_{callee_name}_{inst.getAddress()}"
                entry_point = str(callee_func.getEntryPoint()) if callee_func else None
                _seed_root(root_id, callee_name, entry_point)
        else:
            if string_args:
                root_id = f"indirect_{inst.getAddress()}"
                _seed_root(root_id, "<indirect>", None)
            if op.getOutput() is not None:
                out_val = self._get_val(op.getOutput(), states).clone()
                out_val.bit_width = op.getOutput().getSize() * 8
                for inp in call_args:
                    src = self._get_val(inp, states)
                    out_val = out_val.merge(src)
                self._set_val(op.getOutput(), out_val, states)

    def _handle_return(self, inputs, states, summary: FunctionSummary):
        if not inputs:
            return
        ret_source = inputs[-1] if len(inputs) > 1 else inputs[0]
        ret_val = self._get_val(ret_source, states)
        summary.return_influence |= set(ret_val.origins)

    def _handle_unknown(self, out, inputs, states):
        if out is None:
            return
        val = AbstractValue(bit_width=out.getSize() * 8)
        for inp in inputs:
            val = val.merge(self._get_val(inp, states))
        if not val.candidate_bits:
            val.mark_all_bits_used()
        self._set_val(out, val, states)

    def _finalize_summary_from_slots(self, summary: FunctionSummary) -> None:
        existing = self.global_state.function_summaries.get(summary.name)
        if existing:
            summary.merge_from(existing)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def build_root_records(global_state: GlobalState) -> List[Dict[str, Any]]:
    records = []
    for root_id, meta in sorted(global_state.roots.items()):
        slot_entries = []
        used_bits: Set[int] = set()
        candidate_bits: Set[int] = set()
        slot_bit_widths: List[int] = []
        for (base_id, offset), slot in global_state.struct_slots.items():
            if slot.value.origins and root_id in slot.value.origins:
                slot_entries.append(
                    {
                        "base_id": base_id,
                        "offset": offset,
                        "offset_hex": hex(offset),
                        "stride": slot.stride,
                        "index_based": bool(slot.index_var),
                        "notes": "struct slot",
                    }
                )
                used_bits |= slot.value.used_bits
                candidate_bits |= slot.value.candidate_bits
                slot_bit_widths.append(slot.value.bit_width)
        decisions = [d.to_dict() for d in global_state.decisions if root_id in d.origins]
        overrides = [o for o in global_state.overrides if root_id in o.get("source_origins", [])]
        record = {
            "id": root_id,
            "type": meta.get("type", "registry"),
            "hive": meta.get("hive"),
            "path": meta.get("path"),
            "value_name": meta.get("value_name"),
            "api_name": meta.get("api_name"),
            "entry": meta.get("entry"),
            "struct_slots": slot_entries,
            "bit_usage": {
                "bit_width": max([32] + slot_bit_widths),
                "used_bits": sorted(used_bits),
                "candidate_bits": sorted(candidate_bits),
            },
            "decisions": decisions,
            "overrides": overrides,
        }
        records.append(record)
    return records


def emit_ndjson(global_state: GlobalState) -> None:
    for rec in build_root_records(global_state):
        print(json.dumps(rec))
    summary = {
        "type": "analysis_summary",
        "functions_analyzed": len(global_state.function_summaries),
        "roots": len(global_state.roots),
        "decisions": len(global_state.decisions),
        "struct_slots": len(global_state.struct_slots),
        "limits_hit": {
            "worklist": boolify(global_state.analysis_stats.get("worklist_limit")),
            "function_iterations": boolify(global_state.analysis_stats.get("function_iterations_limit")),
            "call_depth": boolify(global_state.analysis_stats.get("call_depth_limit")),
        },
    }
    print(json.dumps(summary))


def emit_improvement_suggestions(global_state: GlobalState) -> None:
    suggestions: List[str] = []
    if not global_state.roots:
        suggestions.append(
            "No registry/config roots were detected; consider extending REGISTRY_PREFIXES or adding custom root seeding."
        )
    if not global_state.decisions:
        suggestions.append(
            "No branch decisions were attributed to roots; enable trace logging to confirm taint propagation and broaden bit tracking."
        )
    if global_state.analysis_stats.get("worklist_limit"):
        suggestions.append("Worklist iteration hit its safety limit; raise max_steps or refine CFG traversal to reach a fixpoint.")
    if global_state.analysis_stats.get("function_iterations_limit"):
        suggestions.append(
            "Function summary convergence stopped early; increase iteration budget or add call-depth pruning heuristics."
        )
    if global_state.analysis_stats.get("call_depth_limit"):
        suggestions.append("Call depth limit reached; review recursive or deeply nested call chains.")
    if not suggestions:
        suggestions.append(
            "Analysis completed without hitting safety limits; consider enabling full mode to broaden coverage if needed."
        )
    log_info("[suggestions] " + " | ".join(suggestions))


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def main():
    if not _ensure_environment(INVOCATION_CONTEXT):
        return
    if DUMMY_MONITOR is None:
        print(
            "[error] TaskMonitor.DUMMY is unavailable; cannot proceed with control-flow analysis.",
            file=sys.stderr,
        )
        if INVOCATION_CONTEXT == "headless":
            sys.exit(1)
        return
    program = currentProgram
    api = FlatProgramAPI(program)
    mode = args.get("mode") or "taint"
    log_info(
        f"[info] RegistryKeyBitfieldReport starting (mode={mode}, debug={DEBUG_ENABLED}, trace={TRACE_ENABLED}, context={INVOCATION_CONTEXT})"
    )
    if INVOCATION_CONTEXT == "script_manager":
        log_info("[info] Script Manager detected; NDJSON output will appear in the Ghidra console.")
    global_state = GlobalState()
    # ensure call_depth_limit is explicitly initialized (future use)
    global_state.analysis_stats["call_depth_limit"] = False
    global_state.registry_strings = collect_registry_string_candidates(program)
    log_debug(
        f"[debug] initial registry roots={len(global_state.roots)} registry-like strings={len(global_state.registry_strings)}"
    )
    analyzer = FunctionAnalyzer(api, program, global_state, mode)
    if args.get("max_steps"):
        analyzer.max_steps = max(1, int(args.get("max_steps")))
    if args.get("max_function_iterations"):
        analyzer.max_function_iterations = max(1, int(args.get("max_function_iterations")))
    analyzer.analyze_all()
    # Synthetic root for full mode when no registry APIs are detected
    if mode == "full" and not global_state.roots:
        synthetic_id = "synthetic_full_mode_root"
        global_state.roots[synthetic_id] = {
            "id": synthetic_id,
            "type": "synthetic",
            "api_name": None,
            "address": None,
            "entry": None,
            "hive": None,
            "path": None,
            "value_name": None,
        }
    emit_ndjson(global_state)
    emit_improvement_suggestions(global_state)
    log_debug(
        f"[debug] analyzed {len(global_state.function_summaries)} functions, roots={len(global_state.roots)} decisions={len(global_state.decisions)} slots={len(global_state.struct_slots)}"
    )


_REGKEYBITFIELDREPORT_RAN = False

def _maybe_run_main_from_script_manager():
    """
    Ghidra's Script Manager may execute this module without setting __name__ to
    "__main__". Run main() once in that scenario while avoiding double
    execution when PyGhidra invokes the script normally.
    """

    global _REGKEYBITFIELDREPORT_RAN
    if INVOCATION_CONTEXT == "script_manager" and not _REGKEYBITFIELDREPORT_RAN:
        _REGKEYBITFIELDREPORT_RAN = True
        main()


if __name__ == "__main__":
    _REGKEYBITFIELDREPORT_RAN = True
    main()
else:
    _maybe_run_main_from_script_manager()
