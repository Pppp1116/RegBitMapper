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
import os
from collections import defaultdict, deque
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

_JAVA_UNSAFE_SUPPRESS_FLAG = "-Dorg.apache.felix.framework.debug=false"
_existing_java_opts = os.environ.get("JAVA_TOOL_OPTIONS", "")
if _JAVA_UNSAFE_SUPPRESS_FLAG not in _existing_java_opts:
    os.environ["JAVA_TOOL_OPTIONS"] = (_existing_java_opts + " " + _JAVA_UNSAFE_SUPPRESS_FLAG).strip()

try:  # pragma: no cover - executed inside Ghidra
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.program.model.listing import Instruction
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.symbol import RefType, SourceType
    from ghidra.util.task import TaskMonitor
except Exception:  # pragma: no cover
    FlatProgramAPI = None
    BasicBlockModel = None
    Instruction = None
    PcodeOp = None
    RefType = None
    SourceType = None
    TaskMonitor = None
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
    if "max_call_depth" in parsed:
        try:
            parsed["max_call_depth"] = int(parsed.get("max_call_depth", "0"))
        except Exception:
            print("[warn] max_call_depth is not an integer; using default", file=sys.stderr)
            parsed.pop("max_call_depth", None)
    if "registry_scan_limit" in parsed:
        try:
            parsed["registry_scan_limit"] = int(parsed.get("registry_scan_limit", "0"))
        except Exception:
            print("[warn] registry_scan_limit is not an integer; using default", file=sys.stderr)
            parsed.pop("registry_scan_limit", None)
    parsed["enable_string_seeds"] = _parse_bool(parsed.get("enable_string_seeds", "true"))
    parsed["enable_indirect_roots"] = _parse_bool(parsed.get("enable_indirect_roots", "true"))
    parsed["enable_synthetic_full_root"] = _parse_bool(parsed.get("enable_synthetic_full_root", "true"))
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
    if not _has_mode(cli_args):
        print("[error] headless execution requires mode=taint|full", file=sys.stderr)
        sys.exit(1)
    args = parse_args(cli_args, INVOCATION_CONTEXT)
else:
    INVOCATION_CONTEXT = "script_manager"
    args = {"mode": "taint", "debug": False, "trace": False}
DEBUG_ENABLED = args.get("debug", False)
TRACE_ENABLED = args.get("trace", False)
for _flag in ["enable_string_seeds", "enable_indirect_roots", "enable_synthetic_full_root"]:
    args.setdefault(_flag, True)


DEFAULT_POINTER_BIT_WIDTH = 32


def _detect_pointer_bit_width(program) -> int:
    try:
        lang = program.getLanguage()
        space = getattr(lang, "getDefaultSpace", lambda: None)()
        if space:
            size_bytes = space.getPointerSize()
            if size_bytes:
                return int(size_bytes) * 8
    except Exception:
        pass
    return DEFAULT_POINTER_BIT_WIDTH


def _resolve_dummy_monitor():
    try:
        candidate = getattr(TaskMonitor, "DUMMY", None) if TaskMonitor else None
    except Exception:
        candidate = None
    if candidate is not None:
        return candidate

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


def _resolve_active_monitor():
    if TaskMonitor is not None:
        for accessor in ("getActiveMonitor", "current", "getCurrentMonitor"):
            try:
                getter = getattr(TaskMonitor, accessor, None)
                if getter:
                    current = getter()
                    if current is not None:
                        return current
            except Exception:
                continue
    for name in ("monitor", "currentMonitor"):
        cand = globals().get(name)
        try:
            if cand is not None and hasattr(cand, "isCancelled"):
                return cand
        except Exception:
            continue
    return DUMMY_MONITOR


ACTIVE_MONITOR = _resolve_active_monitor()


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
    offset_history: Set[int] = field(default_factory=set)

    def adjust_offset(self, delta: int) -> None:
        if self.offset is None:
            self.offset = delta
        else:
            self.offset += delta
        try:
            self.offset_history.add(self.offset)
            if len(self.offset_history) >= 2:
                sorted_offsets = sorted(self.offset_history)
                deltas = [b - a for a, b in zip(sorted_offsets, sorted_offsets[1:]) if b - a > 0]
                if deltas:
                    stride_candidate = deltas[0]
                    for d in deltas[1:]:
                        if d != stride_candidate:
                            stride_candidate = None
                            break
                    if stride_candidate:
                        self.stride = stride_candidate
        except Exception:
            pass

    def clone(self) -> "PointerPattern":
        return PointerPattern(
            base_id=self.base_id,
            offset=self.offset,
            stride=self.stride,
            index_var=self.index_var,
            unknown=self.unknown,
            offset_history=set(self.offset_history),
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
        merged.offset_history = set(self.offset_history | other.offset_history)
        return merged


@dataclass
class AbstractValue:
    tainted: bool = False
    origins: Set[str] = field(default_factory=set)
    bit_width: int = 32
    used_bits: Set[int] = field(default_factory=set)
    candidate_bits: Set[int] = field(default_factory=set)
    definitely_used_bits: Set[int] = field(default_factory=set)
    maybe_used_bits: Set[int] = field(default_factory=set)
    forbidden_bits: Set[int] = field(default_factory=set)
    pointer_pattern: Optional[PointerPattern] = None
    pointer_targets: Set[int] = field(default_factory=set)
    function_pointer_labels: Set[str] = field(default_factory=set)
    compare_details: Dict[str, Any] = field(default_factory=dict)
    mask_history: List[Dict[str, Any]] = field(default_factory=list)
    bit_usage_degraded: bool = False
    slot_sources: Set[Tuple[str, int]] = field(default_factory=set)

    def clone(self) -> "AbstractValue":
        return AbstractValue(
            tainted=self.tainted,
            origins=set(self.origins),
            bit_width=self.bit_width,
            used_bits=set(self.used_bits),
            candidate_bits=set(self.candidate_bits),
            definitely_used_bits=set(self.definitely_used_bits),
            maybe_used_bits=set(self.maybe_used_bits),
            forbidden_bits=set(self.forbidden_bits),
            pointer_pattern=self.pointer_pattern.clone() if self.pointer_pattern else None,
            pointer_targets=set(self.pointer_targets),
            function_pointer_labels=set(self.function_pointer_labels),
            compare_details=dict(self.compare_details),
            mask_history=list(self.mask_history),
            bit_usage_degraded=self.bit_usage_degraded,
            slot_sources=set(self.slot_sources),
        )

    def mark_bits_used(self, mask: int) -> None:
        for i in range(self.bit_width):
            if mask & (1 << i):
                self.candidate_bits.add(i)
                self.used_bits.add(i)
                self.definitely_used_bits.add(i)
                self.maybe_used_bits.add(i)

    def mark_all_bits_used(self, degraded: bool = False) -> None:
        for i in range(self.bit_width):
            self.candidate_bits.add(i)
            self.used_bits.add(i)
            self.definitely_used_bits.add(i)
            self.maybe_used_bits.add(i)
        if degraded:
            self.bit_usage_degraded = True

    def merge(self, other: "AbstractValue") -> "AbstractValue":
        if other is None:
            return self
        merged = AbstractValue()
        merged.tainted = self.tainted or other.tainted
        merged.origins = set(self.origins | other.origins)
        merged.bit_width = max(self.bit_width, other.bit_width)
        merged.used_bits = set(self.used_bits | other.used_bits)
        merged.definitely_used_bits = set(self.definitely_used_bits | other.definitely_used_bits | merged.used_bits)
        merged.maybe_used_bits = set(self.maybe_used_bits | other.maybe_used_bits | merged.definitely_used_bits)
        merged.candidate_bits = set(self.candidate_bits | other.candidate_bits | merged.maybe_used_bits)
        merged.forbidden_bits = set(self.forbidden_bits | other.forbidden_bits)
        merged.pointer_targets = set(self.pointer_targets | other.pointer_targets)
        merged.function_pointer_labels = set(self.function_pointer_labels | other.function_pointer_labels)
        if self.pointer_pattern and other.pointer_pattern:
            merged.pointer_pattern = self.pointer_pattern.merge(other.pointer_pattern)
        elif self.pointer_pattern:
            merged.pointer_pattern = self.pointer_pattern.clone()
        elif other.pointer_pattern:
            merged.pointer_pattern = other.pointer_pattern.clone()
        else:
            merged.pointer_pattern = None
        merged.compare_details = dict(self.compare_details or {})
        if other.compare_details:
            merged.compare_details.update(other.compare_details)
        merged.mask_history = list(self.mask_history or []) + list(other.mask_history or [])
        merged.bit_usage_degraded = self.bit_usage_degraded or other.bit_usage_degraded
        merged.slot_sources = set(self.slot_sources | other.slot_sources)
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
            frozenset(self.definitely_used_bits),
            frozenset(self.maybe_used_bits),
            frozenset(self.candidate_bits),
            pointer_sig,
            frozenset(self.pointer_targets),
            frozenset(self.function_pointer_labels),
            frozenset(self.compare_details.items()),
            tuple(sorted([tuple(sorted(m.items())) for m in self.mask_history])) if self.mask_history else (),
            self.bit_usage_degraded,
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
    uses_registry: bool = False
    registry_decision_roots: Set[str] = field(default_factory=set)
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
        if decision.origins:
            self.uses_registry = True
            self.registry_decision_roots |= set(decision.origins)

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
        if other.uses_registry and not self.uses_registry:
            self.uses_registry = True
            changed = True
        merged_roots = set(self.registry_decision_roots | other.registry_decision_roots)
        if merged_roots != self.registry_decision_roots:
            self.registry_decision_roots = merged_roots
            changed = True
        return changed


@dataclass
class GlobalState:
    roots: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    struct_slots: Dict[Tuple[str, int], StructSlot] = field(default_factory=dict)
    decisions: List[Decision] = field(default_factory=list)
    function_summaries: Dict[str, FunctionSummary] = field(default_factory=dict)
    analysis_stats: Dict[str, Any] = field(default_factory=dict)
    overrides: List[Dict[str, Any]] = field(default_factory=list)
    registry_strings: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    root_decision_index: Dict[str, List[Decision]] = field(default_factory=lambda: defaultdict(list))
    root_slot_index: Dict[str, Set[Tuple[str, int]]] = field(default_factory=lambda: defaultdict(set))
    root_override_index: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    heap_string_writes: Dict[str, Dict[int, bytes]] = field(default_factory=lambda: defaultdict(dict))


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def boolify(val: bool) -> bool:
    return bool(val)


def vn_has_address(vn) -> bool:
    try:
        if vn is None:
            return False
        if hasattr(vn, "isAddress") and vn.isAddress():
            return True
        if hasattr(vn, "isAddrTied") and vn.isAddrTied():
            return True
    except Exception:
        return False
    return False


def varnode_key(vn) -> Tuple:
    if vn is None:
        return (None,)
    if vn.isRegister():
        return ("reg", str(vn.getAddress()), vn.getSize())
    if vn.isUnique():
        return ("tmp", int(vn.getOffset()), vn.getSize())
    if vn.isConstant():
        return ("const", int(vn.getOffset()), vn.getSize())
    if vn_has_address(vn):
        return ("mem", str(vn.getAddress()), vn.getSize())
    return ("unk", str(vn), vn.getSize())


_BASE_ID_STORAGE_META: Dict[str, Dict[str, Any]] = {}


def _record_storage_metadata(base_id: Optional[str], vn, program) -> None:
    if not base_id or vn is None or program is None:
        return
    meta = _BASE_ID_STORAGE_META.get(base_id, {})
    try:
        addr = vn.getAddress()
    except Exception:
        addr = None
    space_name = None
    block_name = None
    if addr is not None:
        try:
            space = addr.getAddressSpace()
            if space:
                space_name = space.getName()
        except Exception:
            space_name = None
        try:
            mem = program.getMemory()
            if mem:
                block = mem.getBlock(addr)
                if block:
                    block_name = block.getName()
        except Exception:
            block_name = None
    if space_name:
        meta["space_name"] = space_name
    if block_name:
        meta["block_name"] = block_name
    if meta:
        _BASE_ID_STORAGE_META[base_id] = meta


def _definitely_bits(val: AbstractValue) -> Set[int]:
    bits = set(val.definitely_used_bits or val.used_bits)
    if not bits and val.used_bits:
        bits |= set(val.used_bits)
    return bits


def _maybe_bits(val: AbstractValue) -> Set[int]:
    bits = set(val.maybe_used_bits or val.candidate_bits)
    if not bits:
        bits |= set(val.definitely_used_bits)
    if not bits:
        bits |= set(val.used_bits)
    return bits


def _fallback_bits_from_value(val: AbstractValue) -> Set[int]:
    width = max(1, int(val.bit_width or DEFAULT_POINTER_BIT_WIDTH))
    bits: Set[int] = set()
    for entry in val.mask_history or []:
        try:
            mask_val = int(entry.get("mask", 0))
        except Exception:
            continue
        bits |= _mask_to_bits(mask_val, width)
    compare_meta = val.compare_details or {}
    const_mask_bits = compare_meta.get("constant_mask_bits")
    if const_mask_bits:
        try:
            bits |= {int(b) for b in const_mask_bits}
        except Exception:
            pass
    approx_range = compare_meta.get("approx_bit_range")
    if approx_range and len(approx_range) >= 2:
        try:
            start = max(0, int(approx_range[0]))
            end = min(width - 1, int(approx_range[1]))
            if end >= start:
                bits |= set(range(start, end + 1))
        except Exception:
            pass
    if not bits:
        return set(range(width))
    return bits


def _mask_to_bits(mask: int, width: int) -> Set[int]:
    try:
        return {i for i in range(width) if mask & (1 << i)}
    except Exception:
        return set()


def _bits_from_mask_history(val: AbstractValue) -> Set[int]:
    bits: Set[int] = set()
    for entry in val.mask_history:
        try:
            mask = int(entry.get("mask", 0))
            bits |= _mask_to_bits(mask, val.bit_width)
        except Exception:
            continue
    return bits


def pointer_base_identifier(func, vn) -> str:
    key = varnode_key(vn)
    func_name = func.getName() if func else "<unknown>"
    return f"{func_name}::{key}"


def slot_key_from_pattern(ptr: Optional[PointerPattern]) -> Optional[Tuple[str, int]]:
    if ptr is None or ptr.base_id is None or ptr.offset is None:
        return None
    offset_val = ptr.offset
    if ptr.index_var is not None and ptr.stride:
        try:
            offset_val = ptr.offset % ptr.stride
        except Exception:
            offset_val = ptr.offset
    return (ptr.base_id, offset_val)


def classify_storage(base_id: Optional[str]) -> str:
    if not base_id:
        return "heap_or_unknown"
    meta = _BASE_ID_STORAGE_META.get(base_id, {})
    space_name = str(meta.get("space_name") or "").lower()
    block_name = str(meta.get("block_name") or "").lower()
    if space_name == "stack":
        return "stack"
    if space_name == "ram" and block_name in {".data", ".rdata", ".bss"}:
        return "global"
    return "heap_or_unknown"


def vn_is_constant(vn) -> bool:
    try:
        return bool(vn) and vn.isConstant()
    except Exception:
        return False


def vn_get_offset(vn) -> Optional[int]:
    try:
        if vn_is_constant(vn):
            return int(vn.getOffset())
    except Exception:
        return None
    return None


def new_value_from_varnode(vn) -> AbstractValue:
    width = vn.getSize() * 8 if vn else DEFAULT_POINTER_BIT_WIDTH
    if not width:
        width = DEFAULT_POINTER_BIT_WIDTH
    val = AbstractValue(bit_width=width)
    if vn and vn.isConstant():
        val.tainted = False
        off = vn_get_offset(vn)
        if off is not None:
            val.pointer_targets.add(off)
    try:
        if vn_has_address(vn):
            addr = vn.getAddress()
            if addr is not None and hasattr(addr, "getOffset"):
                val.pointer_targets.add(int(addr.getOffset()))
    except Exception:
        pass
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
REGISTRY_RTL_REGISTRY_RE = re.compile(r"(?i)^rtl.*registry")

# Curated registry API names help avoid accidental matches against local
# functions with Reg*/Zw*/Nt*/Rtl*/Cm* prefixes that have nothing to do with
# the Windows registry.
CURATED_REGISTRY_APIS = {
    "cmcreatekey",
    "cmdeletekey",
    "cmdeletevaluekey",
    "cmenumeratekey",
    "cmenumeratevaluekey",
    "cmopenkey",
    "cmquerykey",
    "cmquerykeysecurity",
    "cmqueryvaluekey",
    "cmrenamekey",
    "cmsetkeysecurity",
    "cmsetvaluekey",
    "ntcreatekey",
    "ntdeletekey",
    "ntdeletevaluekey",
    "ntopenkey",
    "ntopenkeyex",
    "ntqueryattributesfile",
    "ntquerykey",
    "ntquerymultiplevaluekey",
    "ntqueryvaluekey",
    "ntsetinformationkey",
    "ntsetvaluekey",
    "rtlcheckregistrykey",
    "rtlcreateregistrykey",
    "rtldeleteregistryvalue",
    "rtlqueryregistryvalues",
    "rtlwriteregistryvalue",
    "regclosekey",
    "regconnectregistrya",
    "regconnectregistryw",
    "regcreatekeya",
    "regcreatekeyexa",
    "regcreatekeyexw",
    "regcreatekeytransacteda",
    "regcreatekeytransactedw",
    "regcreatekeyw",
    "regdeletekey",
    "regdeletekeyexa",
    "regdeletekeyexw",
    "regdeletekeytransacteda",
    "regdeletekeytransactedw",
    "regdeletevaluea",
    "regdeletevaluew",
    "regdisablepredefinedcache",
    "regdisablepredefinedcacheex",
    "regdisablereflectionkey",
    "regenablereflectionkey",
    "regenumkeyexa",
    "regenumkeyexw",
    "regenumvaluea",
    "regenumvaluew",
    "regflushkey",
    "reggetvaluea",
    "reggetvaluew",
    "regloadkeya",
    "regloadkeyw",
    "regnotifychangekeyvalue",
    "regopenkeya",
    "regopenkeyexa",
    "regopenkeyexw",
    "regopenkeytransacteda",
    "regopenkeytransactedw",
    "regopenkeyw",
    "regqueryinfokey",
    "regqueryvaluea",
    "regqueryvalueexa",
    "regqueryvalueexw",
    "regqueryvaluew",
    "regrestorekeya",
    "regrestorekeyw",
    "regsavekeya",
    "regsavekeyex",
    "regsavekeyexw",
    "regsavekeyw",
    "regsetkeysecurity",
    "regsetvaluea",
    "regsetvalueexa",
    "regsetvalueexw",
    "regsetvaluew",
    "regunloadkey",
    "zwcreatekey",
    "zwdeletekey",
    "zwdeletevaluekey",
    "zwenumeratekey",
    "zwenumeratevaluekey",
    "zwflushkey",
    "zwloadkey",
    "zwnotifychangekey",
    "zwopenkey",
    "zwopenkeyex",
    "zwquerykey",
    "zwquerymultiplevaluekey",
    "zwqueryvaluekey",
    "zwrestorekey",
    "zwsavekey",
    "zwsetinformationkey",
    "zwsetvaluekey",
}

# Imported registry APIs gathered from the binary's externals. Filled in at
# runtime inside main().
IMPORTED_REGISTRY_API_NAMES: Set[str] = set()
IMPORTED_REGISTRY_API_ADDRS: Dict[Any, str] = {}

# HKEY_* handle constants and their logical hive names/kernels-style roots for
# combining with "SOFTWARE\\RegTestMatrix\\..." suffixes.
HKEY_HANDLE_MAP: Dict[int, Dict[str, str]] = {
    0x80000000: {"hive": "HKCR", "nt_root": "\\Registry\\Machine"},
    0x80000001: {"hive": "HKCU", "nt_root": "\\Registry\\User"},
    0x80000002: {"hive": "HKLM", "nt_root": "\\Registry\\Machine"},
    0x80000003: {"hive": "HKU", "nt_root": "\\Registry\\User"},
    0x80000005: {"hive": "HKCC", "nt_root": "\\Registry\\Machine"},
}

REGISTRY_HIVE_ALIASES = {
    "HKLM": ["HKLM", "HKEY_LOCAL_MACHINE", "\\Registry\\Machine", "Registry\\Machine"],
    "HKCU": ["HKCU", "HKEY_CURRENT_USER", "\\Registry\\User", "Registry\\User"],
    "HKCR": ["HKCR", "HKEY_CLASSES_ROOT"],
    "HKU": ["HKU", "HKEY_USERS", "\\Registry\\Users", "Registry\\Users"],
    "HKCC": ["HKCC", "HKEY_CURRENT_CONFIG"],
}

REGISTRY_STRING_PREFIX_RE = re.compile(
    r"(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|\\\\?Registry\\\\Machine|\\\\?Registry\\\\User|\\\\?Registry\\\\Users)",
    re.IGNORECASE,
)

REGISTRY_LIKELY_PATH_RE = re.compile(
    r"(?i)^(?:"
    r"HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|"
    r"(?:\\?Registry\\(?:Machine|User|Users))|"
    r"software\\|system\\|hardware\\|sam\\|security\\|currentcontrolset\\|controlset[0-9]+\\"
    r")",
)


def normalize_registry_label(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    cleaned = re.sub(r"(?i)^(?:j__|__imp__?|imp_|__imported_|imported_)", "", cleaned)
    cleaned = cleaned.strip("@ !:\\/")
    # Keep suffixes that look registry-like, handling common separators and
    # mangled import labels such as ADVAPI32.dll::RegOpenKeyExA@16 or
    # ADVAPI32.dll_RegQueryValueExW. We also want to gracefully accept
    # decorations like "__imp__RegOpenKeyExA@16" and thunks that carry module
    # qualifiers.
    split_re = r"[.:@!\\/]|::"
    tokens: List[str] = []
    for part in re.split(split_re, cleaned):
        for seg in part.split("_"):
            seg = seg.strip()
            if seg:
                tokens.append(seg)
    tokens = tokens or [cleaned]
    # strip leftover decoration like @NN or trailing digits
    cleaned = re.sub(r"@[0-9]+$", "", cleaned)
    cleaned = re.sub(r"\$[A-Za-z0-9_]+$", "", cleaned)
    registry_re = re.compile(r"(?i)(reg|zw|nt|cm|rtl)[a-z0-9_@]*")
    for tok in reversed(tokens):
        m = registry_re.search(tok)
        if m:
            return m.group(0)
    m = registry_re.search(cleaned)
    return m.group(0) if m else None


def is_registry_api(name: str) -> bool:
    """
    Return True if the given function name looks like a Windows registry API.

    This handles both plain names (e.g., "RegOpenKeyExA") and module-prefixed
    imports that Ghidra may emit (e.g., "ADVAPI32.dll::RegOpenKeyExA" or
    "ADVAPI32.dll_RegQueryValueExW").
    """
    if not name:
        return False

    normalized = normalize_registry_label(name)
    if not normalized:
        return False

    lowered = normalized.lower()
    matched = False

    if lowered in CURATED_REGISTRY_APIS:
        matched = True

    if lowered in IMPORTED_REGISTRY_API_NAMES:
        matched = True

    if not matched:
        likely_external = ("::" in name) or (normalized in IMPORTED_REGISTRY_API_NAMES)
        prefix_hit = any(lowered.startswith(pref.lower()) for pref in REGISTRY_PREFIXES)
        if lowered.startswith("rtl") and REGISTRY_RTL_REGISTRY_RE.match(lowered):
            matched = likely_external or True
        elif prefix_hit and likely_external:
            matched = True

    if matched and DEBUG_ENABLED:
        log_debug(f"[debug] registry API matched: callee_name={name!r} normalized={normalized!r}")

    return matched


def classify_registry_api_kind(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    lowered = (normalize_registry_label(name) or name).lower()
    if "querymultiplevalue" in lowered or "queryregistryvalues" in lowered:
        return "rtl_query_table"
    if "queryvalue" in lowered or "getvalue" in lowered:
        return "query_value"
    if "setvalue" in lowered:
        return "set_value"
    if "createkey" in lowered:
        return "create_key"
    if "openkey" in lowered or "connectregistry" in lowered:
        return "open_key"
    if "delete" in lowered and "value" in lowered:
        return "delete_value"
    if "delete" in lowered and "key" in lowered:
        return "delete_key"
    if lowered.startswith("rtl"):
        return "rtl_query_table"
    return None


def parse_registry_string(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    raw = raw.strip("\x00").strip()
    if not raw:
        return None
    raw = raw.replace("/", "\\")
    # Trim leading junk before a known hive fragment if present, but do not
    # require a canonical prefix – synthetic/relative paths are allowed.
    m = REGISTRY_STRING_PREFIX_RE.search(raw)
    hive_key = None
    path = raw
    key_path: Optional[str] = None
    value_name = None
    if m:
        candidate_segment = raw[m.start() :]
        prefix = m.group(1)
        for short, aliases in REGISTRY_HIVE_ALIASES.items():
            for alias in aliases:
                if prefix.lower().startswith(alias.lower()):
                    hive_key = short
                    break
            if hive_key:
                break
        hive_key = hive_key or prefix
        path = candidate_segment[len(prefix) :].lstrip("\\/") or candidate_segment
    path = path.strip().strip("\x00")
    if not path:
        return None
    path = path.strip("\0\r\n \t\"")
    lowered_path = path.lower()
    if hive_key is None:
        if lowered_path.startswith("registry\\"):
            hive_key = "HKLM" if "\\machine\\" in lowered_path else None
            hive_key = hive_key or ("HKU" if "\\user" in lowered_path or "\\users" in lowered_path else None)
        if not REGISTRY_LIKELY_PATH_RE.match(path):
            return None
    elif lowered_path.startswith("registry\\"):
        path = re.sub(r"(?i)^registry\\(?:machine|user|users)\\?", "", path)
    if "\\" not in path:
        return None
    parts = [p for p in path.split("\\") if p]
    if not parts:
        return None
    if len(parts) > 1:
        value_name = parts[-1]
        key_path = "\\".join(parts[:-1])
        path = "\\".join(parts)
    elif "\\" in path:
        value_name = parts[-1]
        path = "\\".join(parts)
    return {
        "hive": hive_key,
        "path": path,
        "key_path": key_path,
        "value_name": value_name,
        "has_prefix": bool(hive_key),
        "raw": raw,
    }


def _decode_registry_string_from_memory(
    program, addr, max_len: int = 512, strip_leading_nulls: bool = False, stop_after_first: bool = False
) -> Optional[Dict[str, Any]]:
    try:
        mem = program.getMemory()
        buf = bytearray(max(1, max_len))
        read = mem.getBytes(addr, buf)
        if not isinstance(read, (int, float)) or read <= 0:
            return None
        trimmed = bytes(buf[: int(read)])
    except Exception:
        return None
    codecs = (("utf-16-le", b"\x00\x00"), ("utf-8", b"\x00"), ("latin-1", b"\x00"))
    if stop_after_first:
        for codec, terminator in codecs:
            try:
                segment = trimmed.split(terminator)[0]
                if strip_leading_nulls:
                    segment = segment.lstrip(b"\x00")
                if not segment:
                    continue
                sval = segment.decode(codec, errors="ignore")
                if not sval:
                    continue
                meta = parse_registry_string(sval)
                if meta:
                    return meta
                return None
            except Exception:
                continue
        return None
    candidates: List[str] = []
    for codec, terminator in codecs:
        try:
            segment = trimmed.split(terminator)[0]
            if strip_leading_nulls:
                segment = segment.lstrip(b"\x00")
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
            return meta
    return None


def collect_registry_string_candidates(program, scan_limit: Optional[int] = None) -> Dict[str, Dict[str, Any]]:
    listing = program.getListing()
    candidates: Dict[str, Dict[str, Any]] = {}
    if scan_limit == 0:
        return {}
    max_scan = scan_limit
    scanned = 0
    monitor = ACTIVE_MONITOR or DUMMY_MONITOR
    for data in listing.getDefinedData(True):
        try:
            if monitor and hasattr(monitor, "isCancelled") and monitor.isCancelled():
                log_debug("[debug] registry string scan cancelled by user")
                break
        except Exception:
            pass
        scanned += 1
        if max_scan is not None and scanned > max_scan:
            log_debug("[debug] registry string candidate scan capped for performance")
            break
        try:
            sval: Optional[str] = None
            meta: Optional[Dict[str, Any]] = None
            if data.hasStringValue():
                try:
                    val_obj = data.getValue()
                    sval = val_obj.getString() if hasattr(val_obj, "getString") else str(val_obj)
                    if sval is not None:
                        meta = parse_registry_string(sval)
                except Exception:
                    sval = None
            if sval is None and meta is None:
                meta = _decode_registry_string_from_memory(
                    program,
                    data.getAddress(),
                    max_len=max(16, data.getLength()),
                    strip_leading_nulls=False,
                    stop_after_first=True,
                )
            if meta:
                candidates[str(data.getAddress())] = meta
        except Exception as e:
            if DEBUG_ENABLED:
                try:
                    addr_str = str(data.getAddress())
                except Exception:
                    addr_str = "<unknown>"
                log_debug(f"[debug] error in collect_registry_string_candidates at {addr_str}: {e!r}")
            continue
    return candidates


def collect_imported_registry_apis(program) -> Tuple[Set[str], Dict[Any, str]]:
    names: Set[str] = set()
    addr_map: Dict[Any, str] = {}

    def _record_symbol(sym_name: Optional[str], addr_obj) -> None:
        normalized = normalize_registry_label(sym_name)
        if not normalized:
            return
        lowered = normalized.lower()
        if lowered not in CURATED_REGISTRY_APIS:
            prefixes = [p.lower() for p in REGISTRY_PREFIXES]
            if not any(lowered.startswith(pref) for pref in prefixes):
                return
        names.add(lowered)
        try:
            if addr_obj is not None and hasattr(addr_obj, "getOffset"):
                addr_map[int(addr_obj.getOffset())] = normalized
                addr_map[str(addr_obj)] = normalized
                if DEBUG_ENABLED:
                    log_debug(
                        f"[debug] registry import detected: raw={sym_name!r} normalized={normalized!r} addr={addr_obj}"
                    )
        except Exception:
            pass

    try:
        symtab = program.getSymbolTable()
        ext_syms = symtab.getExternalSymbols() if symtab else None
        if ext_syms:
            for sym in ext_syms:
                try:
                    _record_symbol(sym.getName(True) if hasattr(sym, "getName") else str(sym), sym.getAddress())
                except Exception:
                    continue
    except Exception:
        pass

    try:
        fm = program.getFunctionManager()
        for f in fm.getFunctions(True):
            try:
                if getattr(f, "isExternal", lambda: False)():
                    _record_symbol(f.getName(), f.getEntryPoint())
            except Exception:
                continue
    except Exception:
        pass

    return names, addr_map


# ---------------------------------------------------------------------------
# Core analysis engine
# ---------------------------------------------------------------------------


class FunctionAnalyzer:
    DEFAULT_MAX_STEPS = 5_000_000
    DEFAULT_MAX_FUNCTION_ITERATIONS = 250_000

    def __init__(self, api: FlatProgramAPI, program, global_state: GlobalState, mode: str, max_call_depth: Optional[int] = None):
        self.api = api
        self.global_state = global_state
        self.mode = mode
        self.max_steps = self.DEFAULT_MAX_STEPS
        self.max_function_iterations = self.DEFAULT_MAX_FUNCTION_ITERATIONS
        self.max_call_depth = max_call_depth
        self.program = program
        # Reuse a single BasicBlockModel for the program (safe for Ghidra 12).
        self.block_model = BasicBlockModel(self.program)
        self.monitor = ACTIVE_MONITOR or DUMMY_MONITOR
        self._registry_string_usage_cache: Dict[str, bool] = {}
        self._functions_with_registry_calls: Set[str] = set()

    def _get_function_for_inst(self, inst: Instruction):
        try:
            fm = self.program.getFunctionManager()
            return fm.getFunctionContaining(inst.getAddress())
        except Exception:
            return None

    def _record_base_id_metadata(self, base_id: Optional[str], vn) -> None:
        _record_storage_metadata(base_id, vn, self.program)

    def _function_has_registry_calls(self, func) -> bool:
        if func is None:
            return False
        try:
            if func.getName() in self._functions_with_registry_calls:
                return True
            summary = self.global_state.function_summaries.get(func.getName())
            if summary and summary.uses_registry:
                return True
        except Exception:
            return False

    def _pointer_args_from_registry(self, pointer_args: List[Any], states: Dict[Tuple, AbstractValue]) -> bool:
        for arg in pointer_args:
            try:
                if self._get_val(arg, states).origins:
                    return True
            except Exception:
                continue
        return False

    def _mark_all_bits_used_degraded(self, val: AbstractValue) -> None:
        original_used = set(val.used_bits)
        original_candidates = set(val.candidate_bits)
        if not val.used_bits and not val.candidate_bits:
            fallback_bits = _fallback_bits_from_value(val)
            val.used_bits |= set(fallback_bits)
            val.definitely_used_bits |= set(fallback_bits)
            val.maybe_used_bits |= set(fallback_bits)
            val.candidate_bits |= set(fallback_bits)
            val.bit_usage_degraded = True
        else:
            val.bit_usage_degraded = True
        if val.used_bits != original_used or val.candidate_bits != original_candidates:
            val.bit_usage_degraded = True
        self.global_state.analysis_stats["bit_precision_degraded"] = True

    def _resolve_string_at_address(self, addr, addr_str: str) -> Optional[Dict[str, Any]]:
        if addr_str in self.global_state.registry_strings:
            return self.global_state.registry_strings[addr_str]
        # --- inside _resolve_string_at_address ---
        data = self.program.getListing().getDataContaining(addr)
        if data and data.hasStringValue():
            try:
                val_obj = data.getValue()
                sval = val_obj.getString() if hasattr(val_obj, "getString") else str(val_obj)
                meta = parse_registry_string(sval)
                if meta:
                    self.global_state.registry_strings[addr_str] = meta
                    return meta
            except Exception as e:
                if DEBUG_ENABLED:
                    log_debug(f"[debug] error resolving string value at {addr_str}: {e!r}")
        return self._decode_string_at_address(addr, addr_str)

    def _registry_string_addresses(self) -> Set[str]:
        # do not cache — registry strings can be discovered dynamically during analysis
        return set(self.global_state.registry_strings.keys())

    def _function_uses_registry_strings(self, func) -> bool:
        if func is None:
            return False
        key = self._func_key(func)
        if key in self._registry_string_usage_cache:
            return self._registry_string_usage_cache[key]
        ref_mgr = getattr(self.program, "getReferenceManager", lambda: None)()
        listing = self.program.getListing()
        addr_set = self._registry_string_addresses()
        uses_strings = False
        try:
            it = listing.getInstructions(func.getBody(), True)
            for inst in it:
                try:
                    refs = list(ref_mgr.getReferencesFrom(inst.getAddress())) if ref_mgr else []
                except Exception:
                    refs = []
                for ref in refs:
                    to_addr = getattr(ref, "getToAddress", lambda: None)()
                    if to_addr is None:
                        continue
                    if str(to_addr) in addr_set:
                        uses_strings = True
                        break
                if uses_strings:
                    break
        except Exception as e:
            if DEBUG_ENABLED:
                log_debug(f"[debug] error checking registry strings in {func.getName()}: {e!r}")
        self._registry_string_usage_cache[key] = uses_strings
        return uses_strings

    def _external_label_for_address(self, addr) -> Optional[str]:
        ref_mgr = getattr(self.program, "getReferenceManager", lambda: None)()
        if ref_mgr is None:
            return None
        try:
            addr_space = addr.getAddressSpace() if addr is not None else None
            if addr_space and str(addr_space).lower().startswith("external"):
                symtab = getattr(self.program, "getSymbolTable", lambda: None)()
                if symtab:
                    try:
                        sym = symtab.getPrimarySymbol(addr)
                        if sym and sym.getName():
                            return sym.getName()
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            refs_from = list(ref_mgr.getReferencesFrom(addr))
        except Exception:
            refs_from = []
        try:
            refs_to = list(ref_mgr.getReferencesTo(addr))
        except Exception:
            refs_to = []
        for ref in refs_from + refs_to:
            try:
                if hasattr(ref, "isExternalReference") and ref.isExternalReference():
                    ext_loc = ref.getExternalLocation()
                    if ext_loc:
                        label = ext_loc.getLabel() or ext_loc.getOriginalImportedName()
                        if label:
                            return label
            except Exception:
                continue
        return None

    def _follow_thunk(self, func):
        try:
            if func and getattr(func, "isThunk", lambda: False)():
                thunk_target = getattr(func, "getThunkedFunction", lambda: None)()
                if thunk_target:
                    return thunk_target
            # Manual thunk resolution: some headless analyses never promote IAT
            # jump stubs to real thunk functions, so inspect the first
            # instruction for a direct/indirect jump to an external target.
            listing = getattr(self.program, "getListing", lambda: None)()
            if listing and func is not None:
                try:
                    inst = listing.getInstructionAt(func.getEntryPoint())
                except Exception:
                    inst = None
                if inst and inst.getMnemonicString().upper().startswith("JMP"):
                    try:
                        flows = list(inst.getFlows())
                    except Exception:
                        flows = []
                    fm = self.program.getFunctionManager()
                    for dest in flows:
                        ext_label = self._external_label_for_address(dest)
                        if ext_label:
                            followed = getattr(fm, "getFunctionAt", lambda a: None)(dest)
                            return followed or func
                        mapped = IMPORTED_REGISTRY_API_ADDRS.get(str(dest)) or IMPORTED_REGISTRY_API_ADDRS.get(dest)
                        if mapped:
                            followed = getattr(fm, "getFunctionAt", lambda a: None)(dest)
                            return followed or func
        except Exception:
            pass
        return func

    def _read_pointer_value(self, addr) -> Optional[int]:
        try:
            mem = self.program.getMemory()
            if mem is None:
                return None
            width_bytes = max(1, DEFAULT_POINTER_BIT_WIDTH // 8)
            buf = bytearray(width_bytes)
            read = mem.getBytes(addr, buf)
            if not isinstance(read, (int, float)) or read <= 0:
                return None
            return int.from_bytes(bytes(buf[: int(read)]), byteorder="little", signed=False)
        except Exception:
            return None

    def _resolve_import_from_pointer(self, ptr_addr) -> Optional[str]:
        if ptr_addr is None:
            return None
        pointee = self._read_pointer_value(ptr_addr)
        if pointee is None:
            return None
        mapped = IMPORTED_REGISTRY_API_ADDRS.get(pointee) or IMPORTED_REGISTRY_API_ADDRS.get(str(pointee))
        if mapped:
            return mapped
        try:
            target_addr = self.api.toAddr(pointee)
        except Exception:
            target_addr = None
        if target_addr:
            mapped = IMPORTED_REGISTRY_API_ADDRS.get(str(target_addr))
            if mapped:
                return mapped
            return self._external_label_for_address(target_addr)
        return None

    def _find_hkey_meta(self, call_args: List[Any], states: Dict[Tuple, AbstractValue]) -> Optional[Dict[str, str]]:
        for arg in call_args[:2]:
            try:
                val = self._get_val(arg, states)
            except Exception:
                val = AbstractValue()
            off = vn_get_offset(arg)
            if off is None:
                for tgt in sorted(val.pointer_targets):
                    if tgt in HKEY_HANDLE_MAP:
                        off = tgt
                        break
            if off is not None and off in HKEY_HANDLE_MAP:
                return HKEY_HANDLE_MAP.get(off)
        return None

    def _derive_registry_fields(
        self, string_args: List[Dict[str, Any]], call_args: List[Any], detected_hkey_meta: Optional[Dict[str, str]]
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Dict[str, Any]]:
        hive = path = value_name = None
        detail_meta: Dict[str, Any] = {"inferred_hive": False, "inference_reason": None}
        hkey_meta = detected_hkey_meta
        if string_args:
            hive = string_args[0].get("hive")
            path = string_args[0].get("path")
            value_name = string_args[0].get("value_name")
            if hive:
                detail_meta["inferred_hive"] = True
                detail_meta["inference_reason"] = detail_meta.get("inference_reason") or "registry_prefix"
            if len(string_args) > 1:
                value_candidate = string_args[1].get("value_name") or string_args[1].get("raw")
                if value_candidate:
                    value_name = value_candidate
        if hkey_meta and not hive:
            hive = hkey_meta.get("hive")
            if hive:
                detail_meta["inferred_hive"] = True
                detail_meta["inference_reason"] = detail_meta.get("inference_reason") or "has_hkey_handle"
        if hkey_meta and path:
            clean = str(path).lstrip("\\/")
            lowered_clean = clean.lower()
            has_prefix = bool(REGISTRY_STRING_PREFIX_RE.match(clean)) or lowered_clean.startswith("registry\\")
            if not has_prefix:
                nt_root = hkey_meta.get("nt_root")
                if nt_root:
                    path = f"{nt_root}\\{clean}"
                    detail_meta["inferred_hive"] = True
                    detail_meta["inference_reason"] = detail_meta.get("inference_reason") or "hkey_path_join"
        return hive, path, value_name, detail_meta

    def _taint_registry_outputs(
        self, func, call_args: List[Any], states: Dict[Tuple, AbstractValue], label: Optional[str], root_id: Optional[str]
    ) -> None:
        if label is None or root_id is None:
            return
        lowered = label.lower()
        buffer_indices: Set[int] = set()
        if "queryvalueex" in lowered:
            buffer_indices.update([3, 4])
        if lowered.startswith("regqueryvalue") and "ex" not in lowered:
            buffer_indices.update([2])
        if "rtlqueryregistryvalues" in lowered:
            buffer_indices.update(range(len(call_args)))
        if "queryvaluekey" in lowered:
            buffer_indices.update([3, 5])
        if not buffer_indices and "query" in lowered and "value" in lowered:
            buffer_indices.update([len(call_args) - 1])
        for idx in sorted(buffer_indices):
            if idx < 0 or idx >= len(call_args):
                continue
            val = self._get_val(call_args[idx], states)
            val.tainted = True
            val.origins.add(root_id)
            base_id = pointer_base_identifier(func, call_args[idx])
            if base_id is not None:
                self._record_base_id_metadata(base_id, call_args[idx])
                self.global_state.root_slot_index[root_id].add((base_id, 0))
            self._set_val(call_args[idx], val, states)

    def _resolve_callee_from_refs(self, inst: Instruction, refs_list) -> Tuple[Optional[str], Optional[Any]]:
        fm = self.program.getFunctionManager()
        for r in refs_list:
            try:
                to_addr = r.getToAddress()
                if to_addr is None:
                    continue
                f = self._follow_thunk(fm.getFunctionAt(to_addr))
                if f is not None:
                    return f.getName(), f
                external_label = self._external_label_for_address(to_addr)
                if external_label:
                    return external_label, fm.getFunctionAt(to_addr)
            except Exception as e:
                if DEBUG_ENABLED:
                    log_debug(f"[debug] error resolving call reference at {inst.getAddress()}: {e!r}")
        return None, None

    def _resolve_callee_from_external_refs(self, inst: Instruction, refs_list) -> Optional[str]:
        for r in refs_list:
            try:
                if hasattr(r, "isExternalReference") and r.isExternalReference():
                    ext_loc = r.getExternalLocation()
                    if ext_loc:
                        label = ext_loc.getLabel() or ext_loc.getOriginalImportedName()
                        if label:
                            return label
            except Exception as e:
                if DEBUG_ENABLED:
                    log_debug(f"[debug] error resolving external reference at {inst.getAddress()}: {e!r}")
        return None

    def _resolve_callee_from_pcode_target(self, target_vn, states: Dict[Tuple, AbstractValue]) -> Tuple[Optional[str], Optional[Any]]:
        fm = self.program.getFunctionManager()
        callee = None
        callee_func = None
        target_addr = None
        try:
            def_op = target_vn.getDef() if target_vn is not None else None
        except Exception:
            def_op = None
        if def_op is not None and def_op.getOpcode() == PcodeOp.LOAD:
            try:
                load_addr_vn = def_op.getInput(1)
            except Exception:
                load_addr_vn = None
            if load_addr_vn and vn_is_constant(load_addr_vn):
                load_offset = vn_get_offset(load_addr_vn)
                if load_offset is not None:
                    try:
                        callee_addr = self.api.toAddr(load_offset)
                    except Exception:
                        callee_addr = None
                    try:
                        sym = getattr(self.api, "getSymbolAt", lambda a: None)(callee_addr)
                    except Exception:
                        sym = None
                    if sym is not None:
                        callee = sym.getName()
                        try:
                            if SourceType is not None and getattr(sym, "getSource", lambda: None)() == SourceType.IMPORTED:
                                ext_loc = sym.getExternalLocation()
                                if ext_loc and ext_loc.getLabel():
                                    callee = ext_loc.getLabel()
                        except Exception:
                            pass
                        try:
                            callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(callee_addr))
                        except Exception:
                            pass
                    if callee is None:
                        mapped = None
                        if callee_addr is not None:
                            mapped = IMPORTED_REGISTRY_API_ADDRS.get(str(callee_addr))
                        if mapped is None and load_offset is not None:
                            try:
                                mapped = IMPORTED_REGISTRY_API_ADDRS.get(int(load_offset))
                            except Exception:
                                mapped = None
                        if mapped:
                            callee = mapped
                            if callee_addr is not None:
                                try:
                                    callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(callee_addr))
                                except Exception:
                                    pass
        if target_vn is not None:
            try:
                if hasattr(target_vn, "getAddress"):
                    target_addr = target_vn.getAddress()
                if target_addr is None and vn_is_constant(target_vn):
                    off = vn_get_offset(target_vn)
                    if off is not None:
                        target_addr = self.api.toAddr(off)
            except Exception:
                target_addr = None
        try:
            val = self._get_val(target_vn, states) if target_vn is not None else AbstractValue()
        except Exception:
            val = AbstractValue()
        if val.function_pointer_labels:
            callee = sorted(val.function_pointer_labels)[0]
        if target_addr is not None:
            func_at_target = self._follow_thunk(fm.getFunctionAt(target_addr))
            if func_at_target:
                callee_func = func_at_target
                if callee is None:
                    callee = func_at_target.getName()
            mapped = IMPORTED_REGISTRY_API_ADDRS.get(str(target_addr))
            if mapped:
                callee = callee or mapped
                try:
                    callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(target_addr))
                except Exception:
                    pass
            if callee is None:
                ext_label = self._external_label_for_address(target_addr)
                if ext_label:
                    callee = ext_label
            if callee is None:
                manual = self._resolve_import_from_pointer(target_addr)
                if manual:
                    callee = manual
        try:
            target = target_vn.getOffset() if target_vn is not None and hasattr(target_vn, "getOffset") else None
        except Exception:
            target = None
        if callee is None and target is not None:
            mapped = IMPORTED_REGISTRY_API_ADDRS.get(int(target))
            if mapped:
                callee = mapped
                try:
                    callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(self.api.toAddr(target)))
                except Exception:
                    pass
            if callee is None:
                try:
                    callee = self._resolve_import_from_pointer(self.api.toAddr(target))
                except Exception:
                    pass
        if callee is None:
            for tgt in sorted(val.pointer_targets):
                mapped = IMPORTED_REGISTRY_API_ADDRS.get(tgt)
                if mapped:
                    callee = mapped
                    try:
                        callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(self.api.toAddr(tgt)))
                    except Exception:
                        pass
                    break
                try:
                    addr_obj = self.api.toAddr(tgt)
                    str_addr = str(addr_obj)
                    mapped = IMPORTED_REGISTRY_API_ADDRS.get(str_addr)
                    if mapped:
                        callee = mapped
                        callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(addr_obj))
                        break
                    ext_label = self._external_label_for_address(addr_obj)
                    if ext_label:
                        callee = ext_label
                        callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(addr_obj))
                        break
                    manual = self._resolve_import_from_pointer(addr_obj)
                    if manual:
                        callee = manual
                        callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(addr_obj))
                        break
                except Exception:
                    continue
        return callee, callee_func

    def _resolve_string_from_vn(self, vn, states: Optional[Dict[Tuple, AbstractValue]] = None) -> Optional[Dict[str, Any]]:
        try:
            addr_candidates: List[Any] = []
            if vn is None:
                return None
            if vn_has_address(vn):
                addr_candidates.append(vn.getAddress())
            elif vn_is_constant(vn):
                off = vn_get_offset(vn)
                if off is not None:
                    addr_candidates.append(self.api.toAddr(off))
            if states is not None:
                val = self._get_val(vn, states)
                for off in sorted(val.pointer_targets):
                    try:
                        addr_candidates.append(self.api.toAddr(off))
                    except Exception:
                        continue
                if val.pointer_pattern and val.pointer_pattern.base_id:
                    heap_bytes = self.global_state.heap_string_writes.get(val.pointer_pattern.base_id)
                    if heap_bytes:
                        collected = bytearray()
                        # Prefer contiguous bytes from the exact offset forward.
                        start = val.pointer_pattern.offset or 0
                        for i in range(0, 256):
                            b = heap_bytes.get(start + i)
                            if b is None:
                                break
                            collected.extend(b)
                            if b == b"\x00":
                                break
                        if collected:
                            meta = parse_registry_string(collected.decode("latin-1", errors="ignore"))
                            if meta:
                                return meta
            for addr in addr_candidates:
                if addr is None:
                    continue
                meta = self._resolve_string_at_address(addr, str(addr))
                if meta:
                    return meta
            return None
        except Exception as e:
            if DEBUG_ENABLED:
                log_debug(f"[debug] error in _resolve_string_from_vn for {vn}: {e!r}")
            return None

    def _decode_string_at_address(self, addr, addr_str: str) -> Optional[Dict[str, Any]]:
        try:
            meta = _decode_registry_string_from_memory(
                self.program,
                addr,
                max_len=512,
                strip_leading_nulls=True,
                stop_after_first=False,
            )
            if meta:
                self.global_state.registry_strings[addr_str] = meta
                return meta
        except Exception as e:
            if DEBUG_ENABLED:
                log_debug(f"[debug] error decoding string at {addr_str}: {e!r}")
            return None
        return None

    def _func_key(self, func) -> str:
        if hasattr(func, "getEntryPoint"):
            try:
                return str(func.getEntryPoint())
            except Exception:
                pass
        return func.getName()

    def analyze_all(self) -> None:
        """Global fixed-point over function summaries.

        The worklist processes functions whose summaries might impact callers or callees.
        ``queued`` only tracks functions currently scheduled (in ``worklist``), so a
        function can be re-enqueued if its summary changes in a later iteration.
        """
        fm = self.program.getFunctionManager()
        worklist = deque()
        queued: Set[str] = set()
        for func in fm.getFunctions(True):
            key = self._func_key(func)
            worklist.append((func, 0))
            queued.add(key)
        iteration_guard = 0
        while worklist and iteration_guard < self.max_function_iterations:
            try:
                if self.monitor and hasattr(self.monitor, "isCancelled") and self.monitor.isCancelled():
                    self.global_state.analysis_stats["cancelled"] = True
                    log_debug("[debug] analysis cancelled by user")
                    break
            except Exception:
                pass
            func, depth = worklist.popleft()
            func_key = self._func_key(func)
            queued.discard(func_key)
            iteration_guard += 1
            if self.max_call_depth is not None and depth > self.max_call_depth:
                self.global_state.analysis_stats["call_depth_limit"] = True
                continue
            summary = self.analyze_function(func)
            self.global_state.analysis_stats["functions_analyzed"] = self.global_state.analysis_stats.get(
                "functions_analyzed", 0
            ) + 1
            existing = self.global_state.function_summaries.get(func.getName())
            if existing is None:
                self.global_state.function_summaries[func.getName()] = summary
                for callee in func.getCalledFunctions(self.monitor):
                    callee_key = self._func_key(callee)
                    if callee_key not in queued:
                        queued.add(callee_key)
                        worklist.append((callee, depth + 1))
            else:
                if existing.merge_from(summary):
                    for callee in func.getCalledFunctions(self.monitor):
                        callee_key = self._func_key(callee)
                        if callee_key not in queued:
                            queued.add(callee_key)
                            worklist.append((callee, depth + 1))
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
        blocks = list(self.block_model.getCodeBlocksContaining(body, self.monitor))
        preds: Dict[Any, List[Any]] = defaultdict(list)
        succs: Dict[Any, List[Any]] = defaultdict(list)
        for blk in blocks:
            it = blk.getDestinations(self.monitor)
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
            try:
                if self.monitor and hasattr(self.monitor, "checkCanceled"):
                    self.monitor.checkCanceled()
            except Exception:
                pass
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
        for inst in listing.getInstructions(addr_set, True):
            try:
                if self.monitor and hasattr(self.monitor, "isCancelled") and self.monitor.isCancelled():
                    self.global_state.analysis_stats["cancelled"] = True
                    log_debug("[debug] instruction traversal cancelled by user")
                    break
            except Exception:
                pass
            try:
                pcode_ops = list(inst.getPcodeOps())
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
            self._handle_orxor(out, inputs, states, opname)
        elif opname in {"INT_LEFT", "INT_RIGHT", "INT_SRIGHT"}:
            self._handle_shift(out, inputs, states, opname)
        elif opname == "LOAD":
            self._handle_load(out, inputs, states)
        elif opname == "STORE":
            self._handle_store(inst, inputs, states)
        elif opname == "PTRADD":
            self._handle_ptradd(func, out, inputs, states)
        elif opname == "PTRSUB":
            self._handle_ptrsub(func, out, inputs, states)
        elif opname in {
            "INT_EQUAL",
            "INT_NOTEQUAL",
            "INT_LESS",
            "INT_LESSEQUAL",
            "INT_SLESS",
            "INT_SLESSEQUAL",
            "INT_CARRY",
            "INT_SCARRY",
            "INT_SBORROW",
        }:
            self._handle_compare(out, inputs, states)
        elif opname == "CBRANCH":  # unconditional BRANCH has no condition operand
            self._handle_branch(func, inst, opname, inputs, states, summary)
        elif opname == "MULTIEQUAL":
            self._handle_multiequal(out, inputs, states)
        elif opname == "INDIRECT":
            self._handle_indirect(out, inputs, states)
        elif opname in {"CALL", "CALLIND"}:
            # Treat both direct (CALL) and indirect (CALLIND) calls as call sites.
            # For CALLIND, callee_name may be None, but we still seed roots based
            # on registry-like string arguments.
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
        val.slot_sources = set(a.slot_sources | b.slot_sources)
        val.bit_width = out.getSize() * 8
        val.definitely_used_bits = _definitely_bits(a) | _definitely_bits(b)
        val.maybe_used_bits = _maybe_bits(a) | _maybe_bits(b) | set(val.definitely_used_bits)
        val.used_bits = set(val.definitely_used_bits)
        val.candidate_bits = set(val.maybe_used_bits)
        val.pointer_targets = set(a.pointer_targets | b.pointer_targets)
        if a.pointer_pattern and vn_is_constant(inputs[1]):
            pp = a.pointer_pattern.clone()
            delta = vn_get_offset(inputs[1]) or 0
            pp.adjust_offset(delta if opname == "INT_ADD" else -delta)
            val.pointer_pattern = pp
            if a.pointer_targets:
                adj = vn_get_offset(inputs[1]) or 0
                val.pointer_targets = {p + (adj if opname == "INT_ADD" else -adj) for p in a.pointer_targets}
        elif b.pointer_pattern and vn_is_constant(inputs[0]):
            pp = b.pointer_pattern.clone()
            delta = vn_get_offset(inputs[0]) or 0
            pp.adjust_offset(delta if opname == "INT_ADD" else -delta)
            val.pointer_pattern = pp
            if b.pointer_targets:
                adj = vn_get_offset(inputs[0]) or 0
                val.pointer_targets = {p + (adj if opname == "INT_ADD" else -adj) for p in b.pointer_targets}
        elif a.pointer_pattern and b.pointer_pattern:
            val.pointer_pattern = a.pointer_pattern.merge(b.pointer_pattern)
        if not val.pointer_pattern:
            if vn_is_constant(inputs[1]) and a.pointer_targets:
                adj = vn_get_offset(inputs[1]) or 0
                val.pointer_targets = {p + (adj if opname == "INT_ADD" else -adj) for p in a.pointer_targets}
            elif vn_is_constant(inputs[0]) and b.pointer_targets:
                adj = vn_get_offset(inputs[0]) or 0
                val.pointer_targets = {p + (adj if opname == "INT_ADD" else -adj) for p in b.pointer_targets}
        self._set_val(out, val, states)

    def _handle_multdiv(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.slot_sources = set(a.slot_sources | b.slot_sources)
        val.bit_width = out.getSize() * 8
        val.definitely_used_bits = _definitely_bits(a) | _definitely_bits(b)
        val.maybe_used_bits = _maybe_bits(a) | _maybe_bits(b) | set(val.definitely_used_bits)
        val.used_bits = set(val.definitely_used_bits)
        val.candidate_bits = set(val.maybe_used_bits)
        val.pointer_pattern = PointerPattern(unknown=True) if (a.pointer_pattern or b.pointer_pattern) else None
        val.pointer_targets = set()
        self._set_val(out, val, states)

    def _handle_and(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.slot_sources = set(a.slot_sources | b.slot_sources)
        val.bit_width = out.getSize() * 8
        val.definitely_used_bits = _definitely_bits(a) | _definitely_bits(b)
        val.maybe_used_bits = _maybe_bits(a) | _maybe_bits(b) | set(val.definitely_used_bits)
        val.used_bits = set(val.definitely_used_bits)
        val.candidate_bits = set(val.maybe_used_bits)
        val.pointer_targets = set(a.pointer_targets | b.pointer_targets)
        mask_src = None
        other = None
        if vn_is_constant(inputs[0]):
            mask_src = inputs[0]
            other = b
        elif vn_is_constant(inputs[1]):
            mask_src = inputs[1]
            other = a
        if mask_src is not None and other is not None:
            mask_val = vn_get_offset(mask_src) or 0
            full_mask = (1 << val.bit_width) - 1
            clean_mask = mask_val & full_mask
            mask_bits = _mask_to_bits(clean_mask, val.bit_width)
            other_def = _definitely_bits(other) & mask_bits
            other_maybe = _maybe_bits(other) & mask_bits if _maybe_bits(other) else set(mask_bits)
            if not other_def and mask_bits:
                other_def = set(mask_bits)
            val.definitely_used_bits |= other_def
            val.maybe_used_bits |= other_maybe | other_def | mask_bits
            val.used_bits = set(val.definitely_used_bits)
            val.candidate_bits = set(val.maybe_used_bits)
            val.forbidden_bits |= set(range(val.bit_width)) - set(mask_bits)
            val.mask_history.append({"op": "and", "mask": clean_mask})
        self._set_val(out, val, states)

    def _handle_orxor(self, out, inputs, states, opname):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.slot_sources = set(a.slot_sources | b.slot_sources)
        val.bit_width = out.getSize() * 8
        val.definitely_used_bits = _definitely_bits(a) | _definitely_bits(b)
        val.maybe_used_bits = _maybe_bits(a) | _maybe_bits(b) | set(val.definitely_used_bits)
        val.used_bits = set(val.definitely_used_bits)
        val.candidate_bits = set(val.maybe_used_bits)
        val.pointer_targets = set(a.pointer_targets | b.pointer_targets)
        mask_src = None
        if vn_is_constant(inputs[0]):
            mask_src = inputs[0]
        elif vn_is_constant(inputs[1]):
            mask_src = inputs[1]
        if mask_src is not None:
            mask_val = vn_get_offset(mask_src) or 0
            mask_bits = _mask_to_bits(mask_val, val.bit_width)
            val.maybe_used_bits |= mask_bits
            val.candidate_bits |= mask_bits
            val.mask_history.append({"op": opname.lower() if opname else "orxor", "mask": mask_val})
        self._set_val(out, val, states)

    def _handle_shift(self, out, inputs, states, opname):
        if out is None or len(inputs) < 2:
            return
        base = self._get_val(inputs[0], states)
        amt = inputs[1]
        val = AbstractValue()
        val.tainted = base.tainted or self._get_val(amt, states).tainted
        val.origins = set(base.origins | self._get_val(amt, states).origins)
        val.slot_sources = set(base.slot_sources | self._get_val(amt, states).slot_sources)
        val.bit_width = out.getSize() * 8
        val.pointer_targets = set(base.pointer_targets)
        val.mask_history = list(base.mask_history)
        val.forbidden_bits = set(base.forbidden_bits)
        shift = vn_get_offset(amt)
        if shift is None:
            fallback_bits = _fallback_bits_from_value(base)
            val.definitely_used_bits = set(_definitely_bits(base))
            val.maybe_used_bits = set(fallback_bits) | set(val.definitely_used_bits)
            val.candidate_bits = set(val.maybe_used_bits)
            val.used_bits = set(val.definitely_used_bits)
            val.bit_usage_degraded = True
            self.global_state.analysis_stats["bit_precision_degraded"] = True
        else:
            base_def = _definitely_bits(base) or set()
            base_maybe = _maybe_bits(base) or set(range(base.bit_width))
            shifted_def: Set[int] = set()
            shifted_maybe: Set[int] = set()
            for b in base_def:
                if opname == "INT_LEFT":
                    shifted_def.add(min(val.bit_width - 1, b + shift))
                else:
                    shifted_def.add(max(0, b - shift))
            for b in base_maybe:
                if opname == "INT_LEFT":
                    shifted_maybe.add(min(val.bit_width - 1, b + shift))
                else:
                    shifted_maybe.add(max(0, b - shift))
            val.definitely_used_bits = shifted_def
            val.maybe_used_bits = shifted_maybe | shifted_def
            val.used_bits = set(val.definitely_used_bits)
            val.candidate_bits = set(val.maybe_used_bits)
            if shift != 0:
                val.pointer_targets = set()
            val.mask_history.append({"op": "shift", "direction": opname.lower(), "amount": shift})
        self._set_val(out, val, states)

    def _handle_compare(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue(bit_width=out.getSize() * 8)
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.slot_sources = set(a.slot_sources | b.slot_sources)
        def_bits_a = _definitely_bits(a)
        def_bits_b = _definitely_bits(b)
        maybe_bits_a = _maybe_bits(a) or set(range(a.bit_width))
        maybe_bits_b = _maybe_bits(b) or set(range(b.bit_width))
        const_side = None
        const_val = None
        compare_meta: Dict[str, Any] = {}
        op_tag = opcode_name(out.getDef()) if hasattr(out, "getDef") else None
        if op_tag:
            compare_meta["compare_op"] = op_tag.lower()
        if vn_is_constant(inputs[0]):
            const_side = "left"
            const_val = vn_get_offset(inputs[0]) or 0
        elif vn_is_constant(inputs[1]):
            const_side = "right"
            const_val = vn_get_offset(inputs[1]) or 0
        if op_tag in {"INT_EQUAL", "INT_NOTEQUAL"}:
            compare_meta["compare_kind"] = "eq" if op_tag == "INT_EQUAL" else "neq"
            if const_side and const_val is not None:
                var_val = b if const_side == "left" else a
                var_maybe = _maybe_bits(var_val) or set(range(var_val.bit_width))
                mask_bits = _bits_from_mask_history(var_val)
                highest_bit = max(0, int(const_val).bit_length() - 1)
                mask_bits |= set(range(0, min(var_val.bit_width, max(1, highest_bit + 1))))
                if var_maybe:
                    mask_bits &= set(var_maybe) or mask_bits
                if not mask_bits:
                    mask_bits = set(var_maybe or {0})
                val.definitely_used_bits = set(mask_bits & _definitely_bits(var_val))
                val.maybe_used_bits = set(mask_bits | val.definitely_used_bits)
                compare_meta["constant_side"] = const_side
                compare_meta["constant_value"] = const_val
                compare_meta["constant_mask_bits"] = sorted(mask_bits)
            else:
                val.definitely_used_bits = def_bits_a | def_bits_b
                val.maybe_used_bits = maybe_bits_a | maybe_bits_b | val.definitely_used_bits
        elif op_tag in {
            "INT_LESS",
            "INT_LESSEQUAL",
            "INT_SLESS",
            "INT_SLESSEQUAL",
        }:
            compare_meta["compare_kind"] = op_tag.lower()
            sign_sensitive = op_tag in {"INT_SLESS", "INT_SLESSEQUAL"}
            if sign_sensitive:
                try:
                    sign_bit = max(a.bit_width, b.bit_width, 1) - 1
                except Exception:
                    sign_bit = max(a.bit_width, b.bit_width) - 1 if a.bit_width or b.bit_width else 0
                compare_meta["sign_sensitive"] = True
                compare_meta["sign_bit"] = sign_bit
            if const_side and const_val is not None:
                var_val = b if const_side == "left" else a
                var_maybe = _maybe_bits(var_val) or set(range(var_val.bit_width))
                max_bit = max(0, int(const_val).bit_length() - 1)
                if sign_sensitive and var_val.bit_width:
                    sign_bit = var_val.bit_width - 1
                    val.definitely_used_bits.add(sign_bit)
                    max_bit = max(max_bit, sign_bit)
                bit_range = (0, min(max_bit, var_val.bit_width - 1))
                approx_bits = set(range(bit_range[0], bit_range[1] + 1))
                approx_bits &= set(var_maybe) or approx_bits
                if not approx_bits and var_maybe:
                    approx_bits = set(var_maybe)
                val.maybe_used_bits |= approx_bits
                val.definitely_used_bits |= _definitely_bits(var_val) & approx_bits
                compare_meta["constant_side"] = const_side
                compare_meta["constant_value"] = const_val
                compare_meta["approx_bit_range"] = [bit_range[0], bit_range[1]]
            else:
                val.definitely_used_bits = def_bits_a | def_bits_b
                val.maybe_used_bits = maybe_bits_a | maybe_bits_b | val.definitely_used_bits
        else:
            val.definitely_used_bits = def_bits_a | def_bits_b
            val.maybe_used_bits = maybe_bits_a | maybe_bits_b | val.definitely_used_bits
        val.used_bits = set(val.definitely_used_bits)
        val.candidate_bits = set(val.maybe_used_bits)
        if compare_meta:
            val.compare_details = compare_meta
        self._set_val(out, val, states)

    def _handle_load(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        addr_val = self._get_val(inputs[1], states)
        val = AbstractValue(bit_width=out.getSize() * 8)
        key = slot_key_from_pattern(addr_val.pointer_pattern)
        if key:
            slot = self.global_state.struct_slots.get(key)
            if slot:
                val = slot.value.clone()
                val.slot_sources.add(key)
        self._set_val(out, val, states)

    def _handle_store(self, inst, inputs, states):
        if len(inputs) < 3:
            return
        addr_val = self._get_val(inputs[1], states)
        src_val = self._get_val(inputs[2], states)
        old_value = None
        key = slot_key_from_pattern(addr_val.pointer_pattern)
        if key:
            slot = self.global_state.struct_slots.get(key)
            if slot is None:
                slot = StructSlot(
                    addr_val.pointer_pattern.base_id,
                    key[1],
                    addr_val.pointer_pattern.stride,
                    addr_val.pointer_pattern.index_var,
                    value=src_val.clone(),
                )
                self.global_state.struct_slots[key] = slot
            else:
                old_value = slot.value.clone()
                slot.value = old_value.merge(src_val)
            slot.value.slot_sources.add(key)
            inst_func = self._get_function_for_inst(inst)
            func_name = inst_func.getName() if inst_func else "unknown"
            if inst_func is not None:
                entry_str = str(inst_func.getEntryPoint())
            else:
                entry_str = str(inst.getAddress())
            self.global_state.function_summaries.setdefault(
                func_name, FunctionSummary(func_name, entry_str)
            ).slot_writes.append(
                {
                    "base_id": slot.base_id,
                    "offset": slot.offset,
                    "origins": sorted(slot.value.origins),
                }
            )
            for origin in slot.value.origins:
                self.global_state.root_slot_index[origin].add(key)
            if old_value is not None and old_value.tainted and not src_val.tainted:
                override_entry = {
                    "address": str(inst.getAddress()),
                    "function": func_name,
                    "source_origins": sorted(old_value.origins),
                    "notes": "struct slot override",
                }
                self.global_state.overrides.append(override_entry)
                for origin in old_value.origins:
                    self.global_state.root_override_index[origin].append(override_entry)
        # Reconstruct heap/stack string fragments from MOV/STORE sequences.
        if addr_val.pointer_pattern and addr_val.pointer_pattern.base_id and vn_is_constant(inputs[2]):
            try:
                const_val = vn_get_offset(inputs[2]) or 0
                width = inputs[2].getSize()
                bytes_le = const_val.to_bytes(width, byteorder="little", signed=False)
                for idx, b in enumerate(bytes_le):
                    offset = (addr_val.pointer_pattern.offset or 0) + idx
                    self.global_state.heap_string_writes[addr_val.pointer_pattern.base_id][offset] = bytes([b])
            except Exception:
                pass

    def _handle_ptradd(self, func, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        base = self._get_val(inputs[0], states)
        offset = inputs[1]
        val = base.clone()
        val.bit_width = out.getSize() * 8
        if val.pointer_pattern is None:
            base_id = pointer_base_identifier(func, inputs[0])
            val.pointer_pattern = PointerPattern(base_id=base_id)
            self._record_base_id_metadata(base_id, inputs[0])
        if vn_is_constant(offset):
            val.pointer_pattern.adjust_offset(vn_get_offset(offset) or 0)
        else:
            val.pointer_pattern.index_var = varnode_key(offset) if offset is not None else None
            val.pointer_pattern.unknown = True
        if vn_is_constant(offset) and val.pointer_targets:
            delta = vn_get_offset(offset) or 0
            val.pointer_targets = {p + delta for p in val.pointer_targets}
        self._set_val(out, val, states)

    def _handle_ptrsub(self, func, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        base = self._get_val(inputs[0], states)
        offset = inputs[1]
        val = base.clone()
        val.bit_width = out.getSize() * 8
        if val.pointer_pattern is None:
            base_id = pointer_base_identifier(func, inputs[0])
            val.pointer_pattern = PointerPattern(base_id=base_id)
            self._record_base_id_metadata(base_id, inputs[0])
        if vn_is_constant(offset):
            delta = vn_get_offset(offset) or 0
            val.pointer_pattern.adjust_offset(-delta)
            if val.pointer_targets:
                val.pointer_targets = {p - delta for p in val.pointer_targets}
        else:
            val.pointer_pattern.index_var = varnode_key(offset) if offset is not None else None
            val.pointer_pattern.unknown = True
            val.pointer_targets = set()
        self._set_val(out, val, states)

    def _handle_branch(self, func, inst, opname, inputs, states, summary: FunctionSummary):
        if opname != "CBRANCH" or not inputs:
            return
        cond_val = self._get_val(inputs[0], states)
        if self.mode == "taint" and not cond_val.origins:
            log_trace(f"[trace] skipping untainted branch at {inst.getAddress()}")
            return
        branch_detail = {"type": "branch"}
        used_bits = set(_definitely_bits(cond_val))
        maybe_bits = set(_maybe_bits(cond_val))
        if not used_bits and maybe_bits:
            used_bits = set(maybe_bits)
        if not used_bits and not maybe_bits:
            history_bits = _bits_from_mask_history(cond_val)
            if history_bits:
                used_bits = set(history_bits)
                cond_val.definitely_used_bits |= used_bits
                cond_val.maybe_used_bits |= used_bits
                cond_val.candidate_bits |= used_bits
            fallback_bits = _fallback_bits_from_value(cond_val)
            if fallback_bits:
                used_bits = set(fallback_bits)
                branch_detail["bit_heuristic"] = "fallback_bits_from_history"
                cond_val.used_bits |= set(used_bits)
                cond_val.maybe_used_bits |= set(used_bits)
                cond_val.candidate_bits |= set(used_bits)
                cond_val.bit_usage_degraded = True
            else:
                self._mark_all_bits_used_degraded(cond_val)
                used_bits = set(cond_val.used_bits)
                branch_detail["bit_heuristic"] = "all_bits_fallback"
                if DEBUG_ENABLED:
                    log_debug(f"[debug] heuristic bit usage applied at {inst.getAddress()} (all bits fallback)")
        if cond_val.bit_usage_degraded:
            self.global_state.analysis_stats["bit_precision_degraded"] = True
        if cond_val.compare_details:
            branch_detail.update(cond_val.compare_details)
        if cond_val.origins or cond_val.slot_sources:
            summary.uses_registry = summary.uses_registry or bool(cond_val.origins)
        decision = Decision(
            address=str(inst.getAddress()),
            mnemonic=inst.getMnemonicString(),
            disasm=inst.toString(),
            origins=set(cond_val.origins),
            used_bits=set(used_bits),
            details=branch_detail,
        )
        decision.details["branch_kind"] = "conditional"
        if cond_val.slot_sources:
            decision.details["slots"] = [
                {"base_id": base, "offset": offset} for base, offset in sorted(cond_val.slot_sources)
            ]
        summary.add_decision(decision)
        self.global_state.decisions.append(decision)
        for origin in decision.origins:
            self.global_state.root_decision_index[origin].append(decision)

    def _handle_multiequal(self, out, inputs, states):
        if out is None:
            return
        merged = None
        def_intersection: Optional[Set[int]] = None
        maybe_union: Set[int] = set()
        for inp in inputs:
            val = self._get_val(inp, states)
            if merged is None:
                merged = val.clone()
            else:
                merged = merged.merge(val)
            def_bits = _definitely_bits(val)
            maybe_bits = _maybe_bits(val)
            if def_intersection is None:
                def_intersection = set(def_bits)
            else:
                def_intersection &= set(def_bits)
            maybe_union |= set(maybe_bits) | set(def_bits)
        if merged is None:
            merged = AbstractValue()
        merged.bit_width = out.getSize() * 8
        merged.definitely_used_bits = def_intersection or set()
        merged.maybe_used_bits = maybe_union | merged.definitely_used_bits
        merged.used_bits = set(merged.definitely_used_bits)
        merged.candidate_bits = set(merged.maybe_used_bits)
        self._set_val(out, merged, states)

    def _handle_indirect(self, out, inputs, states):
        if out is None or not inputs:
            return
        val = AbstractValue(bit_width=out.getSize() * 8)
        for inp in inputs:
            val = val.merge(self._get_val(inp, states))
        self._set_val(out, val, states)

    def _handle_call(self, func, inst, op: PcodeOp, inputs, states, summary: FunctionSummary):
        string_seeds_enabled = args.get("enable_string_seeds", True)
        indirect_roots_enabled = args.get("enable_indirect_roots", True)
        call_args = inputs[1:] if inputs else []
        string_args: List[Dict[str, Any]] = []
        for inp in call_args:
            meta = self._resolve_string_from_vn(inp, states)
            if meta:
                string_args.append(meta)
        uses_registry_strings = self._function_uses_registry_strings(func)
        detected_hkey_meta: Optional[Dict[str, str]] = self._find_hkey_meta(call_args, states)

        def _pointerish_argument(vn, val: AbstractValue) -> bool:
            try:
                if vn is None:
                    return False
                if val.pointer_targets or val.pointer_pattern or val.function_pointer_labels:
                    return True
                if vn_has_address(vn):
                    return True
                if not vn_is_constant(vn) and vn.getSize() * 8 >= DEFAULT_POINTER_BIT_WIDTH:
                    return True
            except Exception as e:
                if DEBUG_ENABLED:
                    log_debug(f"[debug] error checking pointer-like argument at {inst.getAddress()}: {e!r}")
            return False

        def _seed_root(
            root_id: str,
            api_label: str,
            entry_point: Optional[str],
            api_kind: Optional[str] = None,
            indirect_reason: Optional[str] = None,
        ) -> None:
            summary.uses_registry = True
            hive, path, value_name, derivation_meta = self._derive_registry_fields(
                string_args, call_args, detected_hkey_meta
            )
            if path is None:
                path = f"unknown_path_{inst.getAddress()}"
            root_meta = self.global_state.roots.setdefault(
                root_id,
                {
                    "id": root_id,
                    "type": "registry",
                    "api_name": normalize_registry_label(api_label) or api_label,
                    "api_kind": api_kind,
                    "address": str(inst.getAddress()),
                    "entry": entry_point,
                    "hive": hive,
                    "path": path,
                    "value_name": value_name,
                    "indirect_reason": indirect_reason,
                },
            )
            analysis_meta = root_meta.setdefault("analysis_meta", {})
            if derivation_meta:
                analysis_meta.update(derivation_meta)
            if indirect_reason:
                analysis_meta.setdefault("indirect_reason", indirect_reason)
            if entry_point and not root_meta.get("entry"):
                root_meta["entry"] = entry_point
            if hive and not root_meta.get("hive"):
                root_meta["hive"] = hive
            if path and not root_meta.get("path"):
                root_meta["path"] = path
            if value_name and not root_meta.get("value_name"):
                root_meta["value_name"] = value_name
            if api_kind and not root_meta.get("api_kind"):
                root_meta["api_kind"] = api_kind
            if indirect_reason and not root_meta.get("indirect_reason"):
                root_meta["indirect_reason"] = indirect_reason
            if op.getOutput() is not None:
                val = self._get_val(op.getOutput(), states)
                val.tainted = True
                val.origins.add(root_id)
                val.bit_width = op.getOutput().getSize() * 8
                self._set_val(op.getOutput(), val, states)
            for arg in call_args:
                arg_val = self._get_val(arg, states)
                if _pointerish_argument(arg, arg_val):
                    arg_val.tainted = True
                    arg_val.origins.add(root_id)
                    base_id = pointer_base_identifier(func, arg)
                    if base_id:
                        self._record_base_id_metadata(base_id, arg)
                    self._set_val(arg, arg_val, states)
        pointer_like_args: List[Any] = []
        for idx, inp in enumerate(call_args):
            arg_val = self._get_val(inp, states)
            if arg_val.origins:
                summary.param_influence[idx] |= set(arg_val.origins)
                summary.uses_registry = summary.uses_registry or bool(arg_val.origins)
            if _pointerish_argument(inp, arg_val):
                pointer_like_args.append(inp)
        string_has_registry_prefix = any(
            REGISTRY_STRING_PREFIX_RE.search(meta.get("raw") or meta.get("path") or "") for meta in string_args
        )
        hkey_handle_present = detected_hkey_meta is not None

        # Be liberal: for imported functions the reference type may not report
        # isCall(), so scan all refs and ask FunctionManager if the target is
        # a function. This works better for IAT/thunks on PE files.
        refs = []
        try:
            ref_mgr = self.program.getReferenceManager()
            refs = list(ref_mgr.getReferencesFrom(inst.getAddress())) if ref_mgr else []
        except Exception:
            refs = []

        callee_name, callee_func = self._resolve_callee_from_refs(inst, refs)
        if callee_name is None:
            callee_name = self._resolve_callee_from_external_refs(inst, refs)
        if callee_name is None and inputs:
            alt_name, alt_func = self._resolve_callee_from_pcode_target(inputs[0], states)
            callee_name = alt_name
            callee_func = callee_func or alt_func
        if callee_name is None:
            try:
                ref_mgr = self.program.getReferenceManager()
                ref_candidates = list(ref_mgr.getReferencesFrom(inst.getAddress())) if ref_mgr else []
            except Exception:
                ref_candidates = []
            fm = self.program.getFunctionManager()
            for ref in ref_candidates:
                try:
                    to_addr = ref.getToAddress()
                    offset = to_addr.getOffset() if to_addr else None
                    if offset in IMPORTED_REGISTRY_API_ADDRS:
                        callee_name = IMPORTED_REGISTRY_API_ADDRS.get(offset)
                    elif str(offset) in IMPORTED_REGISTRY_API_ADDRS:
                        callee_name = IMPORTED_REGISTRY_API_ADDRS.get(str(offset))
                    elif to_addr and str(to_addr) in IMPORTED_REGISTRY_API_ADDRS:
                        callee_name = IMPORTED_REGISTRY_API_ADDRS.get(str(to_addr))
                    if callee_name is None:
                        callee_name = self._resolve_import_from_pointer(to_addr)
                    if callee_name:
                        try:
                            callee_func = callee_func or self._follow_thunk(fm.getFunctionAt(to_addr))
                        except Exception:
                            pass
                        if DEBUG_ENABLED:
                            log_debug(
                                f"[debug] fallback resolved registry callee from EXTERNAL import: {callee_name} at {inst.getAddress()}"
                            )
                        break
                except Exception as e:
                    if DEBUG_ENABLED:
                        log_debug(f"[debug] error during fallback external resolution at {inst.getAddress()}: {e!r}")

        if callee_name is None and inputs:
            try:
                ptr_addr = inputs[0].getAddress() if hasattr(inputs[0], "getAddress") else None
            except Exception:
                ptr_addr = None
            if ptr_addr is None and vn_is_constant(inputs[0]):
                try:
                    off = vn_get_offset(inputs[0])
                    ptr_addr = self.api.toAddr(off) if off is not None else None
                except Exception:
                    ptr_addr = None
            manual = self._resolve_import_from_pointer(ptr_addr) if ptr_addr is not None else None
            if manual:
                callee_name = manual

        if DEBUG_ENABLED:
            log_debug(
                f"[debug] call at {inst.getAddress()} opname={opcode_name(op)} "
                f"callee_name={callee_name!r} refs={len(refs)} "
                f"strings={string_args} hkey_meta={detected_hkey_meta}"
            )
        normalized_api_label = normalize_registry_label(callee_name) if callee_name else None
        label_fragment = normalized_api_label or callee_name or "<indirect>"
        safe_label = re.sub(r"[^A-Za-z0-9_]+", "_", label_fragment)
        if normalized_api_label == "getprocaddress" and op.getOutput() is not None:
            try:
                out_val = self._get_val(op.getOutput(), states)
                if string_args:
                    target = string_args[-1].get("raw") or string_args[-1].get("path")
                    norm_target = normalize_registry_label(target)
                    if norm_target:
                        out_val.function_pointer_labels.add(norm_target)
                self._set_val(op.getOutput(), out_val, states)
            except Exception:
                pass
        if callee_name:
            callee_summary = self.global_state.function_summaries.get(callee_name)
            if callee_summary:
                for idx, roots in callee_summary.param_influence.items():
                    if idx < len(call_args):
                        val = self._get_val(call_args[idx], states)
                        summary.param_influence[idx] |= set(roots)
                        val.origins |= roots
                        val.tainted = val.tainted or bool(roots)
                        summary.uses_registry = summary.uses_registry or bool(roots)
                if callee_summary.return_influence and op.getOutput() is not None:
                    val = AbstractValue(
                        tainted=True,
                        origins=set(callee_summary.return_influence),
                        bit_width=op.getOutput().getSize() * 8,
                    )
                    self._set_val(op.getOutput(), val, states)
                    summary.uses_registry = summary.uses_registry or bool(val.origins)
                for slot in callee_summary.slot_writes:
                    key = (slot.get("base_id"), slot.get("offset"))
                    slot_val = self.global_state.struct_slots.get(key)
                    if slot_val:
                        slot_val.value.origins |= set(slot.get("origins", []))
                        for origin in slot_val.value.origins:
                            self.global_state.root_slot_index[origin].add(key)
                    else:
                        origins = set(slot.get("origins", []))
                        if key[0] is not None and key[1] is not None:
                            self.global_state.struct_slots[key] = StructSlot(
                                key[0], key[1], value=AbstractValue(origins=origins, tainted=bool(origins))
                            )
                            for origin in origins:
                                self.global_state.root_slot_index[origin].add(key)
                    if slot.get("origins"):
                        summary.uses_registry = True
                if callee_summary.registry_decision_roots:
                    summary.uses_registry = True
                    summary.registry_decision_roots |= set(callee_summary.registry_decision_roots)
            api_label = normalized_api_label or callee_name
            api_kind = classify_registry_api_kind(api_label)
            callee_is_registry = is_registry_api(callee_name)
            wrapper_registry = callee_summary.uses_registry if callee_summary else False
            registry_like = callee_is_registry or wrapper_registry
            summary.uses_registry = summary.uses_registry or registry_like
            if callee_is_registry:
                if func is not None:
                    try:
                        self._functions_with_registry_calls.add(func.getName())
                    except Exception:
                        pass
                root_id = f"api_{safe_label}_{inst.getAddress()}"
                entry_point = str(callee_func.getEntryPoint()) if callee_func else str(inst.getAddress())
                _seed_root(root_id, api_label, entry_point, api_kind=api_kind)
                self._taint_registry_outputs(func, call_args, states, api_label, root_id)
                if DEBUG_ENABLED:
                    log_debug(
                        f"[debug] registry root seeded: id={root_id} api={api_label} at={inst.getAddress()} entry={entry_point}"
                    )
            elif wrapper_registry and indirect_roots_enabled:
                root_id = f"wrapper_{safe_label}_{inst.getAddress()}"
                entry_point = str(callee_func.getEntryPoint()) if callee_func else str(inst.getAddress())
                _seed_root(root_id, api_label, entry_point, api_kind=api_kind, indirect_reason="registry_wrapper")
                if DEBUG_ENABLED:
                    log_debug(
                        f"[debug] wrapper-based registry root seeded: id={root_id} api={api_label} at={inst.getAddress()}"
                    )
            if not callee_is_registry and string_seeds_enabled:
                if string_args or uses_registry_strings or detected_hkey_meta:
                    root_id = f"string_seed_{inst.getAddress()}_{safe_label}"
                    entry_point = str(callee_func.getEntryPoint()) if callee_func else str(inst.getAddress())
                    _seed_root(
                        root_id=root_id,
                        api_label=label_fragment or "<string_seed>",
                        entry_point=entry_point,
                        api_kind="string_seed",
                        indirect_reason="string_only",
                    )
                    self._taint_registry_outputs(func, call_args, states, label_fragment, root_id)
            if string_args and string_seeds_enabled and indirect_roots_enabled:
                indirect_reason = None
                if string_has_registry_prefix:
                    indirect_reason = "string_prefix"
                elif hkey_handle_present:
                    indirect_reason = "hkey_handle"
                elif registry_like:
                    indirect_reason = "registry_wrapper"
                elif self._pointer_args_from_registry(pointer_like_args, states):
                    indirect_reason = "registry_string_in_function"
                if indirect_reason:
                    root_id = f"indirect_{inst.getAddress()}"
                    entry_point = str(callee_func.getEntryPoint()) if callee_func else str(inst.getAddress())
                    _seed_root(root_id, api_label or "<indirect>", entry_point, api_kind=api_kind, indirect_reason=indirect_reason)
                    if DEBUG_ENABLED:
                        log_debug(
                            f"[debug] string-based root seeded: id={root_id} hive={self.global_state.roots[root_id].get('hive')} "
                            f"path={self.global_state.roots[root_id].get('path')} value={self.global_state.roots[root_id].get('value_name')} "
                            f"at={inst.getAddress()} reason={indirect_reason}"
                        )
        else:
            string_seed_allowed = string_seeds_enabled and (
                string_has_registry_prefix
                or self._function_has_registry_calls(func)
                or self._pointer_args_from_registry(pointer_like_args, states)
                or hkey_handle_present
            )
            if string_args and indirect_roots_enabled and string_seed_allowed:
                indirect_reason = "string_prefix" if string_has_registry_prefix else "registry_string_in_function"
                if hkey_handle_present and indirect_reason != "string_prefix":
                    indirect_reason = "hkey_handle"
                root_id = f"indirect_{inst.getAddress()}"
                _seed_root(root_id, "<indirect>", str(inst.getAddress()), indirect_reason=indirect_reason)
                if DEBUG_ENABLED:
                    log_debug(
                        f"[debug] string-based root seeded: id={root_id} hive={self.global_state.roots[root_id].get('hive')} "
                        f"path={self.global_state.roots[root_id].get('path')} value={self.global_state.roots[root_id].get('value_name')} "
                        f"at={inst.getAddress()} reason={indirect_reason}"
                    )
            elif (
                string_seeds_enabled
                and indirect_roots_enabled
                and uses_registry_strings
                and pointer_like_args
                and string_seed_allowed
            ):
                caller_name = func.getName() if func else "<unknown>"
                api_label = f"<string_seed:{caller_name}>"
                root_id = f"string_seed_{inst.getAddress()}"
                _seed_root(root_id, api_label, str(inst.getAddress()), api_kind="open_key", indirect_reason="registry_string_in_function")
                if DEBUG_ENABLED:
                    log_debug(
                        f"[debug] string-based root seeded: id={root_id} hive={self.global_state.roots[root_id].get('hive')} "
                        f"path={self.global_state.roots[root_id].get('path')} value={self.global_state.roots[root_id].get('value_name')} "
                        f"at={inst.getAddress()} reason=registry_string_in_function"
                    )
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
        ret_source = None
        for vn in reversed(inputs):
            if vn is None:
                continue
            if vn_is_constant(vn):
                continue
            try:
                if hasattr(vn, "isAddress") and vn.isAddress():
                    continue
            except Exception:
                pass
            ret_source = vn
            break
        if ret_source is None:
            ret_source = inputs[-1]
        ret_val = self._get_val(ret_source, states)
        summary.return_influence |= set(ret_val.origins)

    def _handle_unknown(self, out, inputs, states):
        if out is None:
            return
        val = AbstractValue(bit_width=out.getSize() * 8)
        def_union: Set[int] = set()
        maybe_union: Set[int] = set()
        tainted_input = False
        for inp in inputs:
            inp_val = self._get_val(inp, states)
            val = val.merge(inp_val)
            def_union |= _definitely_bits(inp_val)
            maybe_union |= _maybe_bits(inp_val)
            tainted_input = tainted_input or inp_val.tainted
        val.definitely_used_bits = set(def_union)
        val.maybe_used_bits = set(maybe_union | def_union)
        val.candidate_bits = set(val.maybe_used_bits)
        val.used_bits = set(val.definitely_used_bits)
        if tainted_input:
            val.bit_usage_degraded = True
            self.global_state.analysis_stats["bit_precision_degraded"] = True
        self._set_val(out, val, states)

    def _finalize_summary_from_slots(self, summary: FunctionSummary) -> None:
        existing = self.global_state.function_summaries.get(summary.name)
        if any(slot.get("origins") for slot in summary.slot_writes):
            summary.uses_registry = True
        if existing:
            summary.merge_from(existing)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def seed_fallback_roots(program, global_state: GlobalState, args: Dict[str, Any]) -> None:
    """
    When no 'real' registry roots were detected, fall back to heuristic roots so that
    small or heavily optimized binaries still produce something useful.

    Priority:
      1) Registry-like strings (HKLM\\..., HKCU\\..., etc.).
      2) Imported registry APIs (ADVAPI32::RegOpenKeyExW, NTDLL::NtQueryValueKey, ...).

    These roots are marked as synthetic and do NOT have precise bit usage; they are
    just anchors so the NDJSON isn't empty.
    """
    # If we already have roots from real calls, do nothing.
    if global_state.roots:
        return

    # ------------------------------------------------------------------
    # 1) Fallback from registry-like strings
    # ------------------------------------------------------------------
    registry_strings = getattr(global_state, "registry_strings", None) or {}
    if registry_strings:
        af = program.getAddressFactory()
        fm = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()
        created = 0

        for addr_str, meta in registry_strings.items():
            try:
                addr = af.getAddress(addr_str)
            except Exception:
                addr = None

            entry = None
            if addr is not None and ref_mgr is not None and fm is not None:
                try:
                    refs = ref_mgr.getReferencesTo(addr)
                    for r in refs:
                        try:
                            f = fm.getFunctionContaining(r.getFromAddress())
                        except Exception:
                            f = None
                        if f:
                            try:
                                entry = str(f.getEntryPoint())
                            except Exception:
                                entry = f.getName()
                            break
                except Exception:
                    pass

            root_id = f"string_seed_global_{addr_str}"
            if root_id in global_state.roots:
                continue

            global_state.roots[root_id] = {
                "id": root_id,
                "type": "synthetic",      # so root_kind=='synthetic' in NDJSON
                "api_name": None,
                "entry": entry,
                "hive": meta.get("hive") or meta.get("nt_root"),
                "path": meta.get("path") or meta.get("raw"),
                "value_name": meta.get("value_name"),
            }
            created += 1

        if DEBUG_ENABLED:
            log_debug(f"[debug] fallback: created {created} synthetic roots from registry-like strings")

        # If we managed to create at least one string-based root, we're done.
        if created > 0:
            return

    # ------------------------------------------------------------------
    # 2) Fallback from imported registry APIs
    # ------------------------------------------------------------------
    # IMPORTED_REGISTRY_API_NAMES / ADDRS are populated in main().
    global IMPORTED_REGISTRY_API_NAMES
    names = IMPORTED_REGISTRY_API_NAMES or set()
    if not names:
        return

    created = 0
    for api_name in sorted(names):
        root_id = f"import_seed_{api_name}"
        if root_id in global_state.roots:
            continue
        global_state.roots[root_id] = {
            "id": root_id,
            "type": "synthetic",
            "api_name": api_name,
            "entry": None,
            "hive": None,
            "path": None,
            "value_name": None,
        }
        created += 1

    if DEBUG_ENABLED:
        log_debug(f"[debug] fallback: created {created} synthetic roots from imported registry APIs")


def build_root_records(global_state: GlobalState) -> List[Dict[str, Any]]:
    records = []
    for root_id, meta in sorted(global_state.roots.items()):
        slot_entries = []
        used_bits: Set[int] = set()
        candidate_bits: Set[int] = set()
        slot_bit_widths: List[int] = []
        for key in sorted(global_state.root_slot_index.get(root_id, set())):
            slot = global_state.struct_slots.get(key)
            if slot is None:
                continue
            base_id, offset = key
            storage = classify_storage(base_id)
            slot_bits_def = sorted(_definitely_bits(slot.value))
            slot_bits_maybe = sorted(_maybe_bits(slot.value))
            slot_entries.append(
                {
                    "base_id": base_id,
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "stride": slot.stride,
                    "index_based": bool(slot.index_var),
                    "storage": storage,
                    "slot_priority": storage,
                    "slot_bits": {"definitely": slot_bits_def, "maybe": slot_bits_maybe} if slot_bits_def or slot_bits_maybe else None,
                    "notes": "struct slot",
                }
            )
            used_bits |= _definitely_bits(slot.value)
            candidate_bits |= _maybe_bits(slot.value)
            slot_bit_widths.append(slot.value.bit_width)
        decisions = [d.to_dict() for d in global_state.root_decision_index.get(root_id, [])]
        overrides = list(global_state.root_override_index.get(root_id, []))
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
                "bit_width": max([DEFAULT_POINTER_BIT_WIDTH] + slot_bit_widths),
                "used_bits": sorted(used_bits),
                "candidate_bits": sorted(candidate_bits),
            },
            "decisions": decisions,
            "overrides": overrides,
            "decision_count": len(global_state.root_decision_index.get(root_id, [])),
            "slot_count": len(global_state.root_slot_index.get(root_id, set())),
            "root_kind": (
                "api"
                if str(root_id).startswith("api_")
                else "indirect"
                if str(root_id).startswith("indirect_") or str(root_id).startswith("string_seed_")
                else "synthetic"
                if str(root_id) == "synthetic_full_mode_root" or meta.get("type") == "synthetic"
                else "unknown"
            ),
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
    roots_with_no_decisions = sum(1 for rid in global_state.roots if not global_state.root_decision_index.get(rid))
    roots_with_overrides = sum(1 for rid in global_state.roots if global_state.root_override_index.get(rid))
    bit_precision_degraded = bool(global_state.analysis_stats.get("bit_precision_degraded"))
    if not bit_precision_degraded:
        bit_precision_degraded = any(slot.value.bit_usage_degraded for slot in global_state.struct_slots.values())
        if not bit_precision_degraded:
            bit_precision_degraded = any(
                d.details.get("bit_heuristic") == "all_bits_fallback" for d in global_state.decisions if d.details
            )
    summary["meta"] = {
        "bit_precision_degraded": bool(bit_precision_degraded),
        "roots_with_no_decisions": roots_with_no_decisions,
        "roots_with_overrides": roots_with_overrides,
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
    mode = args.get("mode") or "taint"
    print("=== RegistryKeyBitfieldReport (PyGhidra) ===", file=sys.stderr)
    print(
        f"mode={mode} debug={str(DEBUG_ENABLED).lower()} trace={str(TRACE_ENABLED).lower()} context={INVOCATION_CONTEXT}",
        file=sys.stderr,
    )
    if not _ensure_environment(INVOCATION_CONTEXT):
        return
    program = currentProgram
    api = FlatProgramAPI(program)
    global DEFAULT_POINTER_BIT_WIDTH
    DEFAULT_POINTER_BIT_WIDTH = _detect_pointer_bit_width(program)
    log_info(
        f"[info] RegistryKeyBitfieldReport starting (mode={mode}, debug={DEBUG_ENABLED}, trace={TRACE_ENABLED}, context={INVOCATION_CONTEXT})"
    )
    if INVOCATION_CONTEXT == "script_manager":
        log_info("[info] Script Manager detected; NDJSON output will appear in the Ghidra console.")
    global IMPORTED_REGISTRY_API_NAMES, IMPORTED_REGISTRY_API_ADDRS
    IMPORTED_REGISTRY_API_NAMES, IMPORTED_REGISTRY_API_ADDRS = collect_imported_registry_apis(program)
    log_debug(
        f"[debug] imported registry candidates: names={len(IMPORTED_REGISTRY_API_NAMES)} addresses={len(IMPORTED_REGISTRY_API_ADDRS)}"
    )
    global_state = GlobalState()
    # ensure call_depth_limit is explicitly initialized (future use)
    global_state.analysis_stats["call_depth_limit"] = False
    scan_limit = args.get("registry_scan_limit")
    if scan_limit is not None and scan_limit < 0:
        log_debug("[debug] registry_scan_limit negative; disabling pre-scan")
        scan_limit = 0
    global_state.registry_strings = collect_registry_string_candidates(program, scan_limit)
    log_debug(
        f"[debug] initial registry roots={len(global_state.roots)} registry-like strings={len(global_state.registry_strings)}"
    )
    max_call_depth = args.get("max_call_depth")
    if max_call_depth is not None and max_call_depth <= 0:
        max_call_depth = None
    analyzer = FunctionAnalyzer(api, program, global_state, mode, max_call_depth=max_call_depth)
    if args.get("max_steps"):
        analyzer.max_steps = max(1, int(args.get("max_steps")))
    if args.get("max_function_iterations"):
        analyzer.max_function_iterations = max(1, int(args.get("max_function_iterations")))
    analyzer.analyze_all()

    # Heuristic fallback: create synthetic roots when taint-mode finds nothing.
    # This applies to BOTH modes, but only if no real roots exist.
    seed_fallback_roots(program, global_state, args)
    # Synthetic root for full mode when no registry APIs are detected
    if mode == "full" and not global_state.roots and args.get("enable_synthetic_full_root", True):
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
    print(
        f"=== Analysis complete: {len(global_state.roots)} roots, {len(global_state.decisions)} decisions, {len(global_state.struct_slots)} slots ===",
        file=sys.stderr,
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


def _launch_via_pyghidra_bridge() -> None:
    try:
        from pyghidra import open_project, ghidra_script
    except Exception as exc:  # pragma: no cover - bridge only
        print(
            f"[error] pyghidra is required to launch this script headlessly: {exc!r}",
            file=sys.stderr,
        )
        sys.exit(1)

    project_path = (
        os.environ.get("GHIDRA_PROJECT_PATH")
        or os.environ.get("PYGHIDRA_PROJECT_PATH")
        or os.environ.get("GHIDRA_DEFAULT_PROJECT_PATH")
    )
    project_name = (
        os.environ.get("GHIDRA_PROJECT_NAME")
        or os.environ.get("PYGHIDRA_PROJECT_NAME")
        or os.environ.get("GHIDRA_DEFAULT_PROJECT_NAME")
    )
    target_binary = (
        os.environ.get("GHIDRA_TARGET_BINARY")
        or os.environ.get("PYGHIDRA_TARGET_BINARY")
        or os.environ.get("GHIDRA_DEFAULT_TARGET")
    )

    if not project_path or not project_name or not target_binary:
        print(
            "[error] When running outside Ghidra, set GHIDRA_PROJECT_PATH, GHIDRA_PROJECT_NAME, and GHIDRA_TARGET_BINARY.",
            file=sys.stderr,
        )
        sys.exit(1)

    kv_args = _filter_kv_args(_SYS_RAW_ARGS)
    with open_project(project_path, project_name) as proj:
        with ghidra_script(proj, target_binary) as gh:
            gh.run_script(__file__, args=kv_args)


if __name__ == "__main__":
    _REGKEYBITFIELDREPORT_RAN = True
    if currentProgram is None:
        _launch_via_pyghidra_bridge()
    else:
        main()
else:
    _maybe_run_main_from_script_manager()
