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
import heapq
from collections import defaultdict, deque
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class KnownBits:
    """Tracks which bits are definitively zero/one for an abstract value."""

    bit_width: int
    known_zeros: int = 0
    known_ones: int = 0

    @staticmethod
    def top(width: int) -> "KnownBits":
        return KnownBits(width, 0, 0)

    @staticmethod
    def from_constant(width: int, value: int) -> "KnownBits":
        mask = (1 << width) - 1
        clean = value & mask
        return KnownBits(width, (~clean) & mask, clean)

    def _ensure_width(self, other: "KnownBits") -> int:
        return max(self.bit_width, other.bit_width)

    def merge(self, other: "KnownBits") -> "KnownBits":
        width = self._ensure_width(other)
        mask = (1 << width) - 1
        zeros = self.known_zeros & other.known_zeros & mask
        ones = self.known_ones & other.known_ones & mask
        return KnownBits(width, zeros, ones)

    def and_bits(self, other: "KnownBits") -> "KnownBits":
        width = self._ensure_width(other)
        mask = (1 << width) - 1
        zeros = (self.known_zeros | other.known_zeros | (self.known_ones & other.known_zeros)) & mask
        ones = (self.known_ones & other.known_ones) & mask
        return KnownBits(width, zeros, ones)

    def or_bits(self, other: "KnownBits") -> "KnownBits":
        width = self._ensure_width(other)
        mask = (1 << width) - 1
        ones = (self.known_ones | other.known_ones | (self.known_zeros & other.known_ones)) & mask
        zeros = (self.known_zeros & other.known_zeros) & mask
        return KnownBits(width, zeros, ones)

    def xor_bits(self, other: "KnownBits") -> "KnownBits":
        width = self._ensure_width(other)
        mask = (1 << width) - 1
        ones = ((self.known_ones & ~other.known_ones) | (~self.known_ones & other.known_ones)) & mask
        zeros = (self.known_zeros & other.known_zeros) & mask
        return KnownBits(width, zeros, ones)

    def add_bits(self, other: "KnownBits") -> "KnownBits":
        width = self._ensure_width(other)
        mask = (1 << width) - 1
        ones = self.known_ones | other.known_ones
        zeros = self.known_zeros | other.known_zeros
        carry_top = mask ^ (ones | zeros)
        zeros &= ~carry_top
        ones &= ~carry_top
        return KnownBits(width, zeros & mask, ones & mask)

    def shift_left(self, amount: int) -> "KnownBits":
        if amount <= 0:
            return self
        width = self.bit_width
        mask = (1 << width) - 1
        zeros = ((self.known_zeros << amount) | ((1 << amount) - 1)) & mask
        ones = (self.known_ones << amount) & mask
        return KnownBits(width, zeros, ones)

    def shift_right(self, amount: int) -> "KnownBits":
        if amount <= 0:
            return self
        width = self.bit_width
        mask = (1 << width) - 1
        zeros = (self.known_zeros >> amount) | (((1 << amount) - 1) << (width - amount))
        ones = (self.known_ones >> amount) & mask
        return KnownBits(width, zeros & mask, ones & mask)

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
    parsed["trace"] = _parse_bool(parsed.get("trace", "true"))
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
    args = {"mode": "taint", "debug": False, "trace": True}
DEBUG_ENABLED = args.get("debug", False)
TRACE_ENABLED = args.get("trace", False)
for _flag in ["enable_string_seeds", "enable_indirect_roots", "enable_synthetic_full_root"]:
    args.setdefault(_flag, True)


DEFAULT_POINTER_BIT_WIDTH = 32
PROGRAM_IS_BIG_ENDIAN = False
BYTE_ORDER = "little"


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


def _detect_endianness(program) -> Tuple[bool, str]:
    try:
        lang = program.getLanguage()
        is_big = bool(getattr(lang, "isBigEndian", lambda: lambda: False)())
        return is_big, "big" if is_big else "little"
    except Exception:
        return False, BYTE_ORDER


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

    def signature(self) -> Tuple[Any, ...]:
        return (
            self.base_id,
            self.offset,
            self.stride,
            self.index_var,
            self.unknown,
        )

    def merge(self, other: "PointerPattern") -> "PointerPattern":
        if other is None:
            return self
        if self.unknown or other.unknown:
            return PointerPattern(base_id=self.base_id or other.base_id, unknown=True)
        if self.base_id != other.base_id:
            return PointerPattern(base_id=self.base_id or other.base_id, unknown=True)
        merged = PointerPattern(base_id=self.base_id)
        merged.offset_history = set(self.offset_history | other.offset_history)
        merged.index_var = self.index_var if self.index_var == other.index_var else None

        if self.offset == other.offset:
            merged.offset = self.offset
            merged.stride = self.stride if self.stride == other.stride else self.stride or other.stride
        else:
            if self.offset is not None and other.offset is not None:
                diff = abs(other.offset - self.offset)
                stride_candidate = self.stride or other.stride

                if stride_candidate is not None and diff % stride_candidate == 0:
                    merged.stride = stride_candidate
                    merged.offset = min(self.offset, other.offset)
                    merged.index_var = merged.index_var or "loop_inferred"
                elif diff > 0:
                    merged.stride = diff
                    merged.offset = min(self.offset, other.offset)
                    merged.index_var = merged.index_var or "loop_inferred"
                else:
                    merged.unknown = True
            else:
                merged.unknown = True

        if not merged.unknown and merged.offset is None and merged.stride is None:
            merged.unknown = True

        return merged


@dataclass
class AbstractValue:
    # --- Status Flags ---
    tainted: bool = False
    is_top: bool = False      # Represents "Unknown / All Possible Values"
    is_bottom: bool = True    # Represents "Uninitialized / Not Yet Visited"

    # --- Data Tracking ---
    origins: Set[str] = field(default_factory=set)
    control_taints: Set[str] = field(default_factory=set)
    bit_width: int = 32
    known_bits: KnownBits = field(default_factory=lambda: KnownBits.top(DEFAULT_POINTER_BIT_WIDTH))
    range_min: Optional[int] = None
    range_max: Optional[int] = None
    
    # --- Bitfield Tracking ---
    used_bits: Set[int] = field(default_factory=set)
    candidate_bits: Set[int] = field(default_factory=set)
    definitely_used_bits: Set[int] = field(default_factory=set)
    maybe_used_bits: Set[int] = field(default_factory=set)
    forbidden_bits: Set[int] = field(default_factory=set)

    # --- Pointer Analysis ---
    pointer_patterns: List[PointerPattern] = field(default_factory=list)
    pointer_targets: Set[int] = field(default_factory=set)
    function_pointer_labels: Set[str] = field(default_factory=set)
    
    # --- Meta ---
    compare_details: Dict[str, Any] = field(default_factory=dict)
    mask_history: List[Dict[str, Any]] = field(default_factory=list)
    bit_usage_degraded: bool = False
    slot_sources: Set[Tuple[str, int]] = field(default_factory=set)

    def clone(self) -> "AbstractValue":
        return AbstractValue(
            tainted=self.tainted,
            is_top=self.is_top,
            is_bottom=self.is_bottom,
            origins=set(self.origins),
            control_taints=set(self.control_taints),
            bit_width=self.bit_width,
            known_bits=KnownBits(self.known_bits.bit_width, self.known_bits.known_zeros, self.known_bits.known_ones),
            range_min=self.range_min,
            range_max=self.range_max,
            used_bits=set(self.used_bits),
            candidate_bits=set(self.candidate_bits),
            definitely_used_bits=set(self.definitely_used_bits),
            maybe_used_bits=set(self.maybe_used_bits),
            forbidden_bits=set(self.forbidden_bits),
            pointer_patterns=[p.clone() for p in self.pointer_patterns],
            pointer_targets=set(self.pointer_targets),
            function_pointer_labels=set(self.function_pointer_labels),
            compare_details=dict(self.compare_details),
            mask_history=list(self.mask_history),
            bit_usage_degraded=self.bit_usage_degraded,
            slot_sources=set(self.slot_sources),
        )

    def mark_bits_used(self, mask: int) -> None:
        if self.is_bottom: self.is_bottom = False
        for i in range(self.bit_width):
            if mask & (1 << i):
                self.candidate_bits.add(i)
                self.used_bits.add(i)
                self.definitely_used_bits.add(i)
                self.maybe_used_bits.add(i)

    def mark_all_bits_used(self, degraded: bool = False) -> None:
        if self.is_bottom: self.is_bottom = False
        full_set = set(range(self.bit_width))
        self.candidate_bits |= full_set
        self.used_bits |= full_set
        self.definitely_used_bits |= full_set
        self.maybe_used_bits |= full_set
        self.known_bits = KnownBits.top(self.bit_width)
        if degraded:
            self.bit_usage_degraded = True

    def partial_widen(self) -> None:
        """Relax precision without losing the pointer base."""
        if self.is_top: return
        # Keep base_id but discard precise offset/stride
        for ptr in self.pointer_patterns:
            ptr.offset = None
            ptr.stride = None
            ptr.unknown = True
            ptr.offset_history.clear()
        self.pointer_targets.clear()
        self.mask_history.clear()
        self.bit_usage_degraded = True

    def interval_widen(self) -> None:
        """Expand precision conservatively using intervals before giving up to Top."""
        if self.is_top:
            return
        self.is_bottom = False
        self.bit_usage_degraded = True
        if self.range_min is None:
            self.range_min = 0
        if self.range_max is None:
            self.range_max = None
        self.known_bits = KnownBits.top(self.bit_width)
        self.candidate_bits |= set(range(self.bit_width))
        self.maybe_used_bits |= set(range(self.bit_width))
        if not self.definitely_used_bits:
            self.definitely_used_bits = set()

    def widen(self) -> None:
        """Drive to full Top state (completely unknown)."""
        if self.is_top: return
        self.is_top = True
        self.is_bottom = False
        self.mark_all_bits_used(degraded=True)
        self.known_bits = KnownBits.top(self.bit_width)
        self.range_min = None
        self.range_max = None
        self.pointer_targets.clear()
        self.mask_history.clear()
        self.function_pointer_labels.clear()
        for ptr in self.pointer_patterns:
            ptr.unknown = True

    def merge(self, other: "AbstractValue") -> "AbstractValue":
        if other is None: return self
        
        # Handle Bottom (Uninitialized) - The other value "wins" completely
        if self.is_bottom: return other.clone()
        if other.is_bottom: return self.clone()

        # Handle Top (Unknown) - If one is Top, the result is Top (but we try to preserve taint)
        if self.is_top or other.is_top:
            top_val = self.clone()
            top_val.widen()
            # Taint is 'sticky' - if either path was tainted, the result is tainted
            top_val.tainted = self.tainted or other.tainted
            top_val.origins = self.origins | other.origins
            return top_val

        merged = AbstractValue()
        merged.is_bottom = False
        merged.tainted = self.tainted or other.tainted
        merged.origins = self.origins | other.origins
        merged.control_taints = self.control_taints | other.control_taints
        merged.bit_width = max(self.bit_width, other.bit_width)
        merged.known_bits = self.known_bits.merge(other.known_bits)
        if self.range_min is not None and other.range_min is not None:
            merged.range_min = min(self.range_min, other.range_min)
        else:
            merged.range_min = self.range_min if self.range_min is not None else other.range_min
        if self.range_max is not None and other.range_max is not None:
            merged.range_max = max(self.range_max, other.range_max) if None not in (self.range_max, other.range_max) else None
        else:
            merged.range_max = self.range_max if self.range_max is not None else other.range_max

        # Merge Bitfields (Union)
        merged.used_bits = self.used_bits | other.used_bits
        merged.definitely_used_bits = self.definitely_used_bits & other.definitely_used_bits # Intersection for 'definite'
        merged.maybe_used_bits = self.maybe_used_bits | other.maybe_used_bits
        merged.candidate_bits = self.candidate_bits | other.candidate_bits
        merged.forbidden_bits = self.forbidden_bits & other.forbidden_bits
        
        # Merge Pointers
        merged.pointer_targets = self.pointer_targets | other.pointer_targets
        merged.function_pointer_labels = self.function_pointer_labels | other.function_pointer_labels

        existing_sigs = {p.signature() for p in self.pointer_patterns}
        merged.pointer_patterns = [p.clone() for p in self.pointer_patterns]
        for ptr in other.pointer_patterns:
            sig = ptr.signature()
            if sig not in existing_sigs:
                merged.pointer_patterns.append(ptr.clone())
                existing_sigs.add(sig)
        if len(merged.pointer_patterns) > 5:
            merged.pointer_patterns = [self._compress_patterns(merged.pointer_patterns)]

        merged.compare_details = self.compare_details.copy()
        merged.compare_details.update(other.compare_details)
        
        # Limit history growth to prevent memory explosion
        merged.mask_history = (self.mask_history + other.mask_history)[-10:]
        merged.bit_usage_degraded = self.bit_usage_degraded or other.bit_usage_degraded
        merged.slot_sources = self.slot_sources | other.slot_sources

        return merged

    def _compress_patterns(self, patterns: List[PointerPattern]) -> PointerPattern:
        base_ids = {p.base_id for p in patterns if p.base_id is not None}
        base_id = base_ids.pop() if len(base_ids) == 1 else None
        return PointerPattern(base_id=base_id, unknown=True)

    def state_signature(self) -> Tuple:
        pointer_sig = None
        if self.pointer_patterns:
            pointer_sig = tuple(sorted((p.signature() for p in self.pointer_patterns), key=str))
        return (
            self.is_bottom,
            self.is_top,
            self.tainted,
            frozenset(self.origins),
            frozenset(self.control_taints),
            self.bit_width,
            frozenset(self.used_bits),
            frozenset(self.definitely_used_bits),
            pointer_sig,
            frozenset(self.pointer_targets),
            frozenset(self.function_pointer_labels),
            self.bit_usage_degraded,
            self.range_min,
            self.range_max,
        )


@dataclass
class StructSlot:
    base_id: str
    offset: int
    stride: Optional[int] = None
    index_var: Optional[Any] = None
    value: AbstractValue = field(default_factory=AbstractValue)

    def clone(self) -> "StructSlot":
        return StructSlot(
            self.base_id,
            self.offset,
            self.stride,
            self.index_var,
            self.value.clone(),
        )


@dataclass
class MemoryState:
    slots: Dict[Tuple[str, int], StructSlot] = field(default_factory=dict)

    def clone(self) -> "MemoryState":
        return MemoryState({k: v.clone() for k, v in self.slots.items()})

    def merge(self, other: "MemoryState") -> "MemoryState":
        merged_slots: Dict[Tuple[str, int], StructSlot] = {}
        for key in set(self.slots.keys()) | set(other.slots.keys()):
            left = self.slots.get(key)
            right = other.slots.get(key)
            if left and right:
                merged_val = left.value.merge(right.value)
                merged_slots[key] = StructSlot(
                    base_id=left.base_id or right.base_id,
                    offset=left.offset if left.offset is not None else right.offset,
                    stride=left.stride if left.stride is not None else right.stride,
                    index_var=left.index_var if left.index_var is not None else right.index_var,
                    value=merged_val,
                )
            elif left:
                merged_slots[key] = left.clone()
            elif right:
                merged_slots[key] = right.clone()
        return MemoryState(merged_slots)

    def signature(self) -> Tuple:
        sig = []
        for key in sorted(self.slots.keys(), key=lambda k: (str(k[0]), k[1])):
            slot = self.slots[key]
            sig.append((key, slot.value.state_signature(), slot.stride, slot.index_var))
        return tuple(sig)


@dataclass
class AnalysisState:
    values: Dict[Tuple, AbstractValue] = field(default_factory=dict)
    memory: MemoryState = field(default_factory=MemoryState)
    control_taints: Set[str] = field(default_factory=set)

    def clone(self) -> "AnalysisState":
        return AnalysisState(
            values={k: v.clone() for k, v in self.values.items()},
            memory=self.memory.clone(),
            control_taints=set(self.control_taints),
        )


@dataclass
class Decision:
    address: str
    mnemonic: str
    disasm: str
    origins: Set[str]
    used_bits: Set[int]
    control_taints: Set[str] = field(default_factory=set)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "mnemonic": self.mnemonic,
            "disasm": self.disasm,
            "origins": sorted(self.origins),
            "used_bits": sorted(self.used_bits),
            "control_taints": sorted(self.control_taints),
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
            tuple(sorted(decision.control_taints)),
            tuple(sorted(decision.used_bits)),
            tuple(sorted(decision.details.items())),
        )

    def add_decision(self, decision: Decision) -> None:
        sig = self._decision_signature(decision)
        if sig in self._decision_signatures:
            return
        self._decision_signatures.add(sig)
        self.decisions.append(decision)
        if decision.origins or decision.control_taints:
            self.uses_registry = True
            self.registry_decision_roots |= set(decision.origins | decision.control_taints)

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
    function_summaries: Dict[Tuple[str, str], FunctionSummary] = field(default_factory=dict)
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
    known = KnownBits.top(width)
    if vn and vn.isConstant():
        off = vn_get_offset(vn)
        if off is not None:
            known = KnownBits.from_constant(width, off)
    val = AbstractValue(bit_width=width, known_bits=known)
    val.is_bottom = False
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
    # require a canonical prefix â synthetic/relative paths are allowed.
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
    DEFAULT_MAX_CALL_DEPTH = 15
    CALL_STRING_K = 3
    WIDEN_THRESHOLD = 100
    WIDEN_ESCALATION = 50
    LOOP_PEEL_LIMIT = 3

    def __init__(self, api: FlatProgramAPI, program, global_state: GlobalState, mode: str, max_call_depth: Optional[int] = None):
        self.api = api
        self.global_state = global_state
        self.mode = mode
        self.max_steps = self.DEFAULT_MAX_STEPS
        self.max_function_iterations = self.DEFAULT_MAX_FUNCTION_ITERATIONS
        self.max_call_depth = max_call_depth if max_call_depth is not None else self.DEFAULT_MAX_CALL_DEPTH
        self.program = program
        self.pointer_bit_width = _detect_pointer_bit_width(program)
        # Reuse a single BasicBlockModel for the program (safe for Ghidra 12).
        self.block_model = BasicBlockModel(self.program) if BasicBlockModel else None
        self.monitor = ACTIVE_MONITOR or DUMMY_MONITOR
        self._registry_string_usage_cache: Dict[str, bool] = {}
        self._functions_with_registry_calls: Set[str] = set()

    def _summaries_for(self, func_name: str) -> List[FunctionSummary]:
        return [s for (name, _ctx), s in self.global_state.function_summaries.items() if name == func_name]

    def _get_function_for_inst(self, inst: Instruction):
        try:
            fm = self.program.getFunctionManager()
            return fm.getFunctionContaining(inst.getAddress())
        except Exception:
            return None

    def _record_base_id_metadata(self, base_id: Optional[str], vn) -> None:
        _record_storage_metadata(base_id, vn, self.program)

    def _extend_call_context(self, call_ctx: Tuple[str, ...], caller_entry: Any) -> Tuple[str, ...]:
        ctx_list = list(call_ctx or ())
        ctx_list.append(str(caller_entry))
        return tuple(ctx_list[-self.CALL_STRING_K:])

    def _function_has_registry_calls(self, func) -> bool:
        if func is None:
            return False
        try:
            if func.getName() in self._functions_with_registry_calls:
                return True
            for summary in self._summaries_for(func.getName()):
                if summary.uses_registry:
                    return True
        except Exception:
            return False

    def _pointer_args_from_registry(self, pointer_args: List[Any], states: AnalysisState) -> bool:
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
        # do not cache â registry strings can be discovered dynamically during analysis
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
            width_bytes = max(1, getattr(self, "pointer_bit_width", DEFAULT_POINTER_BIT_WIDTH) // 8)
            buf = bytearray(width_bytes)
            read = mem.getBytes(addr, buf)
            if not isinstance(read, (int, float)) or read <= 0:
                return None
            return int.from_bytes(bytes(buf[: int(read)]), byteorder=BYTE_ORDER, signed=False)
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

    def _find_hkey_meta(self, call_args: List[Any], states: AnalysisState) -> Optional[Dict[str, str]]:
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
        self, func, call_args: List[Any], states: AnalysisState, label: Optional[str], root_id: Optional[str]
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

    def _collect_potential_definitions(self, vn, max_depth=100) -> List[Tuple[Any, Optional[PcodeOp]]]:
        """
        Performs a DFS backward slice to find all 'root' definitions of a varnode
        (Constants, Loads, Inputs), handling control flow merges (Phi nodes)
        and passthrough operations.
        """
        definitions = []
        visited = set()
        # Stack stores (Varnode, depth)
        stack = [(vn, 0)]
        
        while stack:
            curr, depth = stack.pop()
            # Cycle detection for "infinite" context safety
            key = varnode_key(curr)
            if key in visited:
                continue
            visited.add(key)
            
            if depth > max_depth:
                definitions.append((curr, None))
                continue

            if curr is None:
                continue

            if curr.isConstant() or curr.isAddress():
                definitions.append((curr, None))
                continue

            try:
                def_op = curr.getDef()
            except Exception:
                definitions.append((curr, None))
                continue

            if not def_op:
                definitions.append((curr, None)) # Function input or uninitialized
                continue
                
            opcode = def_op.getOpcode()
            
            # Passthrough operations: dive deeper
            if opcode in {PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE}:
                inp = def_op.getInput(0)
                if inp:
                    stack.append((inp, depth + 1))
            
            # Phi nodes (MULTIEQUAL): Explore ALL branches (infinite context across CFG splits)
            elif opcode == PcodeOp.MULTIEQUAL:
                for i in range(def_op.getNumInputs()):
                    inp = def_op.getInput(i)
                    if inp:
                        stack.append((inp, depth + 1))
            
            # Meaningful terminal ops (LOAD, PTRADD, CALL return, etc.)
            else:
                definitions.append((curr, def_op))

        return definitions

    def _extract_const_base_offset(self, vn, depth: int = 0) -> Tuple[Optional[int], Optional[int]]:
        if vn is None or depth > 5:
            return None, None
        if vn_is_constant(vn):
            return vn_get_offset(vn), 0
        try:
            def_op = vn.getDef()
        except Exception:
            def_op = None
        if not def_op:
            return None, None
        opcode = def_op.getOpcode()
        if opcode not in {PcodeOp.INT_ADD, PcodeOp.PTRADD}:
            return None, None
        lhs = def_op.getInput(0)
        rhs = def_op.getInput(1)
        base_a, off_a = self._extract_const_base_offset(lhs, depth + 1)
        base_b, off_b = self._extract_const_base_offset(rhs, depth + 1)
        base = base_a if base_a is not None else base_b
        offset = 0
        for off in (off_a, off_b):
            if off is not None:
                offset += off
        if opcode == PcodeOp.PTRADD and def_op.getNumInputs() > 2:
            idx = def_op.getInput(1)
            elem = def_op.getInput(2)
            idx_off = vn_get_offset(idx) if vn_is_constant(idx) else None
            elem_size = vn_get_offset(elem) if elem and vn_is_constant(elem) else None
            if idx_off is not None and elem_size is not None:
                offset = (offset or 0) + idx_off * elem_size
            else:
                offset = None
        return base, offset

    def _resolve_vtable_target(self, addr_vn) -> Tuple[Optional[str], Optional[Any]]:
        try:
            base_const, offset = self._extract_const_base_offset(addr_vn)
            if base_const is None:
                return None, None
            base_addr = self.api.toAddr(base_const + (offset or 0))
            mem = self.program.getMemory()
            block = mem.getBlock(base_addr) if mem else None
            if block is None or block.isWrite():
                return None, None
            ptr = self._read_pointer_value(base_addr)
            if ptr is None:
                return None, None
            fm = self.program.getFunctionManager()
            func = fm.getFunctionAt(self.api.toAddr(ptr)) if fm else None
            if func:
                return func.getName(), func
            ext_label = self._external_label_for_address(self.api.toAddr(ptr))
            if ext_label:
                return ext_label, None
            mapped = IMPORTED_REGISTRY_API_ADDRS.get(ptr) or IMPORTED_REGISTRY_API_ADDRS.get(str(ptr))
            if mapped:
                return mapped, None
        except Exception:
            return None, None
        return None, None

    def _resolve_callee_from_pcode_target(self, target_vn, states: AnalysisState) -> Tuple[Optional[str], Optional[Any]]:
        fm = self.program.getFunctionManager()
        callee = None
        callee_func = None

        # 1. Check abstract value first (Forward propagation results)
        try:
            val = self._get_val(target_vn, states) if target_vn else None
            if val and val.function_pointer_labels:
                # Return the lexicographically first label for consistency
                return sorted(val.function_pointer_labels)[0], None
        except Exception:
            pass

        # 2. Collect Definitions via Slicing
        potential_defs = self._collect_potential_definitions(target_vn)

        for real_vn, def_op in potential_defs:
            if callee: break
            
            if not def_op:
                # Handle Constants (Absolute Addresses)
                if vn_is_constant(real_vn):
                    off = vn_get_offset(real_vn)
                    # Check Import Cache
                    mapped = IMPORTED_REGISTRY_API_ADDRS.get(off)
                    if mapped:
                        callee = mapped
                        break
                    # Check if it's a function start
                    f = fm.getFunctionAt(self.api.toAddr(off))
                    if f:
                        callee_func = f
                        callee = f.getName()
                        break
                continue

            opcode = def_op.getOpcode()

            # Case A: LEA / PTRADD (RIP-Relative addressing patterns)
            # Common in x64: LEA RAX, [RIP + 0x1234]
            if opcode == PcodeOp.PTRADD:
                base = def_op.getInput(0)
                offset = def_op.getInput(1)
                
                # If base is unknown but context implies it might be current block/image base
                # This is hard in pure P-code without the instruction context, 
                # but we can check if 'base' comes from a constant that looks like an image base.
                pass 
            
            # Case B: LOAD (Global Variable / IAT)
            if opcode == PcodeOp.LOAD:
                addr_vn = def_op.getInput(1)
                
                # Recurse: What address are we loading from?
                # This catches: MOV RAX, [0x401000] -> CALL RAX
                sub_defs = self._collect_potential_definitions(addr_vn, max_depth=5)
                for sub_vn, _ in sub_defs:
                    if vn_is_constant(sub_vn):
                        load_addr_off = vn_get_offset(sub_vn)
                        
                        # 1. Is the address in the IAT?
                        mapped = IMPORTED_REGISTRY_API_ADDRS.get(load_addr_off)
                        if mapped:
                            callee = mapped
                            break
                        
                        # 2. Read memory at that address (Global function pointer)
                        ptr = self._read_pointer_value(self.api.toAddr(load_addr_off))
                        if ptr:
                            mapped_ptr = IMPORTED_REGISTRY_API_ADDRS.get(ptr)
                            if mapped_ptr:
                                callee = mapped_ptr
                                break
                            # Is the pointed-to value a function?
                            f_ptr = fm.getFunctionAt(self.api.toAddr(ptr))
                            if f_ptr:
                                callee_func = f_ptr
                                callee = f_ptr.getName()
                                break

                if not callee:
                    vt_name, vt_func = self._resolve_vtable_target(addr_vn)
                    if vt_name:
                        callee = vt_name
                        callee_func = vt_func or callee_func
                        break

        return callee, callee_func

    def _resolve_string_from_vn(self, vn, states: Optional[AnalysisState] = None) -> Optional[Dict[str, Any]]:
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
                for ptr in val.pointer_patterns:
                    if ptr.base_id is None:
                        continue
                    heap_bytes = self.global_state.heap_string_writes.get(ptr.base_id)
                    if heap_bytes:
                        collected = bytearray()
                        start = ptr.offset or 0
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

    def _func_key(self, func, ctx: Any = ("root",)) -> str:
        base = func.getName()
        if hasattr(func, "getEntryPoint"):
            try:
                base = f"{base}@{func.getEntryPoint()}"
            except Exception:
                pass
        ctx_repr = ctx
        try:
            if isinstance(ctx, (list, tuple)):
                ctx_repr = "->".join(ctx)
        except Exception:
            ctx_repr = ctx
        return f"{base}::{ctx_repr}"

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
            worklist.append((func, 0, ("root",)))
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
            func, depth, call_ctx = worklist.popleft()
            func_key = self._func_key(func, call_ctx)
            queued.discard(func_key)
            iteration_guard += 1
            if self.max_call_depth is not None and depth > self.max_call_depth:
                self.global_state.analysis_stats["call_depth_limit"] = True
                continue
            summary = self.analyze_function(func, call_ctx)
            self.global_state.analysis_stats["functions_analyzed"] = self.global_state.analysis_stats.get(
                "functions_analyzed", 0
            ) + 1
            existing = self.global_state.function_summaries.get((func.getName(), call_ctx))
            if existing is None:
                self.global_state.function_summaries[(func.getName(), call_ctx)] = summary
                for callee in func.getCalledFunctions(self.monitor):
                    callee_ctx = self._extend_call_context(call_ctx, func.getEntryPoint())
                    callee_key = self._func_key(callee, callee_ctx)
                    if callee_key not in queued:
                        queued.add(callee_key)
                        worklist.append((callee, depth + 1, callee_ctx))
            else:
                if existing.merge_from(summary):
                    for callee in func.getCalledFunctions(self.monitor):
                        callee_ctx = self._extend_call_context(call_ctx, func.getEntryPoint())
                        callee_key = self._func_key(callee, callee_ctx)
                        if callee_key not in queued:
                            queued.add(callee_key)
                            worklist.append((callee, depth + 1, callee_ctx))
        if iteration_guard >= self.max_function_iterations:
            log_debug("[warn] function iteration limit hit")
            self.global_state.analysis_stats["function_iterations_limit"] = True

    # ------------------------------------------------------------------
    # Function level fixed-point over basic blocks
    # ------------------------------------------------------------------

    def analyze_function(self, func, call_context: str = "root") -> FunctionSummary:
        log_trace(f"[trace] analyzing function {func.getName()} at {func.getEntryPoint()} ctx={call_context}")
        summary = FunctionSummary(func.getName(), str(func.getEntryPoint()))
        body = func.getBody()
        listing = self.program.getListing()
        if not self.block_model:
            return summary
        blocks = list(self.block_model.getCodeBlocksContaining(body, self.monitor))
        preds: Dict[Any, List[Any]] = defaultdict(list)
        succs: Dict[Any, List[Any]] = defaultdict(list)
        for blk in blocks:
            it = blk.getDestinations(self.monitor)
            while it.hasNext():
                dest = it.next()
                succs[blk].append(dest.getDestinationBlock())
                preds[dest.getDestinationBlock()].append(blk)

        # Build Reverse Post-Order for prioritized worklist scheduling
        visited: Set[Any] = set()
        post_order: List[Any] = []

        def _dfs(block):
            visited.add(block)
            for s in succs.get(block, []):
                if s not in visited:
                    _dfs(s)
            post_order.append(block)

        entry_block = None
        try:
            for blk in blocks:
                if blk.getFirstStartAddress() == func.getEntryPoint():
                    entry_block = blk
                    break
        except Exception:
            entry_block = blocks[0] if blocks else None
        if entry_block:
            _dfs(entry_block)
        rpo = list(reversed(post_order)) if post_order else list(blocks)
        priority_map = {blk: idx for idx, blk in enumerate(rpo)}

        loop_headers: Set[Any] = set()
        for blk in blocks:
            for succ in succs.get(blk, []):
                if priority_map.get(succ, len(priority_map)) <= priority_map.get(blk, len(priority_map)):
                    loop_headers.add(succ)

        worklist: List[Tuple[int, Any]] = []
        in_queue: Set[Any] = set()

        def _enqueue(block):
            if block in in_queue:
                return
            prio = priority_map.get(block, len(priority_map))
            heapq.heappush(worklist, (prio, block))
            in_queue.add(block)

        if blocks:
            _enqueue(entry_block or blocks[0])

        out_states: Dict[Any, AnalysisState] = {}
        block_visits: Dict[Any, int] = defaultdict(int)
        steps = 0

        while worklist and steps < self.max_steps:
            _, blk = heapq.heappop(worklist)
            in_queue.discard(blk)
            steps += 1
            try:
                if self.monitor and hasattr(self.monitor, "checkCanceled"):
                    self.monitor.checkCanceled()
            except Exception:
                pass

            block_visits[blk] += 1
            peel_active = blk in loop_headers and block_visits[blk] <= self.LOOP_PEEL_LIMIT
            widen_progress = 0 if peel_active else max(0, block_visits[blk] - self.WIDEN_THRESHOLD)

            state = self._merge_predecessors(blk, preds, out_states, widen_progress)
            new_state = self._run_block(func, blk, state, listing, summary)
            if self._state_changed(out_states.get(blk), new_state):
                out_states[blk] = new_state
                for succ in succs.get(blk, []):
                    _enqueue(succ)
        if steps >= self.max_steps:
            log_debug(f"[warn] worklist limit hit in function {func.getName()}")
            self.global_state.analysis_stats["worklist_limit"] = True
        self._finalize_summary_from_slots(summary)
        return summary

    def _merge_predecessors(
        self, blk, preds: Dict[Any, List[Any]], out_states: Dict[Any, AnalysisState], widen_progress: int = 0
    ) -> AnalysisState:
        # Filter out predecessors that haven't been visited yet (empty states)
        # This prevents "polluting" the merge with empty/bottom values early in the loop.
        valid_preds = [out_states.get(p) for p in preds.get(blk, []) if p in out_states]

        if not valid_preds:
            return AnalysisState()

        merged = valid_preds[0].clone()

        # Merge the rest
        for other_state in valid_preds[1:]:
            all_keys = set(merged.values.keys()) | set(other_state.values.keys())
            for key in all_keys:
                val_a = merged.values.get(key)
                val_b = other_state.values.get(key)

                if val_a is None:
                    merged.values[key] = val_b.clone() if val_b else AbstractValue()
                elif val_b is None:
                    continue
                else:
                    merged.values[key] = val_a.merge(val_b)

            merged.memory = merged.memory.merge(other_state.memory)
            merged.control_taints |= set(other_state.control_taints)

        # Progressive widening if loop threshold reached
        if widen_progress > 0:
            use_interval = widen_progress <= self.WIDEN_ESCALATION
            for v in merged.values.values():
                if use_interval:
                    v.interval_widen()
                else:
                    v.widen()
            widened_slots = {}
            for key, slot in merged.memory.slots.items():
                widened_val = slot.value.clone()
                if use_interval:
                    widened_val.interval_widen()
                else:
                    widened_val.widen()
                widened_slots[key] = StructSlot(
                    slot.base_id,
                    slot.offset,
                    slot.stride,
                    slot.index_var,
                    widened_val,
                )
            merged.memory = MemoryState(widened_slots)

        return merged

    def _state_changed(self, old: AnalysisState, new: AnalysisState) -> bool:
        if old is None:
            return True
        if old.control_taints != new.control_taints:
            return True
        if set(old.values.keys()) != set(new.values.keys()):
            return True
        for k, v in new.values.items():
            o = old.values.get(k)
            if o is None:
                return True
            if v.state_signature() != o.state_signature():
                return True
        if old.memory.signature() != new.memory.signature():
            return True
        return False

    def _run_block(self, func, blk, state: AnalysisState, listing, summary: FunctionSummary) -> AnalysisState:
        states = state.clone()
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

    def _get_val(self, vn, states: AnalysisState) -> AbstractValue:
        key = varnode_key(vn)
        if key not in states.values:
            states.values[key] = new_value_from_varnode(vn)
        return states.values[key]

    def _set_val(self, vn, val: AbstractValue, states: AnalysisState) -> None:
        key = varnode_key(vn)
        if states.control_taints:
            val = val.clone()
            val.tainted = True
            val.control_taints |= set(states.control_taints)
        states.values[key] = val
        log_trace(f"[trace] set {key} -> tainted={val.tainted} origins={sorted(val.origins)} bits={sorted(val.candidate_bits)}")

    def _process_pcode(self, func, inst: Instruction, op: PcodeOp, states: AnalysisState, summary: FunctionSummary) -> None:
        opname = opcode_name(op)
        out = op.getOutput()
        inputs = [op.getInput(i) for i in range(op.getNumInputs())]
        if opname in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"}:
            self._handle_copy(out, inputs, states)
        elif opname == "PIECE":
            self._handle_piece(out, inputs, states)
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
        elif opname in {
            "FLOAT_EQUAL",
            "FLOAT_NOTEQUAL",
            "FLOAT_LESS",
            "FLOAT_LESSEQUAL",
            "FLOAT_NAN",
        }:
            self._handle_compare(out, inputs, states)
        elif opname in {
            "FLOAT_ADD",
            "FLOAT_SUB",
            "FLOAT_MULT",
            "FLOAT_DIV",
            "FLOAT_NEG",
            "FLOAT_ABS",
            "FLOAT_SQRT",
            "INT_FLOAT",
            "FLOAT_INT",
            "FLOAT_TRUNC",
            "FLOAT_CEIL",
            "FLOAT_FLOOR",
            "FLOAT_ROUND",
        }:
            self._handle_float(out, inputs, states, opname)
        elif opname == "CBRANCH":  # unconditional BRANCH has no condition operand
            self._handle_branch(func, inst, opname, inputs, states, summary)
        elif opname == "MULTIEQUAL":
            self._handle_multiequal(out, inputs, states)
        elif opname == "INDIRECT":
            self._handle_indirect(out, inputs, states)
        elif opname in {"CALL", "CALLIND", "BRANCHIND"}:
            # Handle standard calls AND tail-call thunks (BRANCHIND)
            self._handle_call(func, inst, op, inputs, states, summary)
        elif opname == "RETURN":
            self._handle_return(func, inputs, states, summary)
        else:
            self._handle_unknown(out, inputs, states)

    # Individual handlers
    def _handle_copy(self, out, inputs, states):
        if out is None or not inputs:
            return
        src = self._get_val(inputs[0], states)
        val = src.clone()
        val.bit_width = out.getSize() * 8
        val.known_bits = KnownBits(val.bit_width, val.known_bits.known_zeros, val.known_bits.known_ones)

        try:
            op = out.getDef()
            if op and PcodeOp and op.getOpcode() == PcodeOp.SUBPIECE:
                byte_offset = inputs[1].getOffset() if len(inputs) > 1 else 0
                bit_shift = byte_offset * 8

                def _shift_bits(bit_set: Set[int]) -> Set[int]:
                    return {b - bit_shift for b in bit_set if 0 <= (b - bit_shift) < val.bit_width}

                val.used_bits = _shift_bits(src.used_bits)
                val.candidate_bits = _shift_bits(src.candidate_bits)
                val.definitely_used_bits = _shift_bits(src.definitely_used_bits)
                val.maybe_used_bits = _shift_bits(src.maybe_used_bits)

                shifted_known = src.known_bits.shift_right(bit_shift)
                mask = (1 << val.bit_width) - 1 if val.bit_width else 0
                val.known_bits = KnownBits(val.bit_width, shifted_known.known_zeros & mask, shifted_known.known_ones & mask)

                if src.range_min is not None:
                    val.range_min = max(0, src.range_min >> bit_shift)
                if src.range_max is not None:
                    val.range_max = src.range_max >> bit_shift if src.range_max is not None else None

                if bit_shift != 0:
                    val.pointer_targets = set()
                    val.pointer_patterns = []
        except Exception:
            pass
        self._set_val(out, val, states)

    def _handle_piece(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        val = AbstractValue(bit_width=out.getSize() * 8)
        mask = (1 << val.bit_width) - 1 if val.bit_width else 0
        combined_zeros = 0
        combined_ones = 0
        used_bits: Set[int] = set()
        maybe_bits: Set[int] = set()
        origins: Set[str] = set()
        control_taints: Set[str] = set()
        slot_sources: Set[Tuple[str, int]] = set()
        offset = 0
        for vn in reversed(inputs):  # PIECE uses most significant first
            src = self._get_val(vn, states)
            origins |= set(src.origins)
            control_taints |= set(src.control_taints)
            slot_sources |= set(src.slot_sources)
            shifted_def = {b + offset for b in _definitely_bits(src) if (b + offset) < val.bit_width}
            shifted_maybe = {b + offset for b in _maybe_bits(src) if (b + offset) < val.bit_width}
            used_bits |= shifted_def
            maybe_bits |= shifted_maybe | shifted_def
            combined_zeros |= (src.known_bits.known_zeros << offset) & mask
            combined_ones |= (src.known_bits.known_ones << offset) & mask
            offset += max(0, vn.getSize() * 8)

        val.tainted = bool(origins or control_taints)
        val.origins = origins
        val.control_taints = control_taints
        val.slot_sources = slot_sources
        val.definitely_used_bits = used_bits
        val.maybe_used_bits = maybe_bits | used_bits
        val.candidate_bits = set(val.maybe_used_bits)
        val.used_bits = set(val.definitely_used_bits)
        val.known_bits = KnownBits(val.bit_width, combined_zeros & mask, combined_ones & mask)
        val.pointer_patterns = []
        val.pointer_targets = set()
        val.mask_history = []
        self._set_val(out, val, states)

    def _handle_addsub(self, out, inputs, states, opname):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.control_taints = set(a.control_taints | b.control_taints)
        val.slot_sources = set(a.slot_sources | b.slot_sources)
        val.bit_width = out.getSize() * 8
        if opname == "INT_OR":
            val.known_bits = a.known_bits.or_bits(b.known_bits)
        else:
            val.known_bits = a.known_bits.xor_bits(b.known_bits)
        val.known_bits = a.known_bits.and_bits(b.known_bits)
        val.known_bits = KnownBits.top(val.bit_width)
        val.known_bits = a.known_bits.add_bits(b.known_bits)
        val.definitely_used_bits = _definitely_bits(a) | _definitely_bits(b)
        base_maybe = _maybe_bits(a) | _maybe_bits(b) | set(val.definitely_used_bits)
        lowest_candidate = None
        candidate_sources = list(a.candidate_bits) + list(b.candidate_bits)
        if candidate_sources:
            lowest_candidate = min(candidate_sources)
        if lowest_candidate is not None and lowest_candidate < val.bit_width:
            smeared = set(range(lowest_candidate, val.bit_width))
            val.candidate_bits = smeared
            val.maybe_used_bits = set(base_maybe | smeared)
        else:
            val.candidate_bits = set(base_maybe)
            val.maybe_used_bits = set(base_maybe)
        val.used_bits = set(val.definitely_used_bits)
        val.pointer_targets = set(a.pointer_targets | b.pointer_targets)
        val.pointer_patterns = []
        existing_ptr_sigs: Set[Tuple[Any, ...]] = set()

        def _append_pattern(ptr: PointerPattern) -> None:
            sig = ptr.signature()
            if sig not in existing_ptr_sigs:
                val.pointer_patterns.append(ptr)
                existing_ptr_sigs.add(sig)

        if vn_is_constant(inputs[1]):
            delta = vn_get_offset(inputs[1]) or 0
            for ptr in a.pointer_patterns:
                new_ptr = ptr.clone()
                new_ptr.adjust_offset(delta if opname == "INT_ADD" else -delta)
                _append_pattern(new_ptr)
            if a.pointer_targets:
                adj = delta
                val.pointer_targets = {p + (adj if opname == "INT_ADD" else -adj) for p in a.pointer_targets}
        elif vn_is_constant(inputs[0]):
            delta = vn_get_offset(inputs[0]) or 0
            for ptr in b.pointer_patterns:
                new_ptr = ptr.clone()
                new_ptr.adjust_offset(delta if opname == "INT_ADD" else -delta)
                _append_pattern(new_ptr)
            if b.pointer_targets:
                adj = delta
                val.pointer_targets = {p + (adj if opname == "INT_ADD" else -adj) for p in b.pointer_targets}
        elif a.pointer_patterns and b.pointer_patterns:
            for pa in a.pointer_patterns:
                for pb in b.pointer_patterns:
                    _append_pattern(pa.merge(pb))

        if not val.pointer_patterns:
            if vn_is_constant(inputs[1]) and a.pointer_targets:
                adj = vn_get_offset(inputs[1]) or 0
                val.pointer_targets = {p + (adj if opname == "INT_ADD" else -adj) for p in a.pointer_targets}
            elif vn_is_constant(inputs[0]) and b.pointer_targets:
                adj = vn_get_offset(inputs[0]) or 0
                val.pointer_targets = {p + (adj if opname == "INT_ADD" else -adj) for p in b.pointer_targets}
        self._set_val(out, val, states)

    def _handle_float(self, out, inputs, states, opname):
        if out is None or not inputs:
            return
        operands = [self._get_val(inp, states) for inp in inputs if inp is not None]
        if not operands:
            return
        val = operands[0].clone()
        for extra in operands[1:]:
            val = val.merge(extra)
        val.bit_width = out.getSize() * 8
        val.known_bits = KnownBits.top(val.bit_width)
        val.pointer_patterns = []
        val.pointer_targets = set()
        val.function_pointer_labels = set()
        val.mask_history = []
        if opname in {"FLOAT_NEG", "FLOAT_ABS"}:
            val.definitely_used_bits |= set(range(val.bit_width))
            val.maybe_used_bits |= set(range(val.bit_width))
        self._set_val(out, val, states)

    def _handle_multdiv(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        a = self._get_val(inputs[0], states)
        b = self._get_val(inputs[1], states)
        val = AbstractValue()
        val.tainted = a.tainted or b.tainted
        val.origins = set(a.origins | b.origins)
        val.control_taints = set(a.control_taints | b.control_taints)
        val.slot_sources = set(a.slot_sources | b.slot_sources)
        val.bit_width = out.getSize() * 8
        val.definitely_used_bits = _definitely_bits(a) | _definitely_bits(b)
        val.maybe_used_bits = _maybe_bits(a) | _maybe_bits(b) | set(val.definitely_used_bits)
        val.used_bits = set(val.definitely_used_bits)
        val.candidate_bits = set(val.maybe_used_bits)
        if a.pointer_patterns or b.pointer_patterns:
            val.pointer_patterns = [PointerPattern(unknown=True)]
        else:
            val.pointer_patterns = []
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
        val.control_taints = set(a.control_taints | b.control_taints)
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
        val.control_taints = set(base.control_taints | self._get_val(amt, states).control_taints)
        val.slot_sources = set(base.slot_sources | self._get_val(amt, states).slot_sources)
        val.bit_width = out.getSize() * 8
        val.known_bits = KnownBits.top(val.bit_width)
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
            if shift is not None:
                if opname == "INT_LEFT":
                    val.known_bits = base.known_bits.shift_left(shift)
                else:
                    val.known_bits = base.known_bits.shift_right(shift)
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
        val.control_taints = set(a.control_taints | b.control_taints)
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
        loaded = False
        for pattern in addr_val.pointer_patterns:
            key = slot_key_from_pattern(pattern)
            if not key:
                continue
            slot = states.memory.slots.get(key)
            if slot:
                slot_val = slot.value.clone()
                slot_val.slot_sources.add(key)
                if not loaded:
                    val = slot_val
                    loaded = True
                else:
                    val = val.merge(slot_val)

        val.control_taints |= set(addr_val.control_taints)

        # Enable constant propagation from read-only memory (e.g., IAT, .rdata)
        # to resolve indirect calls.
        # Allow 32-bit (4 bytes) or 64-bit (8 bytes) loads
        if out.getSize() in (4, 8) and not val.pointer_targets:
            targets = []
            if vn_is_constant(inputs[1]):
                targets.append(vn_get_offset(inputs[1]))
            elif addr_val.pointer_targets:
                targets.extend(sorted(addr_val.pointer_targets)[:5])
            
            for t in targets:
                if t is None: continue
                try:
                    src_addr = self.api.toAddr(t)
                    
                    # 1. Try reading pointer from memory (e.g. initialized globals)
                    ptr = self._read_pointer_value(src_addr)
                    if ptr is not None:
                        val.pointer_targets.add(ptr)
                        mapped = (IMPORTED_REGISTRY_API_ADDRS.get(ptr) or 
                                  IMPORTED_REGISTRY_API_ADDRS.get(str(ptr)))
                        if mapped:
                            val.function_pointer_labels.add(mapped)

                    # 2. Try resolving via Ghidra References (Critical for IAT/Externals)
                    ref_mgr = getattr(self.program, "getReferenceManager", lambda: None)()
                    if ref_mgr:
                        for ref in ref_mgr.getReferencesFrom(src_addr):
                            to_addr = ref.getToAddress()
                            if not to_addr: continue
                            
                            mapped = (IMPORTED_REGISTRY_API_ADDRS.get(to_addr.getOffset()) or 
                                      IMPORTED_REGISTRY_API_ADDRS.get(str(to_addr)))
                            if mapped:
                                val.function_pointer_labels.add(mapped)
                                val.pointer_targets.add(to_addr.getOffset())
                                continue
                            
                            if getattr(to_addr, "isExternalAddress", lambda: False)():
                                ext_label = self._external_label_for_address(to_addr)
                                if ext_label:
                                    norm = normalize_registry_label(ext_label)
                                    if norm:
                                        val.function_pointer_labels.add(norm)
                                        val.pointer_targets.add(to_addr.getOffset())

                except Exception:
                    pass

        self._set_val(out, val, states)

    def _handle_store(self, inst, inputs, states):
        if len(inputs) < 3: return
        
        addr_val = self._get_val(inputs[1], states)
        src_val = self._get_val(inputs[2], states)

        is_ambiguous = len(addr_val.pointer_patterns) > 1 or len(addr_val.pointer_targets) > 1
        updated_slots = dict(states.memory.slots)

        for pattern in addr_val.pointer_patterns:
            # --- Improvement: Byte-by-byte String Construction Detection ---
            # If we see STORE(Base + Offset, ConstantByte), we record it.
            if pattern.base_id and vn_is_constant(inputs[2]):
                try:
                    base_id = pattern.base_id
                    base_offset = pattern.offset or 0

                    width = inputs[2].getSize()
                    const_val = vn_get_offset(inputs[2]) or 0
                    bytes_le = const_val.to_bytes(width, byteorder=BYTE_ORDER, signed=False)

                    for idx, b in enumerate(bytes_le):
                        final_offset = base_offset + idx
                        if base_id not in self.global_state.heap_string_writes:
                            self.global_state.heap_string_writes[base_id] = {}
                        self.global_state.heap_string_writes[base_id][final_offset] = bytes([b])
                except Exception:
                    pass
            # -------------------------------------------------------------

            key = slot_key_from_pattern(pattern)
            if not key:
                continue

            new_slot_val = src_val.clone()
            new_slot_val.slot_sources.add(key)

            if addr_val.tainted or addr_val.origins or addr_val.control_taints:
                new_slot_val.tainted = True
                new_slot_val.origins |= addr_val.origins
                new_slot_val.control_taints |= addr_val.control_taints

            existing_slot = updated_slots.get(key)
            is_must_write = bool(
                not pattern.unknown
                and pattern.base_id is not None
                and pattern.offset is not None
                and pattern.index_var is None
            )

            base_storage = classify_storage(pattern.base_id)
            local_stack_overwrite = is_must_write and base_storage == "stack"

            strong_update = (
                is_must_write
                and (local_stack_overwrite or (not new_slot_val.tainted and not new_slot_val.origins))
                and not is_ambiguous
            )
            merged_slot_val = new_slot_val
            if existing_slot and not strong_update:
                merged_slot_val = existing_slot.value.merge(new_slot_val)
            merged_slot_val.slot_sources.add(key)

            merged_slot = StructSlot(
                pattern.base_id,
                key[1],
                pattern.stride,
                pattern.index_var,
                value=new_slot_val if strong_update and existing_slot else merged_slot_val,
            )
            updated_slots[key] = merged_slot

            slot = self.global_state.struct_slots.get(key)
            if slot is None:
                slot = merged_slot.clone()
                self.global_state.struct_slots[key] = slot
            else:
                if strong_update:
                    slot.value = new_slot_val.clone()
                else:
                    slot.value = slot.value.merge(merged_slot_val)
            slot.value.slot_sources.add(key)

            inst_func = self._get_function_for_inst(inst)
            func_name = inst_func.getName() if inst_func else "unknown"
            entry_str = str(inst_func.getEntryPoint()) if inst_func else str(inst.getAddress())

            self.global_state.function_summaries.setdefault(
                func_name, FunctionSummary(func_name, entry_str)
            ).slot_writes.append({
                "base_id": slot.base_id,
                "offset": slot.offset,
                "origins": sorted(slot.value.origins),
                "control_taints": sorted(slot.value.control_taints),
            })

            old_value = existing_slot.value if existing_slot else None
            if old_value and old_value.tainted and not src_val.tainted:
                if strong_update and not src_val.origins:
                    log_trace(
                        f"[trace] strong update cleared taint for {key} at {inst.getAddress()}"
                    )
                pass

        states.memory = MemoryState(updated_slots)

    def _handle_ptradd(self, func, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        base = self._get_val(inputs[0], states)
        offset = inputs[1]
        val = base.clone()
        val.bit_width = out.getSize() * 8
        if val.pointer_patterns:
            val.pointer_patterns = [p.clone() for p in val.pointer_patterns]
        else:
            base_id = pointer_base_identifier(func, inputs[0])
            val.pointer_patterns = [PointerPattern(base_id=base_id)]
            self._record_base_id_metadata(base_id, inputs[0])
        if vn_is_constant(offset):
            delta = vn_get_offset(offset) or 0
            for ptr in val.pointer_patterns:
                ptr.adjust_offset(delta)
        else:
            for ptr in val.pointer_patterns:
                ptr.index_var = varnode_key(offset) if offset is not None else None
                ptr.unknown = True
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
        if val.pointer_patterns:
            val.pointer_patterns = [p.clone() for p in val.pointer_patterns]
        else:
            base_id = pointer_base_identifier(func, inputs[0])
            val.pointer_patterns = [PointerPattern(base_id=base_id)]
            self._record_base_id_metadata(base_id, inputs[0])
        if vn_is_constant(offset):
            delta = vn_get_offset(offset) or 0
            for ptr in val.pointer_patterns:
                ptr.adjust_offset(-delta)
            if val.pointer_targets:
                val.pointer_targets = {p - delta for p in val.pointer_targets}
        else:
            for ptr in val.pointer_patterns:
                ptr.index_var = varnode_key(offset) if offset is not None else None
                ptr.unknown = True
            val.pointer_targets = set()
        self._set_val(out, val, states)

    def _handle_branch(self, func, inst, opname, inputs, states, summary: FunctionSummary):
        if opname != "CBRANCH" or not inputs:
            return
        cond_val = self._get_val(inputs[0], states)
        if self.mode == "taint" and not cond_val.origins and not cond_val.control_taints:
            log_trace(f"[trace] skipping untainted branch at {inst.getAddress()}")
            return
        if cond_val.tainted or cond_val.origins or cond_val.control_taints:
            states.control_taints |= set(cond_val.origins | cond_val.control_taints)
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
        if cond_val.origins:
            branch_detail["data_taints"] = sorted(cond_val.origins)
        if cond_val.control_taints:
            branch_detail["control_taints"] = sorted(cond_val.control_taints)
        if cond_val.origins or cond_val.slot_sources or cond_val.control_taints:
            summary.uses_registry = summary.uses_registry or bool(cond_val.origins or cond_val.control_taints)
        decision = Decision(
            address=str(inst.getAddress()),
            mnemonic=inst.getMnemonicString(),
            disasm=inst.toString(),
            origins=set(cond_val.origins),
            used_bits=set(used_bits),
            control_taints=set(cond_val.control_taints),
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
        
        # Determine arguments based on opcode
        is_branch_ind = (op.getOpcode() == PcodeOp.BRANCHIND)
        call_args = []
        if is_branch_ind:
            # BRANCHIND usually doesn't have explicit arguments in P-code like CALL
            # but we treat it as a potential tail-call.
            # We assume standard calling convention registers are already set if this is a tail call.
            pass
        else:
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
                if val.pointer_targets or val.pointer_patterns or val.function_pointer_labels:
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
            
            # If there's an output, taint it
            if op.getOutput() is not None:
                val = self._get_val(op.getOutput(), states)
                val.tainted = True
                val.origins.add(root_id)
                val.bit_width = op.getOutput().getSize() * 8
                self._set_val(op.getOutput(), val, states)
            
            # Taint pointer arguments
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
            if callee_name or detected_hkey_meta or string_args:
                log_debug(
                    f"[debug] call/jump at {inst.getAddress()} opname={opcode_name(op)} "
                    f"callee_name={callee_name!r} strings={len(string_args)} hkey={bool(detected_hkey_meta)}"
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
            callee_summaries = self._summaries_for(callee_name)
            for callee_summary in callee_summaries:
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
                        slot_val.value.control_taints |= set(slot.get("control_taints", []))
                        for origin in slot_val.value.origins:
                            self.global_state.root_slot_index[origin].add(key)
                        for origin in slot_val.value.control_taints:
                            self.global_state.root_slot_index[origin].add(key)
                    else:
                        origins = set(slot.get("origins", []))
                        control_taints = set(slot.get("control_taints", []))
                        if key[0] is not None and key[1] is not None:
                            self.global_state.struct_slots[key] = StructSlot(
                                key[0],
                                key[1],
                                value=AbstractValue(
                                    origins=origins,
                                    control_taints=control_taints,
                                    tainted=bool(origins or control_taints),
                                ),
                            )
                            for origin in origins:
                                self.global_state.root_slot_index[origin].add(key)
                            for origin in control_taints:
                                self.global_state.root_slot_index[origin].add(key)
                    if slot.get("origins") or slot.get("control_taints"):
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

    def _handle_return(self, func, inputs, states, summary: FunctionSummary):
        if not inputs:
            return
        ret_varnode = None
        try:
            func_ret = func.getReturn()
            storage = func_ret.getVariableStorage() if func_ret else None
            storage_vns = list(storage.getVarnodes()) if storage else []
            for vn in inputs:
                for sv in storage_vns:
                    try:
                        if vn.getAddress() == sv.getAddress() and vn.getSize() == sv.getSize():
                            ret_varnode = vn
                            break
                    except Exception:
                        continue
                if ret_varnode:
                    break
        except Exception:
            ret_varnode = None

        if ret_varnode is None:
            for vn in reversed(inputs):
                if vn is None or vn_is_constant(vn):
                    continue
                try:
                    if hasattr(vn, "isAddress") and vn.isAddress():
                        continue
                except Exception:
                    pass
                ret_varnode = vn
                break
        if ret_varnode is None:
            ret_varnode = inputs[-1]
        ret_val = self._get_val(ret_varnode, states)
        summary.return_influence |= set(ret_val.origins | ret_val.control_taints)

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
        if any(slot.get("origins") or slot.get("control_taints") for slot in summary.slot_writes):
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
    global DEFAULT_POINTER_BIT_WIDTH, PROGRAM_IS_BIG_ENDIAN, BYTE_ORDER
    DEFAULT_POINTER_BIT_WIDTH = _detect_pointer_bit_width(program)
    PROGRAM_IS_BIG_ENDIAN, BYTE_ORDER = _detect_endianness(program)
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