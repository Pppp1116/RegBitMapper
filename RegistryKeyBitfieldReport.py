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
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

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
    from ghidra.program.model.symbol import RefType
    from ghidra.util.task import TaskMonitor
except Exception:  # pragma: no cover
    FlatProgramAPI = None
    BasicBlockModel = None
    Instruction = None
    PcodeOp = None
    RefType = None
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


DEFAULT_POINTER_BIT_WIDTH = 32


def _detect_pointer_bit_width(program) -> int:
    try:
        lang = program.getLanguage()
        space = lang.getDefaultSpace() if hasattr(lang, "getDefaultSpace") else None
        if space:
            size_bytes = space.getPointerSize()
            if size_bytes:
                return int(size_bytes) * 8
    except Exception:
        return DEFAULT_POINTER_BIT_WIDTH
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
    pointer_targets: Set[int] = field(default_factory=set)

    def clone(self) -> "AbstractValue":
        return AbstractValue(
            tainted=self.tainted,
            origins=set(self.origins),
            bit_width=self.bit_width,
            used_bits=set(self.used_bits),
            candidate_bits=set(self.candidate_bits),
            pointer_pattern=self.pointer_pattern.clone() if self.pointer_pattern else None,
            pointer_targets=set(self.pointer_targets),
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
        merged.pointer_targets = set(self.pointer_targets | other.pointer_targets)
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
            frozenset(self.pointer_targets),
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
    analysis_stats: Dict[str, Any] = field(default_factory=dict)
    overrides: List[Dict[str, Any]] = field(default_factory=list)
    registry_strings: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    root_decision_index: Dict[str, List[Decision]] = field(default_factory=lambda: defaultdict(list))
    root_slot_index: Dict[str, Set[Tuple[str, int]]] = field(default_factory=lambda: defaultdict(set))
    root_override_index: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))


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


def pointer_base_identifier(func, vn) -> str:
    key = varnode_key(vn)
    func_name = func.getName() if func else "<unknown>"
    return f"{func_name}::{key}"


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
REGISTRY_RTL_REGISTRY_RE = re.compile(r"(?i)^rtl(?:query|write|create|open|delete|check|enumerate)registry")

REGISTRY_HIVE_ALIASES = {
    "HKLM": ["HKLM", "HKEY_LOCAL_MACHINE", "\\Registry\\Machine"],
    "HKCU": ["HKCU", "HKEY_CURRENT_USER", "\\Registry\\User"],
    "HKCR": ["HKCR", "HKEY_CLASSES_ROOT"],
    "HKU": ["HKU", "HKEY_USERS"],
    "HKCC": ["HKCC", "HKEY_CURRENT_CONFIG"],
}

REGISTRY_STRING_PREFIX_RE = re.compile(
    r"(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|\\\\Registry\\\\Machine|\\\\Registry\\\\User|\\\\Registry\\\\Users)",
    re.IGNORECASE,
)


def normalize_registry_label(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    cleaned = re.sub(r"(?i)^(?:__imp__?|imp_)", "", cleaned)
    # Keep suffixes that look registry-like, handling common separators and
    # mangled import labels such as ADVAPI32.dll::RegOpenKeyExA@16 or
    # ADVAPI32.dll_RegQueryValueExW.
    tokens: List[str] = []
    for part in re.split(r"[.:@!_\\/]", cleaned):
        for sub in part.split("::"):
            for seg in sub.split("_"):
                if seg:
                    tokens.append(seg)
    tokens = tokens or [cleaned]
    registry_re = re.compile(r"(?i)(reg|zw|nt|cm|rtl)[a-z0-9_@]*")
    for tok in tokens[::-1]:
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
    if normalized:
        lowered = normalized.lower()
        if any(lowered.startswith(pref.lower()) for pref in ("reg", "zw", "nt", "cm")):
            return True
        if lowered.startswith("rtl"):
            return bool(REGISTRY_RTL_REGISTRY_RE.match(lowered))

    return False


def parse_registry_string(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    raw = raw.strip("\x00").strip()
    if not raw:
        return None
    raw = raw.replace("/", "\\")
    # Trim leading junk before a known hive fragment if present.
    m = REGISTRY_STRING_PREFIX_RE.search(raw)
    hive_key = None
    path = None
    value_name = None
    candidate_segment = raw
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
        path = candidate_segment[len(prefix) :].lstrip("\\/")
    if path is None:
        lowered = raw.lower()
        partial_prefixes = [
            "\\registry\\machine\\",
            "\\registry\\user\\",
            "system\\currentcontrolset\\",
            "system\\controlset",
            "software\\",
            "control\\",
        ]
        for pref in partial_prefixes:
            pos = lowered.find(pref)
            if pos != -1:
                path = raw[pos:].lstrip("\\/")
                break
        if path is None and lowered.startswith(tuple(partial_prefixes)):
            path = raw.lstrip("\\/")
    if path is None:
        return None
    path = path.strip().strip("\x00")
    if not path:
        return None
    path = path.strip("\0\r\n \t\"")
    if path and "\\" in path:
        parts = [p for p in path.split("\\") if p]
        if parts:
            value_name = parts[-1]
            path = "\\".join(parts)
    return {"hive": hive_key, "path": path, "value_name": value_name, "raw": raw}


def collect_registry_string_candidates(program, scan_limit: Optional[int] = None) -> Dict[str, Dict[str, Any]]:
    listing = program.getListing()
    candidates: Dict[str, Dict[str, Any]] = {}
    max_scan = scan_limit if scan_limit is not None else 100_000
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
        if max_scan and scanned > max_scan:
            log_debug("[debug] registry string candidate scan capped for performance")
            break
        try:
            sval: Optional[str] = None
            if data.hasStringValue():
                try:
                    val_obj = data.getValue()
                    sval = val_obj.getString() if hasattr(val_obj, "getString") else str(val_obj)
                except Exception:
                    sval = None
            if sval is None:
                try:
                    mem = program.getMemory()
                    buf = bytearray(max(16, data.getLength()))
                    read = mem.getBytes(data.getAddress(), buf)
                    if read:
                        trimmed = bytes(buf[: int(read) if isinstance(read, (int, float)) else len(buf)])
                        for codec, terminator in (("utf-16-le", b"\x00\x00"), ("utf-8", b"\x00"), ("latin-1", b"\x00")):
                            try:
                                segment = trimmed.split(terminator)[0]
                                if not segment:
                                    continue
                                sval = segment.decode(codec, errors="ignore")
                                if sval:
                                    break
                            except Exception:
                                continue
                except Exception:
                    sval = None
            if not sval:
                continue
            meta = parse_registry_string(sval)
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


# ---------------------------------------------------------------------------
# Core analysis engine
# ---------------------------------------------------------------------------


class FunctionAnalyzer:
    def __init__(self, api: FlatProgramAPI, program, global_state: GlobalState, mode: str, max_call_depth: Optional[int] = None):
        self.api = api
        self.global_state = global_state
        self.mode = mode
        self.max_steps = 5_000_000
        self.max_function_iterations = 250_000
        self.max_call_depth = max_call_depth
        self.program = program
        # Reuse a single BasicBlockModel for the program (safe for Ghidra 12).
        self.block_model = BasicBlockModel(self.program)
        self.monitor = ACTIVE_MONITOR or DUMMY_MONITOR

    def _get_function_for_inst(self, inst: Instruction):
        try:
            fm = self.program.getFunctionManager()
            return fm.getFunctionContaining(inst.getAddress())
        except Exception:
            return None

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
                decoded = self._decode_string_at_address(addr, addr_str)
                if decoded:
                    return decoded
        return self._decode_string_at_address(addr, addr_str)

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
            mem = self.program.getMemory()
            buf = bytearray(512)
            read = mem.getBytes(addr, buf)
            if read is None:
                return None
            trimmed = bytes(buf[: int(read) if isinstance(read, (int, float)) else len(buf)])
            candidates: List[str] = []
            for codec, terminator in (("utf-16-le", b"\x00\x00"), ("utf-8", b"\x00"), ("latin-1", b"\x00")):
                try:
                    segment = trimmed.split(terminator)[0].lstrip(b"\x00")
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
        except Exception as e:
            if DEBUG_ENABLED:
                log_debug(f"[debug] error decoding string at {addr_str}: {e!r}")
            return None
        return None

    def analyze_all(self) -> None:
        fm = self.program.getFunctionManager()
        worklist = deque((func, 0) for func in fm.getFunctions(True))
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
                worklist.extend((callee, depth + 1) for callee in func.getCalledFunctions(self.monitor))
            else:
                if existing.merge_from(summary):
                    worklist.extend((callee, depth + 1) for callee in func.getCalledFunctions(self.monitor))
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
            self._handle_orxor(out, inputs, states)
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
        val.bit_width = out.getSize() * 8
        val.used_bits = set(a.used_bits | b.used_bits)
        val.candidate_bits = set(a.candidate_bits | b.candidate_bits)
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
        val.bit_width = out.getSize() * 8
        val.used_bits = set(a.used_bits | b.used_bits)
        val.candidate_bits = set(a.candidate_bits | b.candidate_bits)
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
        val.bit_width = out.getSize() * 8
        val.used_bits = set(a.used_bits | b.used_bits)
        val.candidate_bits = set(a.candidate_bits | b.candidate_bits)
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
        val.pointer_targets = set(a.pointer_targets | b.pointer_targets)
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
        val.pointer_targets = set(base.pointer_targets)
        shift = vn_get_offset(amt)
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
            if shift != 0:
                val.pointer_targets = set()
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
        old_value = None
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
                old_value = slot.value.clone()
                slot.value = old_value.merge(src_val)
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

    def _handle_ptradd(self, func, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        base = self._get_val(inputs[0], states)
        offset = inputs[1]
        val = base.clone()
        if val.pointer_pattern is None:
            val.pointer_pattern = PointerPattern(base_id=pointer_base_identifier(func, inputs[0]))
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
        if val.pointer_pattern is None:
            val.pointer_pattern = PointerPattern(base_id=pointer_base_identifier(func, inputs[0]))
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
        if not cond_val.candidate_bits and not cond_val.used_bits:
            cond_val.mark_all_bits_used()
            branch_detail["bit_heuristic"] = "all_bits_marked"
        decision = Decision(
            address=str(inst.getAddress()),
            mnemonic=inst.getMnemonicString(),
            disasm=inst.toString(),
            origins=set(cond_val.origins),
            used_bits=set(cond_val.used_bits or cond_val.candidate_bits),
            details=branch_detail,
        )
        decision.details["branch_kind"] = "conditional"
        summary.add_decision(decision)
        self.global_state.decisions.append(decision)
        for origin in decision.origins:
            self.global_state.root_decision_index[origin].append(decision)

    def _handle_multiequal(self, out, inputs, states):
        if out is None:
            return
        merged = AbstractValue()
        for inp in inputs:
            merged = merged.merge(self._get_val(inp, states))
        merged.bit_width = out.getSize() * 8
        self._set_val(out, merged, states)

    def _handle_indirect(self, out, inputs, states):
        if out is None or not inputs:
            return
        val = AbstractValue(bit_width=out.getSize() * 8)
        for inp in inputs:
            val = val.merge(self._get_val(inp, states))
        self._set_val(out, val, states)

    def _handle_call(self, func, inst, op: PcodeOp, inputs, states, summary: FunctionSummary):
        call_args = inputs[1:] if inputs else []
        string_args: List[Dict[str, Any]] = []
        for inp in call_args:
            meta = self._resolve_string_from_vn(inp, states)
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

        def _pointerish_argument(vn, val: AbstractValue) -> bool:
            try:
                if val.pointer_targets or val.pointer_pattern:
                    return True
                if vn is None:
                    return False
                if vn_has_address(vn):
                    return True
                if not vn_is_constant(vn) and vn.getSize() * 8 >= DEFAULT_POINTER_BIT_WIDTH:
                    return True
            except Exception as e:
                if DEBUG_ENABLED:
                    log_debug(f"[debug] error checking pointer-like argument at {inst.getAddress()}: {e!r}")
            return False

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
            for arg in call_args:
                arg_val = self._get_val(arg, states)
                if _pointerish_argument(arg, arg_val):
                    arg_val.tainted = True
                    arg_val.origins.add(root_id)
                    self._set_val(arg, arg_val, states)
        for idx, inp in enumerate(call_args):
            arg_val = self._get_val(inp, states)
            if arg_val.origins:
                summary.param_influence[idx] |= set(arg_val.origins)
        callee_name = None
        callee_func = None

        # Be liberal: for imported functions the reference type may not report
        # isCall(), so scan all refs and ask FunctionManager if the target is
        # a function. This works better for IAT/thunks on PE files.
        refs = []
        try:
            ref_mgr = self.program.getReferenceManager()
            refs = list(ref_mgr.getReferencesFrom(inst.getAddress())) if ref_mgr else []
        except Exception:
            refs = []
        fm = self.program.getFunctionManager()
        for r in refs:
            try:
                to_addr = r.getToAddress()
                if to_addr is None:
                    continue
                f = fm.getFunctionAt(to_addr)
                if f is not None:
                    # Resolve through thunk if needed.
                    if getattr(f, "isThunk", lambda: False)():
                        thunk_target = getattr(f, "getThunkedFunction", lambda: None)()
                        if thunk_target:
                            f = thunk_target
                    callee_func = f
                    callee_name = f.getName()
                    break
            except Exception as e:
                if DEBUG_ENABLED:
                    log_debug(f"[debug] error resolving call reference at {inst.getAddress()}: {e!r}")
                continue

        # Fallback: external location label if no direct function was found.
        if callee_name is None:
            for r in refs:
                try:
                    if hasattr(r, "isExternalReference") and r.isExternalReference():
                        ext_loc = r.getExternalLocation()
                        if ext_loc:
                            callee_name = ext_loc.getLabel() or ext_loc.getOriginalImportedName()
                            if callee_name:
                                break
                except Exception as e:
                    if DEBUG_ENABLED:
                        log_debug(f"[debug] error resolving external reference at {inst.getAddress()}: {e!r}")
                    continue

        # P-code input 0 often carries the callee address for direct CALL
        # sites. Use it as another hint when reference metadata is sparse.
        if callee_name is None and inputs:
            target_vn = inputs[0]
            if target_vn is not None:
                try:
                    target_addr = None
                    if hasattr(target_vn, "getAddress"):
                        target_addr = target_vn.getAddress()
                    if target_addr is None and vn_is_constant(target_vn):
                        off = vn_get_offset(target_vn)
                        if off is not None:
                            target_addr = self.api.toAddr(off)
                    if target_addr is not None:
                        func_at_target = fm.getFunctionAt(target_addr)
                        if func_at_target:
                            if getattr(func_at_target, "isThunk", lambda: False)():
                                thunk_target = getattr(func_at_target, "getThunkedFunction", lambda: None)()
                                if thunk_target:
                                    func_at_target = thunk_target
                            callee_func = func_at_target
                            callee_name = func_at_target.getName()
                except Exception as e:
                    if DEBUG_ENABLED:
                        log_debug(f"[debug] error inferring call target at {inst.getAddress()}: {e!r}")
                    pass

        if DEBUG_ENABLED:
            log_debug(
                f"[debug] call at {inst.getAddress()} opname={opcode_name(op)} "
                f"callee_name={callee_name!r} refs={len(refs)}"
            )
        normalized_api_label = normalize_registry_label(callee_name) if callee_name else None
        label_fragment = normalized_api_label or callee_name or "<indirect>"
        safe_label = re.sub(r"[^A-Za-z0-9_]+", "_", label_fragment)
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
            api_label = normalized_api_label or callee_name
            if is_registry_api(callee_name):
                root_id = f"api_{safe_label}_{inst.getAddress()}"
                # Prefer the resolved callee entrypoint when tying registry roots to call sites.
                entry_point = str(callee_func.getEntryPoint()) if callee_func else None
                _seed_root(root_id, api_label, entry_point)
            elif string_args:
                root_id = f"api_like_{safe_label}_{inst.getAddress()}"
                # Prefer the resolved callee entrypoint when available; otherwise fall back to the call site.
                entry_point = str(callee_func.getEntryPoint()) if callee_func else None
                _seed_root(root_id, api_label or "<unknown>", entry_point)
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
        for key in sorted(global_state.root_slot_index.get(root_id, set())):
            slot = global_state.struct_slots.get(key)
            if slot is None:
                continue
            base_id, offset = key
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
    global_state = GlobalState()
    # ensure call_depth_limit is explicitly initialized (future use)
    global_state.analysis_stats["call_depth_limit"] = False
    scan_limit = args.get("registry_scan_limit")
    if scan_limit is not None and scan_limit < 0:
        scan_limit = None
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
