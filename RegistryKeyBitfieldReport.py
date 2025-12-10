# coding: utf-8
"""
RegistryKeyBitfieldReport (PyGhidra / Python 3.x)

This script is intended for Ghidra 12 with the PyGhidra CPython bridge. It is
not a Jython script and must not subclass ``GhidraScript``. Run it using a
command like:

py -3.11 -m pyghidra ^
  --project-path "C:\\GhidraProjects\\RegMap" ^
  --project-name "MyProj" ^
  "C:\\path\\to\\target.exe" ^
  "C:\\path\\to\\RegistryKeyBitfieldReport.py" ^
  mode=taint debug=true trace=false

Arguments (key=value):
  mode  : "taint" (registry/config seeded) or "full" (analyze all flows).
  debug : verbose summaries (true/false/1/0/yes/no/on/off).
  trace : per-step traces (true/false/1/0/yes/no/on/off).

The analysis treats assembly as authoritative for reporting addresses/mnemonics
and uses p-code as the semantic IR for dataflow.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    from ghidra import currentProgram
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.program.model.pcode import PcodeOp
except Exception:  # pragma: no cover - executed inside Ghidra
    currentProgram = None
    FlatProgramAPI = None
    BasicBlockModel = None
    PcodeOp = None

# ---------------------------------------------------------------------------
# Argument parsing and logging
# ---------------------------------------------------------------------------


def _parse_bool(val: str) -> bool:
    if val is None:
        return False
    val = val.strip().lower()
    return val in {"1", "true", "yes", "on"}


def parse_args(raw_args: List[str]) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    for arg in raw_args:
        if "=" not in arg:
            continue
        k, v = arg.split("=", 1)
        parsed[k.strip().lower()] = v
    if "mode" not in parsed or parsed["mode"] not in {"taint", "full"}:
        print("[error] mode argument missing or invalid (expected mode=taint|full)")
        sys.exit(1)
    parsed["debug"] = _parse_bool(parsed.get("debug", "false"))
    parsed["trace"] = _parse_bool(parsed.get("trace", "false"))
    return parsed


args = parse_args(sys.argv[1:]) if len(sys.argv) > 1 else {}
DEBUG_ENABLED = args.get("debug", False)
TRACE_ENABLED = args.get("trace", False)


def log_info(msg: str) -> None:
    print(msg)


def log_debug(msg: str) -> None:
    if DEBUG_ENABLED:
        print(msg)


def log_trace(msg: str) -> None:
    if TRACE_ENABLED:
        print(msg)


if currentProgram is None:
    print("RegistryKeyBitfieldReport must be run under PyGhidra (currentProgram required).")
    sys.exit(1)


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
        existing_slots = list(self.slot_writes)
        for slot in other.slot_writes:
            if slot not in existing_slots:
                self.slot_writes.append(slot)
                changed = True
        existing_dec = [d.to_dict() for d in self.decisions]
        for d in other.decisions:
            if d.to_dict() not in existing_dec:
                self.decisions.append(d)
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


def new_value_from_varnode(vn) -> AbstractValue:
    width = vn.getSize() * 8 if vn else 32
    val = AbstractValue(bit_width=width)
    if vn and vn.isConstant():
        val.tainted = False
    return val


# ---------------------------------------------------------------------------
# Registry root detection
# ---------------------------------------------------------------------------


REGISTRY_PREFIXES = ["Reg", "Zw", "Nt", "Cm"]


def is_registry_api(name: str) -> bool:
    for pref in REGISTRY_PREFIXES:
        if name.startswith(pref):
            return True
    return False


def discover_registry_roots(api: FlatProgramAPI) -> Dict[str, Dict[str, Any]]:
    roots: Dict[str, Dict[str, Any]] = {}
    root_counter = 0
    fm = api.getFunctionManager()
    for func in fm.getFunctions(True):
        name = func.getName()
        if not is_registry_api(name):
            continue
        root_id = f"root_{root_counter:03d}"
        root_counter += 1
        roots[root_id] = {
            "id": root_id,
            "type": "registry",
            "api_name": name,
            "entry": str(func.getEntryPoint()),
            "details": {},
        }
    return roots


# ---------------------------------------------------------------------------
# Core analysis engine
# ---------------------------------------------------------------------------


class FunctionAnalyzer:
    def __init__(self, api: FlatProgramAPI, global_state: GlobalState, mode: str):
        self.api = api
        self.global_state = global_state
        self.mode = mode
        self.max_steps = 10_000_000

    def analyze_all(self) -> None:
        fm = self.api.getFunctionManager()
        worklist = deque(fm.getFunctions(True))
        iteration_guard = 0
        while worklist and iteration_guard < 1_000_000:
            func = worklist.popleft()
            iteration_guard += 1
            summary = self.analyze_function(func)
            self.global_state.analysis_stats["functions_analyzed"] += 1
            existing = self.global_state.function_summaries.get(func.getName())
            if existing is None:
                self.global_state.function_summaries[func.getName()] = summary
                worklist.extend(func.getCalledFunctions(None))
            else:
                if existing.merge_from(summary):
                    worklist.extend(func.getCalledFunctions(None))
        if iteration_guard >= 1_000_000:
            log_debug("[warn] function iteration limit hit")
            self.global_state.analysis_stats["function_iterations_limit"] = True

    def analyze_function(self, func) -> FunctionSummary:
        summary = FunctionSummary(func.getName(), str(func.getEntryPoint()))
        body = func.getBody()
        listing = self.api.getCurrentProgram().getListing()
        states: Dict[Tuple, AbstractValue] = {}
        block_model = BasicBlockModel(currentProgram)
        blocks = list(block_model.getCodeBlocksContaining(body, self.api.getMonitor()))
        worklist: deque = deque(blocks)
        visited = 0
        while worklist and visited < self.max_steps:
            block = worklist.popleft()
            visited += 1
            it = listing.getInstructions(block, True)
            while it.hasNext():
                inst = it.next()
                pcode_ops = inst.getPcode()
                for op in pcode_ops:
                    self._process_pcode(func, inst, op, states, summary)
        if visited >= self.max_steps:
            log_debug("[warn] worklist limit hit in function %s" % func.getName())
            self.global_state.analysis_stats["worklist_limit"] = True
        return summary

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
        log_trace(f"[trace] set {key} -> {val}")

    def _process_pcode(self, func, inst, op: PcodeOp, states: Dict[Tuple, AbstractValue], summary: FunctionSummary) -> None:
        opcode = op.getOpcode()
        out = op.getOutput()
        inputs = [op.getInput(i) for i in range(op.getNumInputs())]
        opname = op.getMnemonic()
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
            self._handle_ptradd(out, inputs, states)
        elif opname in {"BRANCH", "CBRANCH"}:
            self._handle_branch(func, inst, inputs, states, summary)
        elif opname == "MULTIEQUAL":
            self._handle_multiequal(out, inputs, states)
        elif opname == "CALL":
            self._handle_call(inst, op, inputs, states, summary)
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
            pp.adjust_offset(delta)
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
            for b in base.candidate_bits:
                if opname == "INT_LEFT":
                    val.candidate_bits.add(b + shift)
                else:
                    new_b = max(0, b - shift)
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
        if len(inputs) < 2:
            return
        addr_val = self._get_val(inputs[1], states)
        src_val = self._get_val(inputs[0], states)
        if addr_val.pointer_pattern and addr_val.pointer_pattern.base_id and addr_val.pointer_pattern.offset is not None:
            key = (addr_val.pointer_pattern.base_id, addr_val.pointer_pattern.offset)
            slot = self.global_state.struct_slots.get(key)
            if slot is None:
                slot = StructSlot(addr_val.pointer_pattern.base_id, addr_val.pointer_pattern.offset,
                                  addr_val.pointer_pattern.stride, addr_val.pointer_pattern.index_var,
                                  value=src_val.clone())
                self.global_state.struct_slots[key] = slot
            else:
                slot.value = slot.value.merge(src_val)
            self.global_state.function_summaries.setdefault(
                inst.getFunction().getName() if inst.getFunction() else "unknown", FunctionSummary(
                    inst.getFunction().getName() if inst.getFunction() else "unknown", str(inst.getAddress())
                )
            ).slot_writes.append(
                {
                    "base_id": slot.base_id,
                    "offset": slot.offset,
                    "origins": sorted(slot.value.origins),
                }
            )
            if slot.value.tainted and not src_val.tainted:
                self.global_state.overrides.append({
                    "address": str(inst.getAddress()),
                    "function": inst.getFunction().getName() if inst.getFunction() else None,
                    "source_origins": sorted(src_val.origins),
                    "notes": "struct slot override",
                })

    def _handle_ptradd(self, out, inputs, states):
        if out is None or len(inputs) < 2:
            return
        base = self._get_val(inputs[0], states)
        offset = inputs[1]
        val = base.clone()
        if val.pointer_pattern is None:
            val.pointer_pattern = PointerPattern(base_id=str(inputs[0]))
        if offset.isConstant():
            val.pointer_pattern.adjust_offset(int(offset.getOffset()))
        else:
            val.pointer_pattern.unknown = True
        self._set_val(out, val, states)

    def _handle_branch(self, func, inst, inputs, states, summary: FunctionSummary):
        if not inputs:
            return
        cond_val = self._get_val(inputs[0], states)
        if not cond_val.candidate_bits:
            cond_val.mark_all_bits_used()
        decision = Decision(
            address=str(inst.getAddress()),
            mnemonic=inst.getMnemonicString(),
            disasm=inst.toString(),
            origins=set(cond_val.origins),
            used_bits=set(cond_val.used_bits or cond_val.candidate_bits),
            details={"type": "branch"},
        )
        summary.decisions.append(decision)
        self.global_state.decisions.append(decision)

    def _handle_multiequal(self, out, inputs, states):
        if out is None:
            return
        merged = AbstractValue()
        for inp in inputs:
            merged = merged.merge(self._get_val(inp, states))
        merged.bit_width = out.getSize() * 8
        self._set_val(out, merged, states)

    def _handle_call(self, inst, op, inputs, states, summary: FunctionSummary):
        callee_refs = [r for r in inst.getReferencesFrom() if r.getReferenceType().isCall()]
        callee_name = None
        if callee_refs:
            to_addr = callee_refs[0].getToAddress()
            func = self.api.getFunctionManager().getFunctionAt(to_addr)
            if func:
                callee_name = func.getName()
        if callee_name:
            callee_summary = self.global_state.function_summaries.get(callee_name)
            if callee_summary:
                for idx, roots in callee_summary.param_influence.items():
                    if idx < len(inputs):
                        val = self._get_val(inputs[idx], states)
                        val.origins |= roots
                        val.tainted = val.tainted or bool(roots)
                if callee_summary.return_influence and op.getOutput() is not None:
                    val = AbstractValue(tainted=True, origins=set(callee_summary.return_influence),
                                        bit_width=op.getOutput().getSize() * 8)
                    self._set_val(op.getOutput(), val, states)
                for slot in callee_summary.slot_writes:
                    key = (slot.get("base_id"), slot.get("offset"))
                    slot_val = self.global_state.struct_slots.get(key)
                    if slot_val:
                        slot_val.value.origins |= set(slot.get("origins", []))
            if is_registry_api(callee_name):
                root_id = f"api_{callee_name}_{inst.getAddress()}"
                self.global_state.roots.setdefault(root_id, {
                    "id": root_id,
                    "type": "registry",
                    "api_name": callee_name,
                    "address": str(inst.getAddress()),
                })
                if op.getOutput() is not None:
                    val = self._get_val(op.getOutput(), states)
                    val.tainted = True
                    val.origins.add(root_id)
                    self._set_val(op.getOutput(), val, states)
        else:
            if op.getOutput() is not None:
                out_val = AbstractValue(bit_width=op.getOutput().getSize() * 8)
                for inp in inputs:
                    src = self._get_val(inp, states)
                    out_val = out_val.merge(src)
                self._set_val(op.getOutput(), out_val, states)

    def _handle_return(self, inputs, states, summary: FunctionSummary):
        if not inputs:
            return
        ret_val = self._get_val(inputs[0], states)
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


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def build_root_records(global_state: GlobalState) -> List[Dict[str, Any]]:
    records = []
    for root_id, meta in sorted(global_state.roots.items()):
        slot_entries = []
        used_bits: Set[int] = set()
        candidate_bits: Set[int] = set()
        for (base_id, offset), slot in global_state.struct_slots.items():
            if slot.value.origins and root_id in slot.value.origins:
                slot_entries.append({
                    "base_id": base_id,
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "stride": slot.stride,
                    "index_based": bool(slot.index_var),
                    "notes": "struct slot",
                })
                used_bits |= slot.value.used_bits
                candidate_bits |= slot.value.candidate_bits
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
                "bit_width": max([32] + [slot.value.bit_width for slot in global_state.struct_slots.values()]),
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
    """Print actionable suggestions to guide analysts toward better coverage."""
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
        suggestions.append(
            "Worklist iteration hit its safety limit; raise max_steps or refine CFG traversal to reach a fixpoint."
        )
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
    api = FlatProgramAPI(currentProgram)
    mode = args.get("mode")
    log_info(f"[info] RegistryKeyBitfieldReport starting (mode={mode}, debug={DEBUG_ENABLED}, trace={TRACE_ENABLED})")
    global_state = GlobalState()
    global_state.roots = discover_registry_roots(api)
    if mode == "full" and not global_state.roots:
        # ensure at least one synthetic root so all flows are kept
        global_state.roots["root_synthetic"] = {"id": "root_synthetic", "type": "synthetic", "details": {}}
    analyzer = FunctionAnalyzer(api, global_state, mode)
    analyzer.analyze_all()
    emit_ndjson(global_state)
    emit_improvement_suggestions(global_state)
    log_debug(
        f"[debug] analyzed {len(global_state.function_summaries)} functions, "
        f"roots={len(global_state.roots)} decisions={len(global_state.decisions)} "
        f"slots={len(global_state.struct_slots)}"
    )


if __name__ == "__main__":
    main()
