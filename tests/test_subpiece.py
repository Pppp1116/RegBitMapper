import types
import unittest

import RegistryKeyBitfieldReport as report
from RegistryKeyBitfieldReport import AbstractValue, AnalysisState, FunctionAnalyzer, GlobalState, KnownBits, varnode_key


class DummyOp:
    def __init__(self, opcode):
        self._opcode = opcode

    def getOpcode(self):
        return self._opcode


class DummyVarnode:
    def __init__(self, size, offset=0, space="unique", is_constant=False, def_op=None):
        self._size = size
        self._offset = offset
        self._space = space
        self._const = is_constant
        self._def = def_op

    def getSize(self):
        return self._size

    def getOffset(self):
        return self._offset

    def isRegister(self):
        return False

    def isUnique(self):
        return self._space == "unique"

    def isConstant(self):
        return self._const

    def isAddress(self):
        return self._space in {"stack", "ram"}

    def isAddrTied(self):
        return self.isAddress()

    def getAddress(self):
        return None

    def getDef(self):
        return self._def


class SubpieceHandlingTests(unittest.TestCase):
    def setUp(self):
        # Ensure a minimal PcodeOp stub exists for unit tests
        if not getattr(report, "PcodeOp", None):
            report.PcodeOp = types.SimpleNamespace(SUBPIECE=1)
        elif not hasattr(report.PcodeOp, "SUBPIECE"):
            report.PcodeOp.SUBPIECE = 1
        self.analyzer = FunctionAnalyzer(api=None, program=None, global_state=GlobalState(), mode="taint")
        self.state = AnalysisState()

    def test_subpiece_shifts_bits_and_known_bits(self):
        src = DummyVarnode(size=4, offset=0x10, space="unique")
        out = DummyVarnode(size=2, offset=0x20, space="unique", def_op=DummyOp(report.PcodeOp.SUBPIECE))
        byte_offset = DummyVarnode(size=1, offset=1, space="const", is_constant=True)

        src_val = AbstractValue(bit_width=32, known_bits=KnownBits.from_constant(32, 0xFF00))
        src_val.used_bits = {8, 9, 10, 11, 20}
        src_val.candidate_bits = set(src_val.used_bits)
        src_val.definitely_used_bits = set(src_val.used_bits)
        src_val.maybe_used_bits = set(src_val.used_bits)
        src_val.pointer_targets = {0x1000}

        self.state.values[varnode_key(src)] = src_val

        self.analyzer._handle_copy(out, [src, byte_offset], self.state)

        result = self.state.values[varnode_key(out)]
        self.assertEqual(result.used_bits, {0, 1, 2, 3, 12})
        self.assertEqual(result.definitely_used_bits, {0, 1, 2, 3, 12})
        self.assertEqual(result.candidate_bits, {0, 1, 2, 3, 12})
        self.assertEqual(result.known_bits.known_ones & 0xFFFF, 0x00FF)
        self.assertEqual(result.pointer_targets, set())
        self.assertEqual(result.pointer_patterns, [])


if __name__ == "__main__":
    unittest.main()
