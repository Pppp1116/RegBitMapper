import types
import unittest

import RegistryKeyBitfieldReport as report
from RegistryKeyBitfieldReport import AbstractValue, AnalysisState, FunctionAnalyzer, GlobalState, KnownBits, varnode_key


class DummyVarnode:
    def __init__(self, size, offset=0, space="unique", is_constant=False):
        self._size = size
        self._offset = offset
        self._space = space
        self._const = is_constant

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
        return None


class KnownBitsShiftTests(unittest.TestCase):
    def setUp(self):
        if not getattr(report, "PcodeOp", None):
            report.PcodeOp = types.SimpleNamespace(SUBPIECE=1)
        elif not hasattr(report.PcodeOp, "SUBPIECE"):
            report.PcodeOp.SUBPIECE = 1

    def test_shift_right_arithmetic_negative_fills_ones(self):
        kb = KnownBits(bit_width=8, known_ones=0x80, known_zeros=0)
        shifted = kb.shift_right_arithmetic(2)
        self.assertEqual(shifted.known_ones & 0xFF, 0xE0)
        self.assertEqual(shifted.known_zeros & 0xFF, 0)

    def test_shift_right_arithmetic_positive_fills_zeros(self):
        kb = KnownBits(bit_width=8, known_ones=0x00, known_zeros=0x80)
        shifted = kb.shift_right_arithmetic(3)
        self.assertEqual(shifted.known_zeros & 0xFF, 0xF0)
        self.assertEqual(shifted.known_ones & 0xFF, 0)

    def test_shift_right_arithmetic_unknown_sign_keeps_unknown(self):
        kb = KnownBits(bit_width=8, known_ones=0, known_zeros=0)
        shifted = kb.shift_right_arithmetic(1)
        self.assertEqual(shifted.known_zeros & 0xFF, 0)
        self.assertEqual(shifted.known_ones & 0xFF, 0)

    def test_handle_shift_uses_arithmetic_shift(self):
        analyzer = FunctionAnalyzer(api=None, program=None, global_state=GlobalState(), mode="taint")
        states = AnalysisState()
        base_vn = DummyVarnode(size=1, offset=0x10)
        amt_vn = DummyVarnode(size=1, offset=2, space="const", is_constant=True)
        out_vn = DummyVarnode(size=1, offset=0x20)

        base_val = AbstractValue(bit_width=8, known_bits=KnownBits(bit_width=8, known_ones=0x80, known_zeros=0))
        states.values[varnode_key(base_vn)] = base_val

        analyzer._handle_shift(out_vn, [base_vn, amt_vn], states, "INT_SRIGHT")

        result = states.values[varnode_key(out_vn)]
        self.assertEqual(result.known_bits.known_ones & 0xFF, 0xE0)
        self.assertEqual(result.known_bits.known_zeros & 0xFF, 0)


if __name__ == "__main__":
    unittest.main()
