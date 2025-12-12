import unittest

from RegistryKeyBitfieldReport import (
    AbstractValue,
    AnalysisState,
    FunctionAnalyzer,
    GlobalState,
    KnownBits,
    varnode_key,
)


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


class KnownBitsAddTests(unittest.TestCase):
    def test_add_constant_values_remains_precise(self):
        left = KnownBits.from_constant(4, 0b0010)
        right = KnownBits.from_constant(4, 0b0010)

        result = left.add_bits(right)

        self.assertEqual(result.known_ones & 0xF, 0b0100)
        self.assertEqual(result.known_zeros & 0xF, 0b1011)

    def test_unknown_low_bit_does_not_pollute_high_bits(self):
        left = KnownBits(bit_width=4, known_zeros=0b1110, known_ones=0)
        right = KnownBits.from_constant(4, 0b0010)

        result = left.add_bits(right)

        self.assertEqual(result.known_ones & 0xF, 0b0010)
        self.assertEqual(result.known_zeros & 0xF, 0b1100)


class CallOtherTests(unittest.TestCase):
    def test_callother_propagates_taint(self):
        analyzer = FunctionAnalyzer(api=None, program=None, global_state=GlobalState(), mode="taint")
        states = AnalysisState()

        input_vn = DummyVarnode(size=1, offset=0x10)
        output_vn = DummyVarnode(size=1, offset=0x20)

        tainted_val = AbstractValue(bit_width=8, known_bits=KnownBits.top(8))
        tainted_val.is_bottom = False
        tainted_val.tainted = True
        tainted_val.origins.add("src")
        states.values[varnode_key(input_vn)] = tainted_val

        analyzer._handle_callother(output_vn, [input_vn], states)

        result = states.values[varnode_key(output_vn)]
        self.assertTrue(result.tainted)
        self.assertTrue(result.bit_usage_degraded)
        self.assertEqual(result.known_bits.known_ones, 0)
        self.assertEqual(result.known_bits.known_zeros, 0)
        self.assertTrue(analyzer.global_state.analysis_stats.get("bit_precision_degraded", False))


if __name__ == "__main__":
    unittest.main()
