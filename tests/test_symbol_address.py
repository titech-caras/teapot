import unittest

import gtirb

from teapot.utils.misc import symbol_address


class SymbolAddressTests(unittest.TestCase):
    def test_block_symbols(self):
        interval = gtirb.ByteInterval(address=0x1000, size=32)
        for block_type in (gtirb.CodeBlock, gtirb.DataBlock):
            for at_end in (False, True):
                with self.subTest(block_type=block_type, at_end=at_end):
                    block = block_type(offset=8, size=16, byte_interval=interval)
                    symbol = gtirb.Symbol("bound", payload=block, at_end=at_end)
                    self.assertEqual(symbol_address(symbol), 0x1018 if at_end else 0x1008)

    def test_integral_zero_is_an_address(self):
        self.assertEqual(symbol_address(gtirb.Symbol("zero", payload=0)), 0)

    def test_unresolved_symbols(self):
        for payload in (None, gtirb.ProxyBlock(), gtirb.CodeBlock(size=4)):
            with self.subTest(payload=payload):
                self.assertIsNone(symbol_address(gtirb.Symbol("unknown", payload=payload)))


if __name__ == "__main__":
    unittest.main()
