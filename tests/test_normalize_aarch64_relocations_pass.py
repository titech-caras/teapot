import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.passes.preprocessing.normalize_aarch64_relocations_pass import (
    NormalizeAArch64RelocationsPass,
)


class NormalizeAArch64RelocationsPassTests(unittest.TestCase):
    def test_block_end_symbols_keep_their_addends(self):
        for addend in (0, 16, -8):
            with self.subTest(addend=addend):
                module = gtirb.Module(
                    name="end-symbol", isa=gtirb.Module.ISA.ARM64,
                    file_format=gtirb.Module.FileFormat.ELF,
                    byte_order=gtirb.Module.ByteOrder.Little,
                )
                section = gtirb.Section(name=".text", module=module)
                # adrp x0, 0x2000; add x0, x0, #8+addend
                words = (0xb0000000, 0x91000000 | ((8 + addend) << 10))
                code = gtirb.ByteInterval(
                    address=0x1000, section=section,
                    contents=b"".join(word.to_bytes(4, "little") for word in words),
                )
                gtirb.CodeBlock(size=8, byte_interval=code)
                data = gtirb.ByteInterval(address=0x2000, size=8, section=section)
                block = gtirb.DataBlock(size=8, byte_interval=data)
                symbol = gtirb.Symbol(
                    name="range_end", payload=block, at_end=True, module=module,
                )
                for offset, attributes in (
                    (0, set()), (4, {gtirb.SymbolicExpression.Attribute.LO12}),
                ):
                    code.symbolic_expressions[offset] = gtirb.SymAddrConst(
                        addend, symbol, attributes,
                    )

                normalize = NormalizeAArch64RelocationsPass(
                    GtirbInstructionDecoder(module.isa),
                )
                normalize.begin_module(module, (), None)
                for offset in (0, 4):
                    self.assertEqual(code.symbolic_expressions[offset].offset, addend)
                    self.assertIs(code.symbolic_expressions[offset].symbol, symbol)


if __name__ == "__main__":
    unittest.main()
