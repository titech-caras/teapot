"""PC-relative memory effects cannot be moved ahead of their pre-access patches."""
import unittest

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch import RISCV64Architecture
from test_live_register_preservation import make_module


class RiscvMemoryPairInsertionTests(unittest.TestCase):
    def fixture(self, low_word):
        arch = RISCV64Architecture()
        # AUIPC a4,0; memory a5,0(a4); RET.
        contents = bytes.fromhex('17070000') + low_word.to_bytes(4, 'little') + bytes.fromhex('67800000')
        ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ValidButUnsupported, contents)
        target = gtirb.Symbol('target', payload=gtirb.ProxyBlock(module=module), module=module)
        anchor = gtirb.Symbol('anchor', payload=block, module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        block.byte_interval.symbolic_expressions.update({
            0: gtirb.SymAddrConst(0, target, {attrs.HI, attrs.PCREL}),
            4: gtirb.SymAddrConst(0, anchor, {attrs.LO, attrs.PCREL}),
        })
        return arch, module, block

    def test_pre_access_patch_does_not_move_after_memory_effect(self):
        for word in (0x00f72023, 0x00072783, 0x00f73027, 0x00073787):
            with self.subTest(low_word=hex(word)):
                _, _, block = self.fixture(word)
                actual_block, offset = RewritingContext._teapot_insert_location(block, 4)
                self.assertIs(actual_block, block)
                self.assertEqual(offset, 4)

    def test_actual_insert_preserves_hi_anchor_and_pre_store_order(self):
        _, module, block = self.fixture(0x00f72023)
        decoder = GtirbInstructionDecoder(module.isa)

        @patch_constraints()
        def pre_store(_ctx):
            return 'addi a7,zero,77'

        ctx = RewritingContext(module, Function.build_functions(module))
        ctx.insert_at(block, 4, Patch.from_function(pre_store))
        ctx.apply()
        instructions = [inst for piece in sorted(module.code_blocks, key=lambda b: b.address)
                        if piece.size for inst in decoder.get_instructions(piece)]
        self.assertEqual(instructions[0].mnemonic, 'auipc')
        self.assertEqual(instructions[1].operands[-1].imm, 77)
        self.assertEqual(instructions[2].mnemonic, 'sw')
        attrs = gtirb.SymbolicExpression.Attribute
        low = next(expr for interval in block.section.byte_intervals
                   for expr in interval.symbolic_expressions.values() if attrs.LO in expr.attributes)
        anchor = low.symbol.referent
        self.assertEqual(anchor.address, instructions[0].address)
        self.assertIn(attrs.HI, anchor.byte_interval.symbolic_expressions[anchor.offset].attributes)


if __name__ == '__main__':
    unittest.main()
