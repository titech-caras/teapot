"""A PC-relative HI is completed only by its %pcrel_lo, never by a patch's absolute %lo."""
import unittest

import gtirb
from gtirb_rewriting import RewritingContext

from teapot.arch import RISCV64Architecture
from test_live_register_preservation import make_module


class RiscvPairPartnerTests(unittest.TestCase):
    def fixture(self, hi_attrs, final_low_word):
        arch = RISCV64Architecture()
        # AUIPC a4,0 ; LUI t0,0 ; ADDI t0,t0,0 ; <low a4> ; RET.
        # The LUI/ADDI pair stands for an already inserted patch such as the
        # transient coverage load of guard_list_top.
        contents = (bytes.fromhex('17070000') + bytes.fromhex('b7020000') +
                    bytes.fromhex('93820200') + final_low_word.to_bytes(4, 'little') +
                    bytes.fromhex('67800000'))
        ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ValidButUnsupported, contents)
        target = gtirb.Symbol('target', payload=gtirb.ProxyBlock(module=module), module=module)
        guard = gtirb.Symbol('guard_list_top', payload=gtirb.ProxyBlock(module=module), module=module)
        anchor = gtirb.Symbol('anchor', payload=block, module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        block.byte_interval.symbolic_expressions.update({
            0: gtirb.SymAddrConst(0, target, hi_attrs),
            4: gtirb.SymAddrConst(0, guard, {attrs.HI}),
            8: gtirb.SymAddrConst(0, guard, {attrs.LO}),
            12: gtirb.SymAddrConst(0, anchor, {attrs.LO, attrs.PCREL}),
        })
        return block

    def test_insertion_is_not_moved_inside_patch_absolute_pair(self):
        attrs = gtirb.SymbolicExpression.Attribute
        # LD a4,0(a4): the real partner is a memory access, so the requested
        # boundary after the AUIPC is kept (pre-access patches stay before it).
        for hi_attrs in ({attrs.GOT}, {attrs.HI, attrs.PCREL}, {attrs.TLSGD}):
            with self.subTest(hi=sorted(a.name for a in hi_attrs)):
                block = self.fixture(hi_attrs, 0x00073703)
                actual_block, offset = RewritingContext._teapot_insert_location(block, 4)
                self.assertIs(actual_block, block)
                self.assertEqual(offset, 4)

    def test_address_pair_still_moves_after_its_real_pcrel_low(self):
        attrs = gtirb.SymbolicExpression.Attribute
        # ADDI a4,a4,0: an address materialization partner. The insertion moves
        # after the real %pcrel_lo, not after the patch's absolute %lo.
        block = self.fixture({attrs.HI, attrs.PCREL}, 0x00070713)
        actual_block, offset = RewritingContext._teapot_insert_location(block, 4)
        self.assertIs(actual_block, block)
        self.assertEqual(offset, 16)


if __name__ == '__main__':
    unittest.main()
