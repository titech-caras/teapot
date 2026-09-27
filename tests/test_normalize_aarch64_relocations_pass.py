import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder

from teapot.passes.preprocessing.normalize_aarch64_relocations_pass import (
    NormalizeAArch64RelocationsPass,
)


class NormalizeAArch64RelocationsPassTests(unittest.TestCase):
    def test_nonadjacent_shared_page_users_keep_full_signed_addends(self):
        for symbol_value in (0x2108, 0xf108):
            for split in (False, True):
                with self.subTest(symbol=hex(symbol_value), split=split):
                    ir = gtirb.IR()
                    module = gtirb.Module(name='shared-page', isa=gtirb.Module.ISA.ARM64, ir=ir,
                        file_format=gtirb.Module.FileFormat.ELF, byte_order=gtirb.Module.ByteOrder.Little)
                    text = gtirb.Section(name='.text', module=module)
                    # ADRP x0,0x9000; NOP; LDR x1,[x0,#0x238];
                    # ADD x2,x0,#0x234; ADD x3,x0,#0x234; RET.
                    words = (0x90000040, 0xd503201f, 0xf9400001 | (0x238//8 << 10),
                             0x91000002 | (0x234 << 10), 0x91000003 | (0x234 << 10), 0xd65f03c0)
                    code = gtirb.ByteInterval(address=0x1000, section=text,
                        contents=b''.join(w.to_bytes(4, 'little') for w in words))
                    high = gtirb.CodeBlock(size=8 if split else len(words)*4, byte_interval=code)
                    if split:
                        users = gtirb.CodeBlock(size=16, offset=8, byte_interval=code)
                        ir.cfg.add(gtirb.Edge(high, users, gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
                    symbol = gtirb.Symbol('large_object', payload=symbol_value, module=module)
                    lo12 = gtirb.SymbolicExpression.Attribute.LO12
                    for offset in (0, 8, 12):
                        code.symbolic_expressions[offset] = gtirb.SymAddrConst(
                            0x999, symbol, {lo12} if offset else set())
                    fix = self.normalize(module)
                    for offset, target in ((0, 0x9234), (8, 0x9238), (12, 0x9234), (16, 0x9234)):
                        self.assertEqual(code.symbolic_expressions[offset].offset, target-symbol_value)
                    self.assertEqual(fix.symbolized_split_lo12, 1)

    def test_redefined_base_does_not_supply_a_page_for_a_mismatched_lo12(self):
        module, code, symbol, _ = self.relaxed_adrp_fixture(
            (0xd0000002, 0xd2800002, 0x91002040))  # ADRP x2; MOV x2,0; ADD x0,x2,8
        code.symbolic_expressions[0] = gtirb.SymAddrConst(99, symbol, set())
        code.symbolic_expressions[8] = gtirb.SymAddrConst(99, symbol, {gtirb.SymbolicExpression.Attribute.LO12})
        with self.assertRaisesRegex(ValueError, 'no unique matching ADRP'):
            self.normalize(module)

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

    @staticmethod
    def relaxed_adrp_fixture(words):
        """GNU ld erratum-843419 output: 'adr x2, 0x3000' at page offset 0xff8
        followed by uses of x2, lifted as ddisasm does: each paired use carries
        '.L_3fc0 - .L_3000' (GOT slot minus an integral page symbol)."""
        module = gtirb.Module(
            name="relaxed-adrp", isa=gtirb.Module.ISA.ARM64,
            file_format=gtirb.Module.FileFormat.ELF,
            byte_order=gtirb.Module.ByteOrder.Little,
        )
        text = gtirb.Section(name=".text", module=module)
        code = gtirb.ByteInterval(
            address=0x1ff8, section=text,
            contents=b"".join(word.to_bytes(4, "little") for word in words),
        )
        gtirb.CodeBlock(size=4 * len(words), byte_interval=code)
        got = gtirb.Section(name=".got", module=module)
        slot = gtirb.DataBlock(size=8, byte_interval=gtirb.ByteInterval(address=0x3fc0, size=8, section=got))
        got_symbol = gtirb.Symbol(name=".L_3fc0", payload=slot, module=module)
        target = gtirb.Symbol(name="stderr", payload=gtirb.ProxyBlock(module=module), module=module)
        page = gtirb.Symbol(name=".L_3000", payload=0x3000, module=module)
        module.aux_data["symbolForwarding"] = gtirb.AuxData(
            type_name="mapping<UUID,UUID>", data={got_symbol: target})
        return module, code, got_symbol, page

    def normalize(self, module):
        normalize = NormalizeAArch64RelocationsPass(GtirbInstructionDecoder(module.isa))
        normalize.begin_module(module, (), None)
        return normalize

    ADR_X2_3000 = 0x10008042         # adr x2, 0x3000 (at 0x1ff8)
    LDR_X2_X2_FC0 = 0xF947E042       # ldr x2, [x2, #0xfc0]
    LDR_X0_X2 = 0xF9400040           # ldr x0, [x2]
    LDR_X3_X2_8 = 0xF9400443         # ldr x3, [x2, #8]

    def test_relaxed_adrp_got_pair_is_restored(self):
        module, code, got_symbol, page = self.relaxed_adrp_fixture(
            (self.ADR_X2_3000, self.LDR_X2_X2_FC0, self.LDR_X0_X2))
        code.symbolic_expressions[4] = gtirb.SymAddrAddr(1, 0, got_symbol, page)
        self.assertEqual(self.normalize(module).restored_adrp, 1)
        adrp = next(GtirbInstructionDecoder(module.isa).get_instructions(next(iter(module.code_blocks))))
        # Capstone 6 prints the page without "#"; compare the operands.
        self.assertEqual((adrp.mnemonic, adrp.reg_name(adrp.operands[0].reg), adrp.operands[1].imm),
                         ("adrp", "x2", 0x3000))
        GOT, LO12 = gtirb.SymbolicExpression.Attribute.GOT, gtirb.SymbolicExpression.Attribute.LO12
        self.assertEqual(code.symbolic_expressions[0], gtirb.SymAddrConst(0, got_symbol, {GOT}))
        self.assertEqual(code.symbolic_expressions[4], gtirb.SymAddrConst(0, got_symbol, {GOT, LO12}))
        self.assertNotIn(8, code.symbolic_expressions)

    def test_shared_decoder_observes_restored_adrp_in_the_same_round(self):
        module, code, got_symbol, page = self.relaxed_adrp_fixture(
            (self.ADR_X2_3000, self.LDR_X2_X2_FC0, self.LDR_X0_X2))
        code.symbolic_expressions[4] = gtirb.SymAddrAddr(1, 0, got_symbol, page)
        block = next(iter(module.code_blocks))
        decoder = CachedGtirbInstructionDecoder(module.isa)
        self.assertEqual(next(decoder.get_instructions(block)).mnemonic, 'adr')
        normalize = NormalizeAArch64RelocationsPass(decoder)
        normalize.begin_module(module, (), None)
        self.assertEqual(normalize.restored_adrp, 1)
        self.assertEqual(next(decoder.get_instructions(block)).mnemonic, 'adrp')
        self.assertEqual(normalize._instructions[block.address].mnemonic, 'adrp')

    def test_relaxed_adrp_with_other_base_use_is_left_alone(self):
        # x2 is also read as a plain page base before being redefined.
        module, code, got_symbol, page = self.relaxed_adrp_fixture(
            (self.ADR_X2_3000, self.LDR_X3_X2_8, self.LDR_X2_X2_FC0))
        code.symbolic_expressions[8] = gtirb.SymAddrAddr(1, 0, got_symbol, page)
        original = bytes(code.contents)
        self.assertEqual(self.normalize(module).restored_adrp, 0)
        self.assertEqual(bytes(code.contents), original)
        self.assertNotIn(0, code.symbolic_expressions)
        self.assertIsInstance(code.symbolic_expressions[8], gtirb.SymAddrAddr)

    def test_relaxed_adrp_live_past_block_is_left_alone(self):
        # x2 is never redefined in the block, so later uses cannot be ruled out.
        module, code, got_symbol, page = self.relaxed_adrp_fixture((self.ADR_X2_3000, self.LDR_X0_X2 | 0xFC0 // 8 << 10))
        code.symbolic_expressions[4] = gtirb.SymAddrAddr(1, 0, got_symbol, page)
        self.assertEqual(self.normalize(module).restored_adrp, 0)
        self.assertNotIn(0, code.symbolic_expressions)


if __name__ == "__main__":
    unittest.main()
