"""Native PAC/BTI normalization in the BTI modes (design step 4)."""
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import RewritingContext

from teapot.arch import AArch64Architecture
from teapot.arch.aarch64.bti import AArch64BTIArchitecture
from teapot.arch.aarch64.bti_pac import AArch64BTIPACArchitecture
from teapot.passes.preprocessing.normalize_original_pac_bti_pass import (
    BTI_WORDS, PAC_HINT_NORMALIZATION, NormalizeOriginalPacBtiPass,
)
from test_aarch64_pac_signing import make_function


class NormalizeOriginalPacBtiTests(unittest.TestCase):
    def test_encodings(self):
        self.assertEqual(PAC_HINT_NORMALIZATION[0xd503233f], "pacia x30, sp")
        self.assertEqual(PAC_HINT_NORMALIZATION[0xd503237f], "pacib x30, sp")
        self.assertEqual(PAC_HINT_NORMALIZATION[0xd50323bf], "autia x30, sp")
        self.assertEqual(PAC_HINT_NORMALIZATION[0xd50323ff], "autib x30, sp")
        self.assertEqual(BTI_WORDS, frozenset((0xd503245f, 0xd503249f, 0xd50324df)))

    def test_only_the_bti_modes_carry_the_pass(self):
        decoder = GtirbInstructionDecoder(gtirb.Module.ISA.ARM64)
        for arch in (AArch64BTIArchitecture(), AArch64BTIPACArchitecture()):
            names = [type(p).__name__ for p in arch.normalize_passes(decoder, None)]
            self.assertIn("NormalizeOriginalPacBtiPass", names)
        software = [type(p).__name__ for p in AArch64Architecture().normalize_passes(decoder, None)]
        self.assertNotIn("NormalizeOriginalPacBtiPass", software)

    def test_hints_and_bti_are_replaced_in_place(self):
        arch, module, blocks, function, decoder = make_function(
            ["paciasp\nhint #36\nret"])  # paciasp; bti c; ret
        pass_ = NormalizeOriginalPacBtiPass(decoder)
        context = RewritingContext(module, [function])
        pass_.begin_module(module, [function], context)
        context.apply()
        self.assertEqual(bytes(blocks[0].contents).hex(), "fe03c1da1f2003d5c0035fd6")
        self.assertEqual((pass_.converted_pac, pass_.removed_bti), (1, 1))

    @staticmethod
    def make_signed_function():
        arch, module, blocks, function, decoder = make_function(
            ["stp x29, x30, [sp, #-16]!\nmov x29, sp\npaciasp\nmov x0, #1\nautiasp\nret"])
        toggle = [(".cfi_escape", [0x2d], module.uuid)]
        module.aux_data["cfiDirectives"] = gtirb.AuxData(
            {
                gtirb.Offset(blocks[0], 0): [(".cfi_startproc", [], module.uuid)],
                gtirb.Offset(blocks[0], 12): toggle,
                gtirb.Offset(blocks[0], 20): toggle,
                gtirb.Offset(blocks[0], 24): [(".cfi_endproc", [], module.uuid)],
            },
            "mapping<Offset,sequence<tuple<string,sequence<int64_t>,UUID>>>")
        return module, blocks, function, decoder

    @staticmethod
    def toggle_addresses(module):
        table = module.aux_data["cfiDirectives"].data
        return sorted(offset.element_id.address + offset.displacement
                      for offset, directives in table.items()
                      if getattr(offset.element_id, "byte_interval", None) is not None
                      for name, args, _ in directives
                      if name == ".cfi_escape" and list(args) == [0x2d])

    def test_negate_toggle_is_restored_after_normalization(self):
        module, blocks, function, decoder = self.make_signed_function()
        pass_ = NormalizeOriginalPacBtiPass(decoder)
        context = RewritingContext(module, [function])
        pass_.begin_module(module, [function], context)
        context.apply()
        pass_.end_module(module, [function])
        self.assertEqual((pass_.converted_pac, pass_.restored_toggles), (2, 2))
        self.assertEqual(self.toggle_addresses(module),
                         [blocks[0].address + 12, blocks[0].address + 20])

    def test_existing_toggle_is_not_duplicated(self):
        module, blocks, function, decoder = self.make_signed_function()
        pass_ = NormalizeOriginalPacBtiPass(decoder)
        context = RewritingContext(module, [function])
        pass_.begin_module(module, [function], context)
        context.apply()
        # Simulate a framework that preserves the lifted directive: attach the
        # toggles where they were before the rewrite.
        text = next(section for section in module.sections if section.name == ".text")
        table = module.aux_data["cfiDirectives"].data
        for address in (blocks[0].address + 12, blocks[0].address + 20):
            block = next(block for block in text.code_blocks
                         if block.address is not None
                         and block.address <= address < block.address + block.size)
            table[gtirb.Offset(block, address - block.address)] = [
                (".cfi_escape", [0x2d], module.uuid)]
        pass_.end_module(module, [function])
        self.assertEqual(pass_.restored_toggles, 0)
        self.assertEqual(len(self.toggle_addresses(module)), 2)

    def test_no_toggle_without_a_cfi_procedure(self):
        arch, module, blocks, function, decoder = make_function(["paciasp\nret"])
        module.aux_data["cfiDirectives"] = gtirb.AuxData(
            {}, "mapping<Offset,sequence<tuple<string,sequence<int64_t>,UUID>>>")
        pass_ = NormalizeOriginalPacBtiPass(decoder)
        context = RewritingContext(module, [function])
        pass_.begin_module(module, [function], context)
        context.apply()
        pass_.end_module(module, [function])
        self.assertEqual((pass_.converted_pac, pass_.restored_toggles), (1, 0))
        self.assertEqual(module.aux_data["cfiDirectives"].data, {})


if __name__ == "__main__":
    unittest.main()
