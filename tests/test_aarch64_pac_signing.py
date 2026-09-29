"""PAC-signed return addresses: eligibility, patch bytes and RA-state CFI."""
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_rewriting import Assembler

from teapot.arch import AArch64Architecture
from teapot.arch.aarch64.bti_pac import AArch64BTIPACArchitecture
from teapot.passes.common.return_slot_analysis import ReturnSlotAnalysis, UnsupportedReturnSlot
from teapot.passes.preprocessing.sign_return_addresses_pass import (
    AUTIA_X30_SP, PACIA_X30_SP, AArch64SignReturnAddressesPass,
)
from test_live_register_preservation import make_module


def make_function(chunks, edges=()):
    arch = AArch64Architecture()
    ir, module, first, _, _ = make_module(arch, gtirb.Module.ISA.ARM64, b"\0" * 4)
    interval = first.byte_interval
    contents = bytearray()
    blocks = []
    for index, chunk in enumerate(chunks):
        assembler = Assembler(module)
        assembler.assemble(chunk)
        data = assembler.finalize().text_section.data
        block = first if index == 0 else gtirb.CodeBlock(byte_interval=interval)
        block.offset, block.size = len(contents), len(data)
        contents.extend(data)
        blocks.append(block)
    interval.contents = contents
    interval.size = len(contents)
    function_id = next(iter(module.aux_data["functionBlocks"].data))
    module.aux_data["functionBlocks"].data[function_id] = set(blocks)
    for source, target, kind in edges:
        destination = gtirb.ProxyBlock(module=module) if target is None else blocks[target]
        label = kind if isinstance(kind, gtirb.Edge.Label) else gtirb.Edge.Label(kind)
        ir.cfg.add(gtirb.Edge(blocks[source], destination, label))
    decoder = GtirbInstructionDecoder(module.isa)
    function = next(iter(Function.build_functions(module)))
    return arch, module, blocks, function, decoder


class AArch64PacSigningTests(unittest.TestCase):
    def analyze(self, chunks, edges=()):
        arch, _, blocks, function, decoder = make_function(chunks, edges)
        return AArch64SignReturnAddressesPass(arch, decoder)._analyze(function), blocks

    def test_leaf_function_gets_entry_pacia_and_exit_autia(self):
        (reason, plan), blocks = self.analyze(["mov x0, #1\nret"])
        self.assertIsNone(reason)
        self.assertEqual(plan["entry"], (blocks[0], 0))
        self.assertEqual(plan["exits"], [(blocks[0], 4)])

    def test_saved_return_function_uses_the_lifetime_proof(self):
        (reason, plan), blocks = self.analyze(
            ["stp x29, x30, [sp, #-16]!\nldp x29, x30, [sp], #16\nret"])
        self.assertIsNone(reason)
        self.assertEqual(plan["exits"], [(blocks[0], 8)])

    def test_native_pac_is_left_alone(self):
        (reason, _), _ = self.analyze(
            [".arch_extension pauth\npacia x30, sp\nautia x30, sp\nret"])
        self.assertEqual(reason, "native PAC/BTI already present")

    def test_reading_x30_while_it_holds_lr_is_rejected(self):
        (reason, _), _ = self.analyze(
            ["stp x29, x30, [sp, #-16]!\nldp x29, x30, [sp], #16\nmov x1, x30\nret"])
        self.assertEqual(reason, "x30 is read while holding the incoming return address")

    def test_patch_words_are_the_non_hint_encodings(self):
        self.assertEqual(PACIA_X30_SP, 0xdac103fe)
        self.assertEqual(AUTIA_X30_SP, 0xdac113fe)
        self.assertTrue(AArch64Architecture.is_pac_word(PACIA_X30_SP))
        self.assertTrue(AArch64Architecture.is_pac_word(AUTIA_X30_SP))
        self.assertTrue(AArch64Architecture.is_pac_word(0xd50323bf))  # autiasp
        self.assertFalse(AArch64Architecture.is_pac_word(0xd65f03c0))  # ret

    def test_ra_state_cfi_toggles_follow_pac_instructions(self):
        arch, module, blocks, function, decoder = make_function(
            [".arch_extension pauth\npacia x30, sp\nautia x30, sp\nret"])
        module.aux_data["cfiDirectives"] = gtirb.AuxData(
            {gtirb.Offset(blocks[0], 0): [(".cfi_startproc", [], module.uuid)]},
            "mapping<Offset,sequence<tuple<string,sequence<int64_t>,UUID>>>")
        signer = AArch64SignReturnAddressesPass(arch, decoder)
        signer.signed_functions.append(function.uuid)
        signer.end_module(module, [function])
        entries = {offset.displacement: directives
                   for offset, directives in module.aux_data["cfiDirectives"].data.items()}
        self.assertEqual(entries[4], [(".cfi_escape", [0x2d], module.uuid)])
        self.assertEqual(entries[8], [(".cfi_escape", [0x2d], module.uuid)])

    def test_no_cfi_procedure_gets_no_ra_state_toggle(self):
        """A patch outside a CFI procedure must not describe the RA state."""
        arch, module, blocks, function, decoder = make_function(
            [".arch_extension pauth\npacia x30, sp\nautia x30, sp\nret"])
        module.aux_data["cfiDirectives"] = gtirb.AuxData(
            {}, "mapping<Offset,sequence<tuple<string,sequence<int64_t>,UUID>>>")
        signer = AArch64SignReturnAddressesPass(arch, decoder)
        signer.signed_functions.append(function.uuid)
        signer.end_module(module, [function])
        self.assertEqual(signer.cfi_skipped, 1)
        self.assertEqual(module.aux_data["cfiDirectives"].data, {})

        module.aux_data.pop("cfiDirectives")
        signer = AArch64SignReturnAddressesPass(arch, decoder)
        signer.signed_functions.append(function.uuid)
        signer.end_module(module, [function])
        self.assertEqual(signer.cfi_skipped, 1)

    def test_return_slot_analysis_accepts_pac_only_when_asked(self):
        _, _, _, function, decoder = make_function(
            [".arch_extension pauth\npacia x30, sp\nstp x29, x30, [sp, #-16]!\n"
             "ldp x29, x30, [sp], #16\nautia x30, sp\nret"])
        analysis = ReturnSlotAnalysis(AArch64Architecture(), decoder)
        with self.assertRaisesRegex(UnsupportedReturnSlot, "incoming LR"):
            analysis.analyze(function)
        self.assertTrue(analysis.analyze(function, accept_pac=True))

    def test_pac_mode_contract(self):
        arch = AArch64BTIPACArchitecture()
        self.assertIn("libcheckpoint_enable_aarch64_bti_pac", arch.checkpoint_lib_symbols())
        self.assertIn("libcheckpoint_enable_aarch64_bti",
                      AArch64BTIPACArchitecture.__mro__[1]().checkpoint_lib_symbols())
        from experiments.reusable_libraries.targets import target_for
        target = target_for('ARM64', 'aarch64-bti-pac')
        self.assertEqual(target['text_section'], '.teapot_bti_normal')
        with self.assertRaises(ValueError):
            target_for('X64', 'aarch64-bti-pac')


if __name__ == "__main__":
    unittest.main()
