from types import SimpleNamespace
import unittest

import capstone
import gtirb
from gtirb_rewriting import Assembler

from teapot.arch import AArch64Architecture
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from test_live_register_preservation import make_module


class AArch64ZeroingDiftTests(unittest.TestCase):
    def test_only_unmodified_identical_sources_clear_taint(self):
        arch = AArch64Architecture()
        _, module, _, _, _ = make_module(arch, gtirb.Module.ISA.ARM64, b"\x1f\x20\x03\xd5")
        decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        decoder.detail = True
        text = AArch64TextDiftPropagationLLVMPass(SimpleNamespace(abi=arch.abi), None, None,
                                                 arch, dift_layout=SimpleNamespace(xor_mask=0))
        for assembly, clears in (
                ("eor x8, x0, x0", True), ("sub x0, x0, x0", True),
                ("eor w8, w0, w0", True), ("sub w8, w0, w0", True),
                ("eor x8, x0, x0, lsr #33", False),
                ("eor x8, x0, x0, ror #1", False),
                ("sub x0, x0, x0, lsl #3", False),
                ("sub w8, w0, w0, uxtb", False),
                ("sub w8, w0, w0, sxth", False),
                ("sub x8, x0, x0, uxtx", False),
                ("eor x8, x0, x1", False), ("sub x8, x0, x1", False)):
            with self.subTest(assembly=assembly):
                assembler = Assembler(module)
                assembler.assemble(assembly)
                data = assembler.finalize().text_section.data
                inst = next(decoder.disasm(data, 0x1000))
                block = gtirb.CodeBlock(size=len(data))
                gtirb.ByteInterval(address=0x1000, contents=data, blocks=[block])
                self.assertEqual(arch.dift_clears_destination_tags(inst), clears)
                self.assertEqual(text._instruction_effects(block, inst).clear_dest_tags, clears)
