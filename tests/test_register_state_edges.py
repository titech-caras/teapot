"""Register exchanges move tags, AVX-512 masks carry none, SVE/SME is refused,
and symbol names the assembler cannot spell are renamed."""
from types import SimpleNamespace
import unittest

import gtirb

from teapot.arch import AArch64Architecture, X64Architecture
from teapot.arch.decoders import x64_decoder
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from teapot.preprocess.printable_names import rename_unprintable_symbols
from teapot.utils.decoder import CachedGtirbInstructionDecoder
from test_live_register_preservation import make_module


class X64TagEdgeTests(unittest.TestCase):
    def effects(self, encoded):
        arch = X64Architecture()
        inst, = x64_decoder().disasm(bytes.fromhex(encoded), 0x1000)
        block = gtirb.CodeBlock(size=inst.size)
        gtirb.ByteInterval(address=inst.address, contents=bytes(inst.bytes), blocks=[block])
        dift = X64TextDiftPropagationLLVMPass(SimpleNamespace(abi=arch.abi), None, None, arch,
                                              dift_layout=SimpleNamespace(xor_mask=0))
        return dift, dift._instruction_effects(block, inst)

    def test_register_exchanges_move_tags(self):
        for encoded in ("4c87c1", "4c0fc1c1"):  # xchg rcx, r8; xadd rcx, r8
            with self.subTest(encoded=encoded):
                dift, effects = self.effects(encoded)
                self.assertEqual({reg.name for reg in effects.regs_write}, {"rcx", "r8"})
                self.assertFalse(dift._should_skip_effects(effects))
        dift, effects = self.effects("48ffc1")  # inc rcx keeps its own tag
        self.assertTrue(dift._should_skip_effects(effects))

    def test_mask_registers_carry_no_tag(self):
        # kmovw k1, eax; vmovdqu8 [rdi]{k2}, zmm0
        for encoded in ("c5f892c8", "62f17f4a7f07"):
            with self.subTest(encoded=encoded):
                _, effects = self.effects(encoded)
                names = {reg.name for reg in effects.regs_read | effects.regs_write}
                self.assertFalse(names & {f"k{index}" for index in range(8)})


class AArch64ScalableStateTests(unittest.TestCase):
    def test_sve_and_predicate_state_is_refused(self):
        arch = AArch64Architecture()
        # st1b {z0.b}, p0, [x9]; ptrue p7.b
        for contents in ("20e100e4", "e7e31825"):
            with self.subTest(contents=contents):
                _, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ARM64, bytes.fromhex(contents))
                with self.assertRaisesRegex(ValueError, "SVE/SME instruction at 0x"):
                    arch.unsupported_instructions(block.section, CachedGtirbInstructionDecoder(module.isa))
        # rdvl x0, #1 only reads the vector length.
        _, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ARM64, bytes.fromhex("2050bf04"))
        self.assertEqual(arch.unsupported_instructions(block.section, CachedGtirbInstructionDecoder(module.isa)), [])


class PrintableNameTests(unittest.TestCase):
    def test_gas_numeric_local_labels_get_printable_names(self):
        module = gtirb.Module(name="m", isa=gtirb.Module.ISA.RISCV64)
        first = gtirb.Symbol(".L1\x022", module=module)
        second = gtirb.Symbol(".L1\x021", module=module)
        gtirb.Symbol(".L_teapot_local_0", module=module)
        kept = gtirb.Symbol("main", module=module)
        self.assertEqual(rename_unprintable_symbols(module), 2)
        self.assertEqual((second.name, first.name), (".L_teapot_local_1", ".L_teapot_local_2"))
        self.assertEqual(kept.name, "main")
        self.assertEqual(rename_unprintable_symbols(module), 0)


if __name__ == "__main__":
    unittest.main()
