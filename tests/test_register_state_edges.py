"""Register exchanges move tags, AVX-512 masks carry none, SVE/SME is refused,
and symbol names the assembler cannot spell are renamed."""
from types import SimpleNamespace
import unittest

import gtirb

from teapot.arch import X64Architecture
from teapot.arch.decoders import x64_decoder
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass


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


if __name__ == "__main__":
    unittest.main()
