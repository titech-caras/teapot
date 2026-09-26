import unittest

from teapot.arch.aarch64.architecture import AArch64Architecture
from teapot.arch.decoders import aarch64_decoder


class AArch64MemoryWidthTests(unittest.TestCase):
    def test_memory_width_is_not_the_status_or_destination_width(self):
        decoder = aarch64_decoder()
        arch = AArch64Architecture()
        cases = (
            (0xc8007c41, "stxr", 8),
            (0xc800fc41, "stlxr", 8),
            (0xc8200c41, "stxp", 16),
            (0xc8208c41, "stlxp", 16),
            (0xc87f0c41, "ldxp", 16),
            (0xc87f8c41, "ldaxp", 16),
            (0xa8000440, "stnp", 16),
            (0xa8400440, "ldnp", 16),
            (0x69400440, "ldpsw", 8),
            (0x88007c41, "stxr", 4),
            (0x88200c41, "stxp", 8),
            (0x28000440, "stnp", 8),
            (0xa9000440, "stp", 16),
            (0xa9400440, "ldp", 16),
            (0x08007c41, "stxrb", 1),
            (0x48007c41, "stxrh", 2),
            (0xf9000040, "str", 8),
            (0xb9800040, "ldrsw", 4),
        )
        for word, mnemonic, size in cases:
            with self.subTest(mnemonic=mnemonic, word=hex(word)):
                inst = next(decoder.disasm(word.to_bytes(4, "little"), 0x1000))
                self.assertEqual(inst.mnemonic, mnemonic)
                self.assertEqual(arch.mem_operand_size(inst, arch.memory_operand(inst)), size)

    def test_structure_access_width_follows_the_register_list(self):
        # Capstone 5 names list members v0, v1, ...; Capstone 6 names them q0/d0 with a vector flag.
        decoder = aarch64_decoder()
        arch = AArch64Architecture()
        cases = (
            (0x4c40a000, "ld1", 32),   # ld1 {v0.16b, v1.16b}, [x0]
            (0x0c407000, "ld1", 8),    # ld1 {v0.8b}, [x0]
            (0x0d009000, "st1", 4),    # st1 {v0.s}[1], [x0]
            (0x4d40c800, "ld1r", 4),   # ld1r {v0.4s}, [x0]
            (0x4c408820, "ld2", 32),   # ld2 {v0.4s, v1.4s}, [x1]
            (0x0d202c00, "st4", 4),    # st4 {v0.b, v1.b, v2.b, v3.b}[3], [x0]
        )
        for word, mnemonic, size in cases:
            with self.subTest(mnemonic=mnemonic, word=hex(word)):
                inst = next(decoder.disasm(word.to_bytes(4, "little"), 0x1000))
                self.assertEqual(inst.mnemonic, mnemonic)
                self.assertEqual(arch.mem_operand_size(inst, arch.memory_operand(inst)), size)


if __name__ == "__main__":
    unittest.main()
