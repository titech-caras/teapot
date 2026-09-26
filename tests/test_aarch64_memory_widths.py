import unittest

import capstone
from capstone import CS_ARCH_ARM64, CS_MODE_ARM

from teapot.arch.aarch64.architecture import AArch64Architecture


class AArch64MemoryWidthTests(unittest.TestCase):
    def test_memory_width_is_not_the_status_or_destination_width(self):
        decoder = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
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


if __name__ == "__main__":
    unittest.main()
