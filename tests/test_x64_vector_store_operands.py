import unittest

from teapot.arch.x64.architecture import X64Architecture
from teapot.arch.decoders import x64_decoder


class X64VectorStoreOperandTests(unittest.TestCase):
    # encoding, instruction, read, write. Capstone (5 and 6.0) marks the movq store's and the
    # rotates' memory destinations read-only; the movdqa store, the movq load and the comparison
    # are the controls around the recovered shapes.
    CASES = (
        ("66 44 0f d6 07", "movq [rdi], xmm8", False, True),
        ("66 44 0f 7f 07", "movdqa [rdi], xmm8", False, True),
        ("f3 44 0f 7e 07", "movq xmm8, [rdi]", True, False),
        ("48 83 3f 00", "cmp qword ptr [rdi], 0", True, False),
        ("48 c1 45 e0 0d", "rol qword ptr [rbp-0x20], 13", True, True),
        ("48 c1 4d e0 0d", "ror qword ptr [rbp-0x20], 13", True, True),
        ("48 c1 55 e0 0d", "rcl qword ptr [rbp-0x20], 13", True, True),
        ("48 c1 5d e0 0d", "rcr qword ptr [rbp-0x20], 13", True, True),
    )

    def test_memory_operand_reads_and_writes(self):
        arch = X64Architecture()
        decoder = x64_decoder()
        for encoded, instruction, is_read, is_write in self.CASES:
            with self.subTest(instruction=instruction):
                inst = next(decoder.disasm(bytes.fromhex(encoded), 0x1000))
                operand = arch.memory_operand(inst)
                self.assertEqual(arch.mem_operand_is_read(inst, operand), is_read)
                self.assertEqual(arch.mem_operand_is_write(inst, operand), is_write)
                if instruction == "movq [rdi], xmm8":
                    self.assertEqual(operand.size, 8)


if __name__ == "__main__":
    unittest.main()
