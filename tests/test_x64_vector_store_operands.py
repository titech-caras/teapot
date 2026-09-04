import unittest

import capstone_gt
from capstone_gt import CS_ARCH_X86, CS_MODE_64

from teapot.arch.x64.architecture import X64Architecture


class X64VectorStoreOperandTests(unittest.TestCase):
    @staticmethod
    def _decode(encoded: str):
        decoder = capstone_gt.Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        return next(decoder.disasm(bytes.fromhex(encoded), 0x1000))

    def setUp(self):
        self.arch = X64Architecture()

    def test_movq_xmm_store_is_a_write_not_a_read(self):
        inst = self._decode("66 44 0f d6 07")  # movq [rdi], xmm8
        operand = self.arch.memory_operand(inst)
        self.assertEqual(operand.size, 8)
        self.assertTrue(self.arch.mem_operand_is_write(inst, operand))
        self.assertFalse(self.arch.mem_operand_is_read(inst, operand))

    def test_movq_xmm_load_remains_read_only(self):
        inst = self._decode("f3 44 0f 7e 07")  # movq xmm8, [rdi]
        operand = self.arch.memory_operand(inst)
        self.assertTrue(self.arch.mem_operand_is_read(inst, operand))
        self.assertFalse(self.arch.mem_operand_is_write(inst, operand))

    def test_scalar_memory_comparison_remains_read_only(self):
        inst = self._decode("48 83 3f 00")  # cmp qword ptr [rdi], 0
        operand = self.arch.memory_operand(inst)
        self.assertTrue(self.arch.mem_operand_is_read(inst, operand))
        self.assertFalse(self.arch.mem_operand_is_write(inst, operand))

    def test_memory_rotates_are_read_modify_write(self):
        encodings = (
            "48 c1 45 e0 0d",  # rol qword ptr [rbp-0x20], 13
            "48 c1 4d e0 0d",  # ror qword ptr [rbp-0x20], 13
            "48 c1 55 e0 0d",  # rcl qword ptr [rbp-0x20], 13
            "48 c1 5d e0 0d",  # rcr qword ptr [rbp-0x20], 13
        )
        for encoded in encodings:
            with self.subTest(encoded=encoded):
                inst = self._decode(encoded)
                operand = self.arch.memory_operand(inst)
                self.assertTrue(self.arch.mem_operand_is_read(inst, operand))
                self.assertTrue(self.arch.mem_operand_is_write(inst, operand))

    def test_wide_vector_store_remains_a_write(self):
        inst = self._decode("66 44 0f 7f 07")  # movdqa [rdi], xmm8
        operand = self.arch.memory_operand(inst)
        self.assertTrue(self.arch.mem_operand_is_write(inst, operand))
        self.assertFalse(self.arch.mem_operand_is_read(inst, operand))


if __name__ == "__main__":
    unittest.main()
