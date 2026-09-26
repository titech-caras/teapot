import unittest

from teapot.arch import AArch64Architecture
from teapot.arch.aarch64.operands import aarch64_access_displacement, aarch64_base_register_writeback
from teapot.arch.decoders import aarch64_decoder


class AArch64WritebackAddressingTests(unittest.TestCase):
    """Pre/post-indexed accesses, independent of how Capstone reports the increment.

    Capstone 5 gives `[x1], #8` a zero displacement plus an immediate operand; Capstone 6 folds the
    increment into the displacement and sets post_index. It also sets writeback for tied operands.
    """

    # encoding, accessed displacement, base register writeback
    CASES = (
        ("208400f8", 0, True),     # str x0, [x1], #8
        ("208c00f8", 8, True),     # str x0, [x1, #8]!
        ("200400f9", 8, False),    # str x0, [x1, #8]
        ("fd7bc1a8", 0, True),     # ldp x29, x30, [sp], #16
        ("fd7bbfa9", -16, True),   # stp x29, x30, [sp, #-16]!
        ("417ca0c8", 0, False),    # cas x0, x1, [x2]
        ("0070c24c", 0, True),     # ld1 {v0.16b}, [x0], x2
    )

    def setUp(self):
        self.arch = AArch64Architecture()
        self.decoder = aarch64_decoder()

    def decode(self, encoded):
        return next(self.decoder.disasm(bytes.fromhex(encoded), 0x1000))

    def test_accessed_displacement_and_base_writeback(self):
        for encoded, displacement, writeback in self.CASES:
            inst = self.decode(encoded)
            with self.subTest(instruction=f"{inst.mnemonic} {inst.op_str}"):
                mem = self.arch.memory_operand(inst)
                self.assertEqual(aarch64_access_displacement(inst, mem), displacement)
                self.assertEqual(aarch64_base_register_writeback(inst), writeback)
        movk = self.decode("2000a0f2")  # movk x0, #1, lsl #16: tied, no memory operand
        self.assertFalse(aarch64_base_register_writeback(movk))

    def test_stack_updates_and_accesses(self):
        sp = self.arch.abi.get_register("sp")
        pop, push = self.decode("fd7bc1a8"), self.decode("fd7bbfa9")
        self.assertEqual(self.arch.stack_register_assignment(pop), (sp, sp, 16))
        self.assertEqual(self.arch.stack_register_assignment(push), (sp, sp, -16))
        self.assertEqual(self.arch.stack_memory_access(pop).displacement, 0)
        self.assertEqual(self.arch.stack_memory_access(push).displacement, -16)
        self.assertIsNone(self.arch.stack_register_assignment(self.decode("417ca0c8")))  # cas

    def test_post_indexed_store_logs_the_unmodified_base(self):
        inst = self.decode("208400f8")  # str x0, [x1], #8
        snippet = self.arch.mem_operand_address_snippet(
            self.arch.abi, inst, "x9", "x10", self.arch.memory_operand(inst))
        self.assertIn("mov x9, x1", snippet)
        self.assertNotIn("#8", snippet)
        self.assertNotIn("add", snippet)


if __name__ == "__main__":
    unittest.main()
