"""Instruction families must retain their semantics across decoder aliases."""
import unittest

from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.arch.decoders import x64_decoder, aarch64_decoder, riscv64_decoder


class InstructionSemanticsTests(unittest.TestCase):
    def test_barriers_and_unlogged_cache_stores_rollback(self):
        for encoded in ('ff3003d5', '9f2203d5', '9f3003d5', '9f3403d5',
                        '20740bd5', '60740bd5', '80740bd5'):
            inst, = aarch64_decoder().disasm(bytes.fromhex(encoded), 0)
            with self.subTest(instruction=str(inst)):
                self.assertTrue(AArch64Architecture().instruction_must_rollback(inst))
        inst, = riscv64_decoder().disasm(bytes.fromhex('0f003083'), 0)
        self.assertEqual(inst.mnemonic, 'fence.tso')
        self.assertTrue(RISCV64Architecture().instruction_must_rollback(inst))

    def test_x64_prefixed_control_transfers_are_not_dift_or_rep(self):
        arch = X64Architecture()
        for encoded in ('f3c3', 'f2c3', '3effe0', 'f2ffe0', '3effd0', 'f2ffd0'):
            inst, = x64_decoder().disasm(bytes.fromhex(encoded), 0)
            with self.subTest(instruction=str(inst)):
                self.assertTrue(arch.is_control_transfer_instruction(inst))
                self.assertTrue(arch.dift_should_skip_instruction(inst))
                self.assertFalse(arch.instruction_must_rollback(inst))


if __name__ == '__main__':
    unittest.main()
