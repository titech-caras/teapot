"""Instruction families must retain their semantics across decoder aliases."""
import unittest

from teapot.arch import X64Architecture
from teapot.arch.decoders import x64_decoder


class InstructionSemanticsTests(unittest.TestCase):
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
