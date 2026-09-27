"""Instruction families must retain their semantics across decoder aliases."""
import unittest

from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.arch.decoders import x64_decoder, aarch64_decoder, riscv64_decoder


class InstructionSemanticsTests(unittest.TestCase):
    def test_rcpc_and_loregion_widths_and_stored_value_reads(self):
        arch = AArch64Architecture()
        for width, cases in (
                (1, ('20000019', '20004019', '20008019', '207c9f08', '207cdf08', '20c0bf38')),
                (2, ('20000059', '20004059', '20008059', '207c9f48', '207cdf48', '20c0bf78')),
                (4, ('20008099',))):
            for encoded in cases:
                inst, = aarch64_decoder().disasm(bytes.fromhex(encoded), 0)
                with self.subTest(instruction=str(inst)):
                    operand = arch.memory_operand(inst)
                    self.assertEqual(arch.mem_operand_size(inst, operand), width)
                    is_store = inst.mnemonic.startswith('st')
                    self.assertEqual(arch.mem_operand_is_write(inst, operand), is_store)
                    self.assertEqual(arch.mem_operand_is_read(inst, operand), not is_store)
                    reads = {reg.name for reg in arch.access_registers(arch.abi, inst, 0)}
                    self.assertIn('x1', reads)
                    self.assertEqual('x0' in reads, is_store)

    def test_zeroing_requires_equal_sources_and_no_merging_mask(self):
        arch = X64Architecture()
        zeroes = ('4831c0', '4829c0', '660fefc0', '0f57c0', '660f57c0',
                  'c5f1efc1', 'c5f057c1', '62f17548efc1')
        nonzeroes = ('4829d8', '0f5cc0', 'c5f1efc2', '62f17549efc1')
        for expected, cases in ((True, zeroes), (False, nonzeroes)):
            for encoded in cases:
                inst, = x64_decoder().disasm(bytes.fromhex(encoded), 0)
                with self.subTest(instruction=str(inst)):
                    self.assertEqual(arch.dift_clears_destination_tags(inst), expected)

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
