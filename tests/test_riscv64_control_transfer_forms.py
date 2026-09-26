import unittest

from teapot.arch.decoders import riscv64_decoder
from teapot.arch.riscv64.architecture import RISCV64Architecture


class RISCV64ControlTransferFormTests(unittest.TestCase):
    """Returns, jumps, calls and nops are recognized however Capstone spells them.

    Capstone 5 prints aliases and compressed names (`ret`, `j`, `c.jr ra`); Capstone 6's real,
    uncompressed form prints `jalr zero, 0(ra)`, `jal zero, target` and `addi zero, zero, 0`.
    """

    # encoding, return, unconditional direct jump, call, DIFT skips it
    CASES = (
        ("67800000", True, False, False, True),    # ret
        ("8280", True, False, False, True),        # c.jr ra
        ("67800700", False, False, False, True),   # jr a5
        ("8287", False, False, False, True),       # c.jr a5
        ("e7800700", False, False, True, True),    # jalr a5
        ("8297", False, False, True, True),        # c.jalr a5
        ("6f000010", False, True, False, True),    # j 256
        ("01a2", False, True, False, True),        # c.j 256
        ("ef000010", False, False, True, True),    # jal 256
        ("13000000", False, False, False, True),   # nop
        ("0100", False, False, False, True),       # c.nop
        ("13055000", False, False, False, False),  # li a0, 5
    )

    def test_classification(self):
        arch = RISCV64Architecture()
        decoder = riscv64_decoder()
        for encoded, is_return, is_jump, is_call, skipped in self.CASES:
            inst = next(decoder.disasm(bytes.fromhex(encoded), 0x1000))
            with self.subTest(instruction=f"{inst.mnemonic} {inst.op_str}"):
                self.assertEqual(arch.is_return_instruction(inst), is_return)
                self.assertEqual(arch.is_unconditional_jump(inst), is_jump)
                self.assertEqual(arch.abi.is_call_instruction(inst), is_call)
                self.assertEqual(arch.dift_should_skip_instruction(inst), skipped)
                self.assertTrue(arch.is_control_transfer_instruction(inst) or encoded in (
                    "13000000", "0100", "13055000"))

    def test_constant_loads_clear_destination_tags(self):
        arch = RISCV64Architecture()
        inst = next(riscv64_decoder().disasm(bytes.fromhex("13055000"), 0x1000))  # li a0, 5
        self.assertTrue(arch.dift_clears_destination_tags(inst))
        inst = next(riscv64_decoder().disasm(bytes.fromhex("13850500"), 0x1000))  # mv a0, a1
        self.assertFalse(arch.dift_clears_destination_tags(inst))


if __name__ == "__main__":
    unittest.main()
