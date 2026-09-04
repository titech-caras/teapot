import unittest

import capstone_gt
from capstone_gt import CS_ARCH_RISCV, CS_MODE_RISCV64

from teapot.arch.riscv64.architecture import RISCV64Architecture


class RISCV64AtomicOperandTests(unittest.TestCase):
    ENCODINGS = (
        ("2f25b600", "amoadd.w", "a2", 4, True, True, {"a1", "a2"}, {"a0"}),
        ("afb6e706", "amoadd.d.aqrl", "a5", 8, True, True, {"a4", "a5"}, {"a3"}),
        ("2fa80814", "lr.w.aq", "a7", 4, True, False, {"a7"}, {"a6"}),
        ("2f24991a", "sc.w.rl", "s2", 4, False, True, {"s1", "s2"}, {"s0"}),
        ("afb26308", "amoswap.d", "t2", 8, True, True, {"t1", "t2"}, {"t0"}),
    )

    def setUp(self):
        self.arch = RISCV64Architecture()
        self.decoder = capstone_gt.Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
        self.decoder.detail = True

    def _decode(self, encoded):
        return next(self.decoder.disasm(bytes.fromhex(encoded), 0x1000))

    def test_atomic_memory_and_register_classification(self):
        for (encoded, mnemonic, base, width, reads_memory, writes_memory,
             read_registers, written_registers) in self.ENCODINGS:
            with self.subTest(mnemonic=mnemonic):
                inst = self._decode(encoded)
                operand = self.arch.memory_operand(inst)

                self.assertEqual(inst.mnemonic, mnemonic)
                self.assertEqual(operand.base_name, base)
                self.assertEqual(self.arch.mem_operand_size(inst, operand), width)
                self.assertEqual(
                    self.arch.mem_operand_is_read(inst, operand), reads_memory)
                self.assertEqual(
                    self.arch.mem_operand_is_write(inst, operand), writes_memory)
                self.assertEqual(
                    {reg.name for reg in self.arch.access_registers(
                        self.arch.abi, inst, 0)},
                    read_registers,
                )
                self.assertEqual(
                    {reg.name for reg in self.arch.access_registers(
                        self.arch.abi, inst, 1)},
                    written_registers,
                )


if __name__ == "__main__":
    unittest.main()
