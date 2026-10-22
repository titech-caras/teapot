"""Functional objdump text classification, without provider/proof machinery."""
import unittest

from teapot.riscv_pure_link import check_disassembly


class RiscvPureLinkTests(unittest.TestCase):
    def test_integer_czero_fence_and_padding_are_allowed(self):
        text = "\n".join(f"  {n * 4:x}: {instruction}" for n, instruction in enumerate(
            ("addi a0,a0,1", "czero.eqz a0,a1,a2", "czero.nez a0,a1,a2",
             "fence rw,rw", "fence.i", "c.nop", "nop", "unimp", ".2byte 0",
             "csrrs a0,cycle,zero", "csrrsi a0,0xc00,1")))
        self.assertEqual(check_disassembly(text), 11)

    def test_all_float_vector_and_csr_forms_are_rejected(self):
        instructions = ("flw fa0,0(a0)", "fld fa0,0(a0)", "flq fa0,0(a0)",
                        "fadd.h fa0,fa1,fa2", "fmv.x.w a0,fa0", "c.fld fa0,0(a0)",
                        "c.fswsp fa0,0(sp)", "vadd.vv v0,v1,v2", "vsetvli a0,a1,e8,m1",
                        "frcsr a0", "fsflags a0", "csrrs a0,fcsr,zero",
                        "csrrw a0,0x3,a1", "csrrsi a0,001,0", "csrrc a0,0xc22,a1",
                        "csrw frm,a0", "csrwi 0xc21,0", "csrs vstart,a0",
                        "csrc vxsat,a0", "csrsi 0xa,0", "csrci 15,1")
        for instruction in instructions:
            with self.subTest(instruction=instruction), self.assertRaisesRegex(ValueError, "forbidden"):
                check_disassembly("  100: " + instruction, "fixture")

    def test_only_the_csr_operand_is_classified(self):
        self.assertEqual(check_disassembly("  100: csrrsi a0,0xc00,1"), 1)
        self.assertEqual(check_disassembly("  100: csrwi 0xc00,3"), 1)


if __name__ == "__main__":
    unittest.main()
