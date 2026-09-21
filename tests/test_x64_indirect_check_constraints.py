import unittest

import gtirb

from teapot.arch.x64.architecture import X64Architecture


class X64IndirectCheckConstraintsTests(unittest.TestCase):
    def test_comparisons_declare_flags_clobbered(self):
        arch = X64Architecture()
        symbols = [gtirb.Symbol(name=name) for name in (
            "transient_start", "transient_end", "text_start", "text_end")]
        patch = arch.indirect_branch_check_patch("rax", *symbols, reads_registers={"rax"})
        self.assertTrue(patch.constraints.clobbers_flags)
        self.assertEqual(patch.constraints.scratch_registers, 2)
        self.assertIn("rax", patch.constraints.reads_registers)


if __name__ == "__main__":
    unittest.main()
