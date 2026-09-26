"""LLVM return blocks must leave an inlined replay, not fall into its cold tail."""

from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass, X64LLVMRegisterUsage


class TextDiftReturnTests(unittest.TestCase):
    def _pass(self, arch, cls):
        return cls(SimpleNamespace(abi=arch.abi), None, None, arch,
                   dift_layout=SimpleNamespace(xor_mask=0))

    def test_internal_returns_branch_to_common_patch_epilogue(self):
        for arch, cls, branch, ret in (
                (X64Architecture(), X64TextDiftPropagationLLVMPass, "jmp", "retq"),
                (AArch64Architecture(), AArch64TextDiftPropagationLLVMPass, "b", "ret"),
                (RISCV64Architecture(), RISCV64TextDiftPropagationLLVMPass, "j", "ret")):
            with self.subTest(arch=arch.name):
                dift = self._pass(arch, cls)
                body = dift._extract_function_asm(f"""
func:
    {ret}
.LBB0_1:
    nop
    {ret}
.Lfunc_end0:
    .size func, .Lfunc_end0-func
""")
                self.assertIn(f"{branch} .Lfunc_end0", body)
                self.assertNotRegex(body, r"(?m)^\s*retq?\s*$")
                self.assertTrue(body.rstrip().endswith(".Lfunc_end0:"))

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc"),
                         "requires native x64 and C compiler")
    def test_native_early_exit_does_not_fall_through_into_backward_branch(self):
        # LLVM puts a shared return before a cold block. Deleting that retq
        # makes both paths spin forever, as in SPEC gcc's place_field replay.
        dift = self._pass(X64Architecture(), X64TextDiftPropagationLLVMPass)
        body = dift._extract_function_asm("""
func:
    cmpb $0, dift_reg_tags(%rip)
    jne .LBB0_cold
.LBB0_exit:
    retq
.LBB0_cold:
    movb $1, dift_reg_tags+1(%rip)
    jmp .LBB0_exit
.Lfunc_end0:
    .size func, .Lfunc_end0-func
""")
        patch = dift._build_optimized_dift_values_patch(
            body, X64LLVMRegisterUsage(set(), False))
        snippet = patch(SimpleNamespace(scratch_registers=[]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "probe.S").write_text(f"""
    .text
    .globl probe
probe:
    {snippet}
    movb $1, epilogue(%rip)
    retq
    .section .note.GNU-stack,"",@progbits
""")
            (root / "main.c").write_text("""
unsigned char dift_reg_tags[48], epilogue;
#define condition dift_reg_tags[0]
#define visited dift_reg_tags[1]
extern void probe(void);
int main(void) {
    for (condition = 0; condition < 2; ++condition) {
        visited = epilogue = 0;
        probe();
        if (visited != condition || epilogue != 1) return 1;
    }
    return 0;
}
""")
            subprocess.run(["cc", "-no-pie", str(root / "main.c"), str(root / "probe.S"),
                            "-o", str(root / "check")], check=True, capture_output=True)
            result = subprocess.run([str(root / "check")], timeout=2, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
