import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.arch.aarch64.bti import AArch64BTIArchitecture


class MainEnvpTests(unittest.TestCase):
    def _check(self, arch, compiler, runner):
        if not shutil.which(compiler) or (runner and not shutil.which(runner[0])):
            self.skipTest("target compiler/emulator unavailable")
        patch = arch.init_library_patch()(SimpleNamespace(stack_adjustment=0))
        if arch.name == "x64":
            prefix, jump = ".intel_syntax noprefix", "jmp check_main"
            clobber = "xor edi, edi; xor esi, esi; xor edx, edx; ret"
        elif arch.name == "aarch64":
            prefix, jump = "", "b check_main"
            clobber = "mov x0, #0; mov x1, #0; mov x2, #0; ret"
        else:
            prefix, jump = ".option norelax", "tail check_main"
            clobber = "li a0, 0; li a1, 0; li a2, 0; ret"
        assembly = f"""
            {prefix}
            .text
            .global main
        main:
            {patch}
            {jump}
            .global libcheckpoint_enable
            .global libcheckpoint_enable_aarch64_bti
        libcheckpoint_enable:
        libcheckpoint_enable_aarch64_bti:
            {clobber}
            .section .note.GNU-stack,""
        """
        source = r'''
            #include <string.h>
            int check_main(int argc, char **argv, char **envp) {
                if (argc != 2 || !argv || !envp || strcmp(argv[1], "argument")) return 1;
                for (; *envp; ++envp)
                    if (!strcmp(*envp, "TEAPOT_ENVP_TEST=preserved")) return 0;
                return 2;
            }
        '''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.S").write_text(assembly)
            (root / "check.c").write_text(source)
            subprocess.run([compiler, "-no-pie", str(root / "main.S"), str(root / "check.c"),
                            "-o", str(root / "probe")], check=True, capture_output=True)
            result = subprocess.run([*runner, str(root / "probe"), "argument"],
                                    env={**os.environ, "TEAPOT_ENVP_TEST": "preserved"},
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_x64(self):
        self._check(X64Architecture(), "gcc", [])

    def test_aarch64(self):
        self._check(AArch64Architecture(), "aarch64-linux-gnu-gcc",
                    ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"])

    def test_aarch64_bti_init(self):
        self._check(AArch64BTIArchitecture(), "aarch64-linux-gnu-gcc",
                    ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"])

    def test_riscv64(self):
        self._check(RISCV64Architecture(), "riscv64-linux-gnu-gcc",
                    ["qemu-riscv64", "-L", "/usr/riscv64-linux-gnu"])
