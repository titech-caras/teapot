from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from uuid import uuid4

from teapot.arch import RISCV64Architecture
from teapot.configs.slots import (
    RISCV64_ORIGINAL_TP_OFFSET,
    SCRATCHPAD_FIRST_SPILL_OFFSET,
)


@unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc") and shutil.which("qemu-riscv64"),
                     "requires RV64 compiler and QEMU")
class RISCV64LandingStateTests(unittest.TestCase):
    def test_spilled_direct_and_fallthrough_entries_preserve_state(self):
        arch = RISCV64Architecture()
        for mode in ("spilled", "direct", "fallthrough"):
            for marked in (False, True):
                with self.subTest(mode=mode, marked=marked), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    transfer = (arch.jump_symbol_with_first_spill_restore(".Ltarget", "t0")
                                if mode == "spilled" else "j .Ltarget" if mode == "direct" else "")
                    landing = arch.restore_landing_entry_patch(
                        uuid4(), normal_text=True, preserve_marker=marked)(SimpleNamespace())
                    source = f"""
                        .option nopic
                        .option norvc
                        .text
                        .globl _start
                        _start:
                            la t2, scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}
                            sd tp, 0(t2)
                            mv s0, tp
                            mv s1, sp
                            li ra, 93
                            mv s2, ra
                            la t2, scratchpad+{SCRATCHPAD_FIRST_SPILL_OFFSET}
                            li t0, 99
                            sd t0, 0(t2)
                            sd t0, 8(t2)
                            li t0, 37
                            li t1, 73
                            {transfer}
                        .Ltarget:
                            {landing}
                            li a0, 1
                            li t2, 37
                            bne t0, t2, .Lexit
                            li a0, 2
                            li t2, 73
                            bne t1, t2, .Lexit
                            li a0, 3
                            bne tp, s0, .Lexit
                            li a0, 4
                            bne sp, s1, .Lexit
                            li a0, 5
                            bne ra, s2, .Lexit
                            li a0, 0
                        .Lexit:
                            li a7, 93
                            ecall
                        .bss
                        .balign 16
                        scratchpad:
                            .zero 1048576
                        .section .note.GNU-stack, "", @progbits
                    """
                    assembly = root / "input.S"
                    binary = root / "input"
                    assembly.write_text(source)
                    compiled = subprocess.run(
                        ["riscv64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie",
                         "-Wl,--no-relax", str(assembly), "-o", str(binary)],
                        text=True, capture_output=True)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    run = subprocess.run(["qemu-riscv64", str(binary)],
                                         text=True, capture_output=True, timeout=10)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
