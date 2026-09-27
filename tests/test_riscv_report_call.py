"""Report calls preserve the interrupted floating-point state using the ABI."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from teapot.arch import RISCV64Architecture
from teapot.configs.runtime import SCRATCHPAD_SIZE


class RISCVReportCallTests(unittest.TestCase):
    def test_float_spills_cover_only_call_clobbered_registers(self):
        arch = RISCV64Architecture()
        with_float = arch.report_gadget_snippet(
            'KASPER_CACHE', 'a3', 'a4', 't3', save_float_state=True)
        # psABI: ft0-ft11 and fa0-fa7; fs0-fs11 are the callee's responsibility.
        expected = list(range(8)) + list(range(10, 18)) + list(range(28, 32))
        for operation in ('fsd', 'fld'):
            slots = re.findall(rf'{operation} f(\d+), (\d+)\(sp\)', with_float)
            self.assertEqual([int(register) for register, _ in slots], expected)
            self.assertEqual(len({offset for _, offset in slots}), len(expected))
        without_float = arch.report_gadget_snippet('KASPER_CACHE', 'a3', 'a4', 't3')
        self.assertNotRegex(without_float, r'\b(fsd|fld|frcsr|fscsr)\b')

    def test_report_call_preserves_all_fprs_fcsr_and_stack(self):
        compiler, qemu = shutil.which('riscv64-linux-gnu-gcc'), shutil.which('qemu-riscv64')
        if not compiler or not qemu:
            self.skipTest('requires RISC-V cross compiler and QEMU')
        snippet = RISCV64Architecture().report_gadget_snippet(
            'KASPER_CACHE', 'a3', 'a4', 't3', save_float_state=True)
        # Rewriting collects patch architecture directives separately. GNU as
        # requires their equivalent declaration before this fixture's _start.
        attributes = '\n'.join(line for line in snippet.splitlines() if '.attribute' in line)
        snippet = '\n'.join(line for line in snippet.splitlines() if '.attribute' not in line)
        seed = '\n'.join(f'li t0, {0x3ff0000000000000 + i}\nfmv.d.x f{i}, t0'
                         for i in range(32))
        check = '\n'.join(f'fmv.x.d t0, f{i}\nli t1, {0x3ff0000000000000 + i}\n'
                          'bne t0, t1, fail' for i in range(32))
        # The reporter can overwrite every call-clobbered FPR and FCSR, but is
        # ABI-compliant: it does not modify fs0-fs11. The caller checks all 32.
        clobber = '\n'.join(f'fmv.d.x {name}, zero' for name in
                            [*(f'ft{i}' for i in range(12)), *(f'fa{i}' for i in range(8))])
        assembly = f'''
            {attributes}
            .option norelax
            .option norvc
            .text
            .global _start
        _start:
            mv s0, sp
            {seed}
            li t0, 0x51
            fscsr t0
            li a3, 0x12345678
            li a4, 0x1ab
            call exercise
            call exercise
            bne sp, s0, fail
            {check}
            frcsr t0
            li t1, 0x51
            bne t0, t1, fail
            la t0, calls
            lw t0, 0(t0)
            li t1, 2
            bne t0, t1, fail
            li a0, 0
            j exit
        fail:
            li a0, 1
        exit:
            li a7, 93
            ecall
        exercise:
            {snippet}
            ret
        report_gadget_KASPER_CACHE:
            andi t0, sp, 15
            bnez t0, fail
            li t0, 0x12345678
            bne a1, t0, fail
            li t0, 0xab
            bne a2, t0, fail
            la t0, calls
            lw t1, 0(t0)
            addi t1, t1, 1
            sw t1, 0(t0)
            {clobber}
            li t0, 0x60
            fscsr t0
            ret
            .bss
            .balign 16
        scratchpad:
            .skip {SCRATCHPAD_SIZE}
        calls:
            .skip 4
            .section .note.GNU-stack,"",@progbits
        '''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / 'report.S', root / 'report'
            source.write_text(assembly)
            build = subprocess.run([compiler, '-march=rv64imafd', '-mabi=lp64d',
                                    '-nostdlib', '-static', '-no-pie', '-Wl,--no-relax',
                                    '-Wl,--build-id=none', source, '-o', binary],
                                   text=True, capture_output=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([qemu, binary], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
