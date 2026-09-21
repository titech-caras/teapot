import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from gtirb_functions import Function
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Patch, RewritingContext, patch_constraints

from teapot.arch import AArch64Architecture
from teapot.configs.runtime import SCRATCHPAD_SIZE
from test_live_register_preservation import make_module


class AArch64ReportCallTests(unittest.TestCase):
    def test_report_label_stays_on_call_after_relaxation(self):
        arch = AArch64Architecture()
        _, module, block, _, _ = make_module(
            arch, gtirb.Module.ISA.ARM64, bytes.fromhex("c0035fd6"))
        for name in ("scratchpad", "report_gadget_aarch64_preserve_KASPER_CACHE"):
            gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)

        @patch_constraints()
        def report(ctx):
            return arch.report_gadget_snippet("KASPER_CACHE", "x1", "x2", "x3", "x4")

        context = RewritingContext(module, list(Function.build_functions(module)))
        context.insert_at(block, 0, Patch.from_function(report))
        context.apply()
        arch.relax_conditional_branches(module)
        labels = [symbol for symbol in module.symbols if "__report_gadget_call_" in symbol.name]
        self.assertEqual(len(labels), 1)
        label = labels[0]
        self.assertFalse(label.at_end)
        instruction = next(GtirbInstructionDecoder(module.isa).get_instructions(label.referent))
        self.assertEqual((instruction.mnemonic, instruction.op_str), ("blr", "x4"))

    def test_repeated_report_call_preserves_ip0_and_returns(self):
        compiler = shutil.which("aarch64-linux-gnu-gcc")
        qemu = shutil.which("qemu-aarch64")
        if compiler is None or qemu is None:
            self.skipTest("AArch64 cross compiler and QEMU required")
        snippet = AArch64Architecture().report_gadget_snippet(
            "KASPER_CACHE", "x1", "x2", "x3", "x4")
        assembly = f"""
            .text
            .global _start
        _start:
            mov x16, #0x1616
            bl exercise
            bl exercise
            mov x0, #1
            mov x1, #0x1616
            cmp x16, x1
            b.ne exit
            adrp x1, calls
            ldr w1, [x1, :lo12:calls]
            cmp w1, #1
            b.ne exit
            mov x0, #0
        exit:
            mov x8, #93
            svc #0
        exercise:
            {snippet}
            ret
        report_gadget_aarch64_preserve_KASPER_CACHE:
            ldr x6, [x3]
            mov w7, #0x201f
            movk w7, #0xd503, lsl #16
            str w7, [x6]
            dc cvau, x6
            dsb ish
            ic ivau, x6
            dsb ish
            isb
            adrp x6, calls
            add x6, x6, :lo12:calls
            ldr w7, [x6]
            add w7, w7, #1
            str w7, [x6]
            ret
            .bss
            .balign 16
        scratchpad:
            .skip {SCRATCHPAD_SIZE}
        calls:
            .skip 4
            .section .note.GNU-stack,"",%progbits
        """
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.S"
            binary = Path(directory) / "report"
            source.write_text(assembly)
            subprocess.run([compiler, "-nostdlib", "-static", "-no-pie", "-Wl,-N",
                            "-Wl,--build-id=none", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            result = subprocess.run([qemu, str(binary)], timeout=15, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()
