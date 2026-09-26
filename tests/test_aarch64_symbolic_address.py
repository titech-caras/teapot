import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from gtirb_rewriting import Assembler

from teapot.arch import AArch64Architecture
from teapot.arch.decoders import aarch64_decoder


class AArch64SymbolicAddressTests(unittest.TestCase):
    def _snippet(self, spacing, scale, offset):
        decoder = aarch64_decoder()
        inst = next(decoder.disasm(bytes.fromhex("20004139"), 0x1000))
        self.assertEqual(inst.mnemonic, "ldrb")
        module = gtirb.Module(
            name="address", isa=gtirb.Module.ISA.ARM64,
            file_format=gtirb.Module.FileFormat.ELF,
        )
        base = gtirb.Symbol("base", payload=0x4000, module=module)
        target = gtirb.Symbol("target", payload=0x4000 + spacing, module=module)
        expression = gtirb.SymAddrAddr(scale, offset, target, base)
        arch = AArch64Architecture()
        snippet = arch.mem_operand_address_snippet(
            arch.abi, inst, "x2", "x3", inst.operands[1], mem_symexpr=expression
        )
        return module, snippet, expression

    def test_difference_survives_patch_assembly(self):
        for spacing, scale, offset in ((64, 1, 0), (80, 1, 0), (80, 2, 3),
                                       (80, 2, -3), (4096, 1, 0)):
            with self.subTest(spacing=spacing, scale=scale, offset=offset):
                module, snippet, expected = self._snippet(spacing, scale, offset)
                assembler = Assembler(module)
                assembler.assemble(snippet)
                result = assembler.finalize()
                self.assertEqual(
                    list(result.text_section.symbolic_expressions.values()),
                    [expected],
                )

    def test_relocated_effective_address_executes(self):
        compiler = shutil.which("aarch64-linux-gnu-gcc")
        qemu = shutil.which("qemu-aarch64")
        if compiler is None or qemu is None:
            self.skipTest("AArch64 compiler and QEMU required")
        for spacing, scale, offset in ((64, 1, 0), (80, 1, 0), (80, 2, 3),
                                       (80, 2, -3), (4096, 1, 0)):
            with self.subTest(spacing=spacing, scale=scale, offset=offset):
                _, snippet, _ = self._snippet(spacing, scale, offset)
                source = f"""
                    .text
                    .global _start
                    _start:
                        adr x1, base
                        {snippet}
                        adr x4, base
                        cmp x1, x4
                        b.ne failed
                        add x4, x4, #{spacing // scale + offset}
                        cmp x2, x4
                        cset x0, ne
                        b exit
                    failed:
                        mov x0, #1
                    exit:
                        mov x8, #93
                        svc #0
                    .data
                    base: .zero {spacing}
                    target: .byte 37
                    .section .note.GNU-stack, "", %progbits
                """
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    assembly = root / "test.S"
                    binary = root / "test"
                    assembly.write_text(source)
                    built = subprocess.run(
                        [compiler, "-nostdlib", "-no-pie", str(assembly),
                         "-o", str(binary)], capture_output=True, text=True,
                    )
                    self.assertEqual(built.returncode, 0, built.stderr)
                    ran = subprocess.run(
                        [qemu, str(binary)], capture_output=True, timeout=10,
                    )
                    self.assertEqual(ran.returncode, 0, ran.stderr)

    def test_invalid_scale_is_rejected(self):
        with self.assertRaises(ValueError):
            self._snippet(80, 0, 0)
