import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints
from gtirb_rewriting._modify.edit import edit_byte_interval
from gtirb_rewriting.prepare import prepare_for_rewriting

from teapot.arch import RISCV64Architecture
from teapot.preprocess.copy_section import copy_section
from test_live_register_preservation import make_module


class RiscvPcrelRewritingTests(unittest.TestCase):
    def test_public_symbol_retarget_does_not_redirect_low_anchor(self):
        ir, module, block, _, _ = make_module(
            RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported,
            bytes.fromhex("97020000 93820200 67800000"))
        entry = next(module.symbols_named("test_function"))
        target = gtirb.Symbol("target", payload=gtirb.ProxyBlock(module=module), module=module)
        replacement = gtirb.Symbol("replacement", payload=gtirb.ProxyBlock(module=module), module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        block.byte_interval.symbolic_expressions.update({
            0: gtirb.SymAddrConst(0, target, {attrs.HI, attrs.PCREL}),
            4: gtirb.SymAddrConst(0, entry, {attrs.LO, attrs.PCREL}),
        })
        ctx = RewritingContext(module, Function.build_functions(module))
        ctx.retarget_symbol_uses(entry, replacement)
        ctx.apply()
        low = block.byte_interval.symbolic_expressions[block.offset + 4]
        self.assertIsInstance(low.symbol.referent, gtirb.CodeBlock)
        self.assertIsNot(low.symbol, entry)
        self.assertIsNot(low.symbol, replacement)
        self.assertEqual(low.symbol.referent.address, block.address)

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in (
            "ddisasm", "riscv64-linux-gnu-gcc", "qemu-riscv32", "qemu-riscv64"))
        and shutil.which(os.environ.get("PPRINTER_PATH", "gtirb-pprinter")),
        "local frontend/printer and RISC-V toolchains required")
    def test_frontend_nop_rewrite_roundtrip_runs(self):
        for bits in (32, 64):
            for compressed in (False, True):
                with self.subTest(bits=bits, compressed=compressed), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / "pair.S"
                    source.write_text(f"""
.option {'rvc' if compressed else 'norvc'}
.option norelax
.text
.globl _start
.type _start,@function
_start:
    auipc t0,%pcrel_hi(value)
    j low
decoy:
    auipc t0,%pcrel_hi(other)
    addi t0,t0,%pcrel_lo(decoy)
    j done
low:
    lbu a0,%pcrel_lo(_start)(t0)
    li a7,93
    ecall
done:
    li a0,99
    li a7,93
    ecall
.size _start,.-_start
.data
value: .byte 7
other: .byte 99
""")
                    flags = [f"-march=rv{bits}imac", f"-mabi={'ilp32' if bits == 32 else 'lp64'}",
                             "-nostdlib", "-static", "-no-pie", "-Wl,--no-relax,--build-id=none"]
                    binary = root / "original"
                    subprocess.run(["riscv64-linux-gnu-gcc", *flags, str(source), "-o", str(binary)],
                                   check=True, capture_output=True)
                    self.assertEqual(subprocess.run([f"qemu-riscv{bits}", str(binary)], timeout=10).returncode, 7)
                    path = root / "pair.gtirb"
                    subprocess.run(["ddisasm", str(binary), "--ir", str(path), "-j", "1"],
                                   check=True, capture_output=True)
                    for iteration in range(4):
                        ir = gtirb.IR.load_protobuf(path)
                        module = ir.modules[0]
                        if iteration:
                            with prepare_for_rewriting(module, bytes.fromhex("13000000")):
                                for block in tuple(module.code_blocks):
                                    if not block.size:
                                        continue
                                    padding = bytes.fromhex("13000000") * iteration
                                    edit_byte_interval(block.byte_interval, block.offset, 0, padding, (block,))
                                    block.size += len(padding)
                        ir.save_protobuf(path)
                        printed = root / "printed.S"
                        subprocess.run([os.environ.get("PPRINTER_PATH", "gtirb-pprinter"),
                                        "--ir", str(path), "--asm", str(printed)],
                                       check=True, capture_output=True)
                        rebuilt = root / "rebuilt"
                        subprocess.run(["riscv64-linux-gnu-gcc", *flags, str(printed), "-o", str(rebuilt)],
                                       check=True, capture_output=True)
                        self.assertEqual(
                            subprocess.run([f"qemu-riscv{bits}", str(rebuilt)], timeout=10).returncode,
                            7, f"round {iteration}:\n{printed.read_text()}")

    def test_pair_survives_real_patches_copy_and_serialization(self):
        ir, module, block, _, _ = make_module(
            RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported,
            bytes.fromhex("97020000 93820200 67800000"))
        entry = next(module.symbols_named("test_function"))
        target = gtirb.Symbol("target", payload=gtirb.ProxyBlock(module=module), module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        block.byte_interval.symbolic_expressions.update({
            0: gtirb.SymAddrConst(0, target, {attrs.HI, attrs.PCREL}),
            4: gtirb.SymAddrConst(0, entry, {attrs.LO, attrs.PCREL}),
        })

        @patch_constraints()
        def prefix(_ctx):
            return "nop; nop"

        for iteration in range(3):
            entry = next(module.symbols_named("test_function"))
            ctx = RewritingContext(module, Function.build_functions(module))
            ctx.insert_at(entry.referent, 0, Patch.from_function(prefix))
            ctx.apply()
            if iteration == 0:
                copy_section(entry.referent.section, ".teapot_transient")
            lows = []
            for section in module.sections:
                for interval in section.byte_intervals:
                    for offset, expression in interval.symbolic_expressions.items():
                        if attrs.LO not in expression.attributes:
                            continue
                        lows.append(expression)
                        anchor = expression.symbol.referent
                        high = anchor.byte_interval.symbolic_expressions[anchor.offset]
                        self.assertIn(attrs.HI, high.attributes)
                        self.assertEqual(anchor.section, section)
                        self.assertEqual(anchor.byte_interval.contents[anchor.offset] & 0x7f, 0x17)
                        self.assertIsNot(expression.symbol, entry)
            self.assertEqual(len(lows), 2)
            stream = io.BytesIO()
            ir.save_protobuf_file(stream)
            stream.seek(0)
            ir = gtirb.IR.load_protobuf_file(stream)
            module = ir.modules[0]


if __name__ == "__main__":
    unittest.main()
