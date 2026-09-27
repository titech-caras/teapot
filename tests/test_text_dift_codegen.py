from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import gtirb
from gtirb_rewriting import Assembler
import llvmlite.binding as llvm

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.arch.decoders import riscv64_decoder
from teapot.configs.runtime import SCRATCHPAD_SIZE
from teapot.configs.slots import AARCH64_SHADOW_STACK_SIZE, RISCV64_ORIGINAL_TP_OFFSET
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from test_live_register_preservation import make_module


class TextDiftCodegenTests(unittest.TestCase):
    def test_x64_codegen_ignores_the_host_target(self):
        with mock.patch.object(llvm.Target, 'from_default_triple',
                               side_effect=AssertionError('host target must not be used')):
            dift = self._pass(X64Architecture(), X64TextDiftPropagationLLVMPass)
        self.assertEqual(dift.target_triple, 'x86_64-unknown-linux-gnu')
        module = llvm.parse_assembly('define i64 @func(i64 %a) { ret i64 %a }')
        assembly = dift.target_machine.emit_assembly(module)
        self.assertIn('%rdi', assembly)
        self.assertIn('%rax', assembly)

    def _pass(self, arch, pass_type):
        return pass_type(SimpleNamespace(abi=arch.abi), None, None, arch,
                         dift_layout=SimpleNamespace(xor_mask=0))

    def test_independent_replays_can_reuse_each_target(self):
        # A builder's per-run callbacks must not outlive their LLVM analyses.
        for arch, kind in ((X64Architecture(), X64TextDiftPropagationLLVMPass),
                           (AArch64Architecture(), AArch64TextDiftPropagationLLVMPass),
                           (RISCV64Architecture(), RISCV64TextDiftPropagationLLVMPass)):
            dift = self._pass(arch, kind)
            for offset in range(4):
                with self.subTest(arch=arch.name, batch=offset):
                    body = f"store i8 {offset}, ptr getelementptr ([48 x i8], ptr @dift_reg_tags, i64 0, i64 {offset})"
                    module = dift._parse_and_optimize_llvm(dift._format_llvm_ir(
                        body, target_triple=dift.target_triple))
                    module.verify()
                    asm = dift._extract_function_asm(dift.target_machine.emit_assembly(module))
                    self.assertIn("dift_reg_tags", asm)
                    self.assertTrue(dift._get_register_usage(asm))

    def test_riscv64_uses_hardware_multiply_without_compression(self):
        dift = self._pass(RISCV64Architecture(), RISCV64TextDiftPropagationLLVMPass)
        module = llvm.parse_assembly("""
            define i64 @func(i64 %a, i64 %b) {
                %product = mul i64 %a, %b
                ret i64 %product
            }
        """)
        assembly = dift.target_machine.emit_assembly(module)
        self.assertRegex(assembly, r"\bmul\b")
        self.assertNotIn("__muldi3", assembly)

    def test_riscv64_patch_assembler_accepts_codegen_and_call_saves(self):
        arch = RISCV64Architecture()
        _, module, _, _, _ = make_module(arch, gtirb.Module.ISA.ValidButUnsupported, b"\x13\0\0\0")
        dift = self._pass(arch, RISCV64TextDiftPropagationLLVMPass)
        # A generated call must preserve all FP registers and FCSR, even when
        # no FP registers occur explicitly in the body.
        body = "mul a0, a0, a1\namoadd.d a1, a0, (a2)\ncall helper\n"
        snippet = dift._build_optimized_dift_values_patch(
            body, dift._get_register_usage(body))(SimpleNamespace(stack_adjustment=0))
        for number in range(32):
            self.assertIn(f"fsd f{number},", snippet)
            self.assertIn(f"fld f{number},", snippet)
        assembler = Assembler(module, allow_undef_symbols=True)
        assembler.assemble(snippet)
        data = assembler.finalize().text_section.data
        decoder = riscv64_decoder()
        instructions = list(decoder.disasm(data, 0))
        self.assertEqual(sum(inst.size for inst in instructions), len(data))
        self.assertTrue(instructions)
        self.assertTrue(all(inst.size == 4 for inst in instructions))
        self.assertIn("mul", [inst.mnemonic for inst in instructions])

    def test_aarch64_allows_neon(self):
        dift = self._pass(AArch64Architecture(), AArch64TextDiftPropagationLLVMPass)
        module = llvm.parse_assembly("""
            define void @func(ptr %a, ptr %b) {
                %x = load <16 x i8>, ptr %a, align 1
                %y = load <16 x i8>, ptr %b, align 1
                %z = or <16 x i8> %x, %y
                store <16 x i8> %z, ptr %a, align 1
                ret void
            }
        """)
        self.assertRegex(dift.target_machine.emit_assembly(module), r"\bv[0-9]+\.16b\b")

    def test_aarch64_replay_preserves_simd_and_control(self):
        arch = AArch64Architecture()
        dift = self._pass(arch, AArch64TextDiftPropagationLLVMPass)
        body = "movi v0.16b, #0\nmovi v31.16b, #0\nmsr fpcr, xzr\nmsr fpsr, xzr\n"
        patch = dift._build_optimized_dift_values_patch(
            body, dift._get_register_usage(body), scratch_plan=dift._scratch_plan(None, None, 0))
        snippet = patch(SimpleNamespace(stack_adjustment=0))
        for number in (0, 31):
            self.assertIn(f"str q{number},", snippet)
            self.assertIn(f"ldr q{number},", snippet)
        self.assertNotIn("str q1,", snippet)
        asm = f"""
            .text
            .global probe
        probe:
            mov x9, sp
            {arch.load_address('x10', 'test_stack_top')}
            mov sp, x10
            mrs x11, fpcr
            mrs x12, fpsr
            mov x10, #0x400000
            msr fpcr, x10
            mov x10, #1
            msr fpsr, x10
            movi v0.16b, #0x55
            movi v31.16b, #0x77
            {snippet}
            mov w0, #1
            mrs x10, fpcr
            cmp x10, #0x400000
            b.ne 1f
            mrs x10, fpsr
            cmp x10, #1
            b.ne 1f
            umov x10, v0.d[1]
            {arch.mov_u64('x13', 0x5555555555555555)}
            cmp x10, x13
            b.ne 1f
            umov x10, v31.d[1]
            {arch.mov_u64('x13', 0x7777777777777777)}
            cmp x10, x13
            b.ne 1f
            mov w0, #0
        1:
            msr fpcr, x11
            msr fpsr, x12
            mov sp, x9
            ret
            .bss
            .balign 16
            .skip {AARCH64_SHADOW_STACK_SIZE + 4096}
        test_stack_top:
            .skip 4096
        """
        self._execute(arch, asm)

    def test_riscv64_replay_preserves_fp_and_control(self):
        arch = RISCV64Architecture()
        dift = self._pass(arch, RISCV64TextDiftPropagationLLVMPass)
        body = "fmv.d.x ft0, zero\nfmv.d.x ft11, zero\nfscsr zero\n"
        patch = dift._build_optimized_dift_values_patch(body, dift._get_register_usage(body))
        snippet = patch(SimpleNamespace(stack_adjustment=0))
        for reg in ("ft0", "ft11"):
            self.assertIn(f"fsd {reg},", snippet)
            self.assertIn(f"fld {reg},", snippet)
        self.assertNotIn("fsd ft1,", snippet)
        asm = f"""
            .text
            .global probe
        probe:
            {arch.load_address('t0', f'scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}')}
            sd tp, 0(t0)
            frcsr a3
            li t0, 0x65
            fscsr t0
            li t0, 0x5555555555555555
            fmv.d.x ft0, t0
            li t0, 0x7777777777777777
            fmv.d.x ft11, t0
            {snippet}
            li a0, 1
            frcsr t0
            li t1, 0x65
            bne t0, t1, 1f
            fmv.x.d t0, ft0
            li t1, 0x5555555555555555
            bne t0, t1, 1f
            fmv.x.d t0, ft11
            li t1, 0x7777777777777777
            bne t0, t1, 1f
            li a0, 0
        1:
            fscsr a3
            ret
        """
        self._execute(arch, asm)

    def test_aarch64_lra_replay_preserves_live_gpr_flags_and_simd(self):
        arch = AArch64Architecture()
        dift = self._pass(arch, AArch64TextDiftPropagationLLVMPass)
        live = {arch.abi.get_register(name) for name in ("x9", "x14", "nzcv")}
        plan = dift._plan_scratch_registers(2, live)
        self.assertFalse(plan.saved_regs)
        body = "mov x14, #0\nadds x0, x0, #1\nmovi v0.16b, #0\n"
        snippet = dift._build_optimized_dift_values_patch(
            body, dift._get_register_usage(body), scratch_plan=plan)(SimpleNamespace(stack_adjustment=0))
        self._execute(arch, f"""
            .text
            .global probe
        probe:
            mov x9, sp
            {arch.load_address('x10', 'test_stack_top')}
            mov sp, x10
            mov x14, #0x1234
            mov x10, #0xa0000000
            msr nzcv, x10
            movi v0.16b, #0x55
            {snippet}
            mrs x10, nzcv
            mov w0, #1
            mov x11, #0xa0000000
            cmp x10, x11
            b.ne 1f
            mov x11, #0x1234
            cmp x14, x11
            b.ne 1f
            umov x10, v0.d[1]
            {arch.mov_u64('x11', 0x5555555555555555)}
            cmp x10, x11
            b.ne 1f
            mov w0, #0
        1:
            mov sp, x9
            ret
            .bss
            .balign 16
            .skip {AARCH64_SHADOW_STACK_SIZE + 4096}
        test_stack_top:
            .skip 4096
        """)

    def test_riscv64_lra_replay_preserves_live_gpr_fp_and_control(self):
        arch = RISCV64Architecture()
        dift = self._pass(arch, RISCV64TextDiftPropagationLLVMPass)
        plan = dift._plan_scratch_registers(2, {arch.abi.get_register("t3")})
        self.assertFalse(plan.saved_regs)
        body = "li t3, 0\nli t0, 0\nfmv.d.x ft0, zero\nfscsr zero\n"
        snippet = dift._build_optimized_dift_values_patch(
            body, dift._get_register_usage(body), scratch_plan=plan)(SimpleNamespace(stack_adjustment=0))
        self._execute(arch, f"""
            .text
            .global probe
        probe:
            {arch.load_address('t0', f'scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}')}
            sd tp, 0(t0)
            li t3, 0x1234
            li t0, 0x65
            fscsr t0
            li t0, 0x55
            fmv.d.x ft0, t0
            {snippet}
            li a0, 1
            li t4, 0x1234
            bne t3, t4, 1f
            frcsr t0
            li t4, 0x65
            bne t0, t4, 1f
            fmv.x.d t0, ft0
            li t4, 0x55
            bne t0, t4, 1f
            li a0, 0
        1:
            ret
        """)

    def test_aarch64_shadow_translation_uses_immediate(self):
        arch = AArch64Architecture()
        for bit in (0, 38, 41, 47, 63):
            snippet = arch.dift_shadow_addr_snippet("x0", "x1", 1 << bit)
            self.assertEqual(len(snippet.splitlines()), 2)
            self.assertIn(f"eor x0, x0, #{1 << bit}", snippet)
        self.assertNotIn("eor", arch.dift_shadow_addr_snippet("x0", "x1", 0))
        self.assertIn("eor x0, x0, x1", arch.dift_shadow_addr_snippet("x0", "x1", 0x12345))

    def _execute(self, arch, assembly):
        compiler = f"{arch.name}-linux-gnu-gcc"
        qemu = f"qemu-{arch.name}"
        if not shutil.which(compiler) or not shutil.which(qemu):
            self.skipTest("target compiler and QEMU required")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # File-scope ISA declarations are at the start of an MC patch
            # transaction, but GNU as requires them before the probe setup too.
            lines = assembly.splitlines()
            attributes = [line for line in lines if line.strip().startswith(".attribute ")]
            assembly = "\n".join(attributes + [line for line in lines if line not in attributes])
            (root / "probe.S").write_text(
                assembly + '\n.section .note.GNU-stack,"",%progbits\n')
            (root / "main.c").write_text(f"""
                unsigned char scratchpad[{SCRATCHPAD_SIZE}] __attribute__((aligned(16)));
                extern int probe(void);
                int main(void) {{ return probe(); }}
            """)
            command = [compiler, "-O2", "-no-pie", str(root / "main.c"),
                       str(root / "probe.S"), "-o", str(root / "probe")]
            if arch.name == "riscv64":
                command += ["-march=rv64gc", "-mabi=lp64d", "-Wl,--no-relax"]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([qemu, "-L", f"/usr/{arch.name}-linux-gnu", str(root / "probe")],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
