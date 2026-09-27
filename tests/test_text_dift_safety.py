from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass


class TextDiftSafetyTests(unittest.TestCase):
    def _pass(self, arch, kind):
        return kind(SimpleNamespace(abi=arch.abi), None, None, arch,
                    dift_layout=SimpleNamespace(xor_mask=0))

    def test_extractor_rejects_calls_and_outside_symbols(self):
        for arch, kind, bad in (
                (X64Architecture(), X64TextDiftPropagationLLVMPass,
                 ["callq memset@PLT", "jmp outside", "movq .LCPI0_0(%rip), %rax"]),
                (AArch64Architecture(), AArch64TextDiftPropagationLLVMPass,
                 ["bl memset", "blr x0", "b outside", "adrp x0, .LCPI0_0"]),
                (RISCV64Architecture(), RISCV64TextDiftPropagationLLVMPass,
                 ["call memset@plt", "tail memset@plt", "jalr ra, a0, 0",
                  "j outside", "lui a0, %hi(.LCPI0_0)"])):
            dift = self._pass(arch, kind)
            for instruction in bad:
                with self.subTest(arch=arch.name, instruction=instruction):
                    with self.assertRaisesRegex(ValueError, "call|symbol"):
                        dift._extract_function_asm(f"func:\n{instruction}\nret\n.Lfunc_end0:\n")

    def test_rv64_zero_tags_codegen_has_no_external_call(self):
        dift = self._pass(RISCV64Architecture(), RISCV64TextDiftPropagationLLVMPass)
        # A long, unaligned batch of immediate-register assignments must stay
        # inline rather than call the real, intercepted memset.
        body = "\n".join(
            f"store i8 0, ptr getelementptr inbounds ([48 x i8], ptr @dift_reg_tags, i64 0, i64 {i})"
            for i in range(1, 32))
        ir = dift._parse_and_optimize_llvm(dift._format_llvm_ir(body, target_triple=dift.target_triple))
        ir.verify()
        assembly = dift.target_machine.emit_assembly(ir)
        self.assertNotRegex(assembly, r"\b(?:call|tail)\s+")
        snippet = dift._extract_function_asm(assembly)
        compiler, qemu = shutil.which("riscv64-linux-gnu-gcc"), shutil.which("qemu-riscv64")
        if not compiler or not qemu:
            self.skipTest("RV64 cross compiler and emulator unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "probe.S").write_text(f".text\n.global probe\nprobe:\n{snippet}\nret\n"
                                           '.section .note.GNU-stack,""\n')
            (root / "main.c").write_text('''
                unsigned char dift_reg_tags[48] __attribute__((aligned(16)));
                unsigned char scratchpad[1048576] __attribute__((aligned(16)));
                extern void probe(void);
                int main(void) {
                    for (int i=0; i<48; ++i) dift_reg_tags[i]=0x55;
                    probe();
                    for (int i=0; i<48; ++i)
                        if(dift_reg_tags[i] != (i>0 && i<32 ? 0 : 0x55)) return 1;
                    return 0;
                }
            ''')
            subprocess.run([compiler, "-no-pie", "-Wl,--no-relax", str(root / "probe.S"),
                            str(root / "main.c"), "-o", str(root / "probe")],
                           check=True, capture_output=True)
            result = subprocess.run([qemu, "-L", "/usr/riscv64-linux-gnu", str(root / "probe")],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rv64_backend_libcall_is_rejected_even_with_no_builtins(self):
        dift = self._pass(RISCV64Architecture(), RISCV64TextDiftPropagationLLVMPass)
        # no-builtins does not constrain every backend libcall expansion.
        # Keep the extraction check even when the ordinary 48-byte batch is
        # lowered inline. This oversized clear models such a future expansion.
        body = 'call void @llvm.memset.p0.i64(ptr @scratchpad, i8 0, i64 1024, i1 false)'
        source = dift._format_llvm_ir(body, target_triple=dift.target_triple)
        source += '\ndeclare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)'
        assembly = dift.target_machine.emit_assembly(dift._parse_and_optimize_llvm(source))
        if re.search(r"\b(?:call|tail)\s+", assembly):
            with self.assertRaisesRegex(ValueError, "call"):
                dift._extract_function_asm(assembly)
        else:
            # Newer LLVM may choose a safe inline loop instead.
            dift._extract_function_asm(assembly)
