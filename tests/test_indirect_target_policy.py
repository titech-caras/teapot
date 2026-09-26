"""Execute the actual emitted software target predicate and normal bouncer.

These are regression gates for hardware experiments, not a hardware backend.
The unrestricted transient range and full marker test must not be narrowed.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import gtirb

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.passes.transient.indirect_branch_check_pass import TransientIndirectBranchCheckDestPass


class IndirectTargetPolicyTests(unittest.TestCase):
    def _execute(self, arch, compiler, launcher, operand, scratch, result):
        if not shutil.which(compiler) or launcher and not shutil.which(launcher[0]):
            self.skipTest("requires target compiler and emulator")
        symbols = [gtirb.Symbol(name=name) for name in (
            "transient_start", "transient_end", "text_start", "text_end")]
        check = arch.indirect_branch_check_patch(operand, *symbols)(
            SimpleNamespace(scratch_registers=scratch))
        bouncer = arch.indirect_branch_target_patch(
            gtirb.Symbol(name="transient_bounced"), use_scratch_registers=arch.name != "x64")(
                SimpleNamespace(scratch_registers=scratch))
        directive = ".long" if arch.name == "x64" else ".word"
        marker = "\n".join(f"{directive} 0x{word:08x}" for word in arch.MAGIC_WORDS)
        landing = {"x64": 0xfa1e0ff3, "aarch64": 0xd50324df, "riscv64": 0x00000013}[arch.name]
        assembly = f"""
{'.intel_syntax noprefix' if arch.name == 'x64' else ''}
{'.option norelax' if arch.name == 'riscv64' else ''}
.text
.global check_target
check_target:
{check}
{result} 1
ret
restore_checkpoint_MALFORMED_INDIRECT_BR:
{result} 0
ret
.global trusted_runtime_landing
trusted_runtime_landing:
{directive} 0x{landing:08x}
{result} 99
ret
.section normal_test,"ax",%progbits
.p2align 4
.global text_start, text_end, complete_marker, wrong_second, bare_landing, prefixed_marker
.global marker_crossing_end, normal_bouncer
text_start:
.zero 16
complete_marker:
{marker}
.zero 8
wrong_second:
{directive} 0x{arch.MAGIC_WORDS[0]:08x}
{directive} 0
bare_landing:
{directive} 0x{landing:08x}
.zero 12
prefixed_marker:
{directive} 0x{landing:08x}
{marker}
.zero 8
.p2align 4
normal_bouncer:
{bouncer}
{result} 0
ret
.zero 16
marker_crossing_end:
{directive} 0x{arch.MAGIC_WORDS[0]:08x}
text_end:
{directive} 0x{arch.MAGIC_WORDS[1]:08x}
.zero 16
.section transient_test,"ax",%progbits
.p2align 4
.global transient_start, transient_end, transient_bounced
transient_start:
.zero 64
transient_bounced:
{result} 1
ret
transient_end:
.zero 16
.bss
.p2align 3
.global checkpoint_cnt, indirect_branch_flags_scratch
checkpoint_cnt:
.zero 8
indirect_branch_flags_scratch:
.zero 8
.section .note.GNU-stack,"",%progbits
"""
        source = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern int check_target(uintptr_t), normal_bouncer(void);
extern uint64_t checkpoint_cnt;
extern unsigned char text_start[], text_end[], transient_start[], transient_end[];
extern unsigned char complete_marker[], wrong_second[], bare_landing[], prefixed_marker[];
extern unsigned char trusted_runtime_landing[], marker_crossing_end[];
static int expected(uintptr_t p) {
    if (p >= (uintptr_t)transient_start && p < (uintptr_t)transient_end) return 1;
    if (p < (uintptr_t)text_start || p >= (uintptr_t)text_end) return 0;
    uint32_t a, b;
    memcpy(&a, (void *)p, 4);
    memcpy(&b, (void *)(p + 4), 4);
    return a == MAGIC0 && b == MAGIC1;
}
int main(void) {
    uintptr_t fixed[] = {0, UINTPTR_MAX, (uintptr_t)text_start - 1, (uintptr_t)text_end,
        (uintptr_t)transient_start - 1, (uintptr_t)transient_end,
        (uintptr_t)trusted_runtime_landing};
    unsigned count = 0;
    for (unsigned i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        assert(check_target(fixed[i]) == expected(fixed[i])); count++;
    }
    /* Every byte, not just block starts or aligned instruction addresses. */
    for (uintptr_t p = (uintptr_t)transient_start; p < (uintptr_t)transient_end; p++) {
        assert(check_target(p) == 1); count++;
    }
    for (uintptr_t p = (uintptr_t)text_start; p < (uintptr_t)text_end; p++) {
        assert(check_target(p) == expected(p)); count++;
    }
    assert(check_target((uintptr_t)complete_marker) == 1);
    assert(check_target((uintptr_t)wrong_second) == 0);
    assert(check_target((uintptr_t)bare_landing) == 0);
    assert(check_target((uintptr_t)prefixed_marker) == 0);
    assert(check_target((uintptr_t)prefixed_marker + 4) == 1);
    /* Preserve the existing predicate, including its second-word read past N. */
    assert(check_target((uintptr_t)marker_crossing_end) == 1);
    assert(check_target((uintptr_t)normal_bouncer) == 1);
    checkpoint_cnt = 0;
    assert(normal_bouncer() == 0);
    checkpoint_cnt = 1;
    assert(normal_bouncer() == 1);
    checkpoint_cnt = 2;
    assert(normal_bouncer() == 1);
    printf("%u actual-emitted predicate addresses; normal/nested bouncers passed\n", count);
    return 0;
}
"""
        with tempfile.TemporaryDirectory(prefix="target-policy-") as directory:
            root = Path(directory)
            (root / "policy.S").write_text(assembly)
            (root / "policy.c").write_text(source)
            command = [compiler, "-O2", "-no-pie", "-fno-pie",
                       f"-DMAGIC0=0x{arch.MAGIC_WORDS[0]:08x}U",
                       f"-DMAGIC1=0x{arch.MAGIC_WORDS[1]:08x}U",
                       str(root / "policy.c"), str(root / "policy.S"), "-o", str(root / "policy")]
            built = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run(launcher + [str(root / "policy")], capture_output=True,
                                 text=True, timeout=15)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    def test_x64_exact_target_policy(self):
        if platform.machine() not in ("x86_64", "amd64"):
            self.skipTest("requires native x64")
        self._execute(X64Architecture(), "gcc", [], "rdi", ("r8", "r9"), "mov eax,")

    def test_aarch64_exact_target_policy(self):
        self._execute(AArch64Architecture(), "aarch64-linux-gnu-gcc",
                      ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"],
                      "x0", ("x8", "x9", "x10"), "mov w0,")

    def test_riscv64_exact_target_policy(self):
        # The rewriter hands the patch Register objects, and Capstone 6 prints `jr a0` as
        # `jalr zero, 0(a0)`; a return keeps the bare `ra`.
        arch = RISCV64Architecture()
        scratch = tuple(arch.abi.get_register(name) for name in ("t3", "t4", "t5"))
        for operand in ("a0", "0(a0)"):
            with self.subTest(operand=operand):
                self._execute(arch, "riscv64-linux-gnu-gcc",
                              ["qemu-riscv64", "-L", "/usr/riscv64-linux-gnu"],
                              operand, scratch, "li a0,")

    def test_returns_still_have_software_operands(self):
        edge = gtirb.cfg.Edge.Type.Return
        instruction = SimpleNamespace(op_str="", mnemonic="ret")
        for arch, operand in ((X64Architecture(), "[rsp]"),
                              (AArch64Architecture(), "x30"),
                              (RISCV64Architecture(), "ra")):
            with self.subTest(arch=arch.name):
                self.assertEqual(arch.indirect_branch_operand(edge, instruction), operand)

    def test_returns_calls_and_jumps_still_require_checks(self):
        ordinary = SimpleNamespace(get_name=lambda: "ordinary" + SYMBOL_SUFFIX)
        main = SimpleNamespace(get_name=lambda: "main" + SYMBOL_SUFFIX)
        for kind in (gtirb.cfg.Edge.Type.Return, gtirb.cfg.Edge.Type.Call, gtirb.cfg.Edge.Type.Branch):
            edge = SimpleNamespace(label=SimpleNamespace(type=kind, direct=False))
            self.assertTrue(TransientIndirectBranchCheckDestPass._must_check_edge(edge, ordinary))
        # Preserve, rather than broaden, the pre-existing main-return exception.
        edge = SimpleNamespace(label=SimpleNamespace(type=gtirb.cfg.Edge.Type.Return, direct=False))
        self.assertFalse(TransientIndirectBranchCheckDestPass._must_check_edge(edge, main))


if __name__ == "__main__":
    unittest.main()
