"""Execute the actual emitted software target predicate and normal bouncer.

These are regression gates for hardware experiments, not a hardware backend.
In software mode every ISA checks the marker pair alone, for branches, calls and
returns alike. A target whose pair load faults is rejected, as the runtime rolls
a fault during simulation back. The combined AArch64 mode keeps one window
(normal text through the copy's end) around the same pair test.
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
from teapot.arch.aarch64.bti import AArch64BTIArchitecture
from teapot.arch.decoders import aarch64_decoder
from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.passes.transient.indirect_branch_check_pass import TransientIndirectBranchCheckDestPass


class IndirectTargetPolicyTests(unittest.TestCase):
    def _execute(self, arch, compiler, launcher, operand, scratch, result, *, signed=False,
                 window=False):
        if not shutil.which(compiler) or launcher and not shutil.which(launcher[0]):
            self.skipTest("requires target compiler and emulator")
        symbols = [gtirb.Symbol(name=name) for name in (
            "transient_start", "transient_end", "text_start", "text_end")]
        options = {'strip_pac': True} if signed else {}
        if window:
            options['window'] = True
        check = arch.indirect_branch_check_patch(operand, *symbols, **options)(
            SimpleNamespace(scratch_registers=scratch))
        bouncer = arch.indirect_branch_target_patch(
            gtirb.Symbol(name="transient_bounced"), use_scratch_registers=arch.name != "x64")(
                SimpleNamespace(scratch_registers=scratch))
        # x64 also has a pad for places where the flags are dead.
        flagless = ""
        if arch.name == "x64":
            flagless = "\n".join((".global flagless_bouncer", ".p2align 4", "flagless_bouncer:",
                                  arch.indirect_branch_target_patch(
                                      gtirb.Symbol(name="transient_bounced"), flags_live=False)(
                                          SimpleNamespace(scratch_registers=scratch)),
                                  f"{result} 0", "ret"))
        directive = ".long" if arch.name == "x64" else ".word"
        marker = "\n".join(f"{directive} 0x{word:08x}" for word in arch.MAGIC_WORDS)
        landing = {"x64": 0xfa1e0ff3, "aarch64": 0xd50324df, "riscv64": 0x00000013}[arch.name]
        assembly = f"""
{'.intel_syntax noprefix' if arch.name == 'x64' else ''}
{'.option norelax' if arch.name == 'riscv64' else ''}
{'.arch armv8.3-a' if signed else ''}
.text
.global check_target
check_target:
{'mov x3, x0; pacia x0, x1' if signed else ''}
{check}
{'autia x0, x1; cmp x0, x3; b.ne restore_checkpoint_MALFORMED_INDIRECT_BR' if signed else ''}
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
.global other_module_target
other_module_target:
{marker}
{result} 98
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
{flagless}
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
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern int check_target(uintptr_t), normal_bouncer(void), flagless_bouncer(void);
#pragma weak flagless_bouncer
extern uint64_t checkpoint_cnt;
extern unsigned char text_start[], text_end[], transient_start[], transient_end[];
extern unsigned char complete_marker[], wrong_second[], bare_landing[], prefixed_marker[];
extern unsigned char trusted_runtime_landing[], marker_crossing_end[], other_module_target[];
/* A fault while checking or reading a target is a rejection: during
   simulation the runtime turns a kernel fault into a rollback. */
static sigjmp_buf fault;
static void on_fault(int sig) { (void)sig; siglongjmp(fault, 1); }
static int guarded_check(uintptr_t p) {
    if (sigsetjmp(fault, 1)) return 0;
    return check_target(p);
}
static int expected(uintptr_t p) {
#ifdef WINDOW_PREDICATE
    /* Combined mode: an in-window target needs the pair; returns keep the
       copy sub-range clause through a separate option. */
    if (p < (uintptr_t)text_start || p >= (uintptr_t)transient_end) return 0;
#endif
    if (sigsetjmp(fault, 1)) return 0;
    uint32_t a, b;
    memcpy(&a, (void *)p, 4);
    memcpy(&b, (void *)(p + 4), 4);
    return a == MAGIC0 && b == MAGIC1;
}
#define check_target guarded_check
int main(void) {
    signal(SIGSEGV, on_fault);
    signal(SIGBUS, on_fault);
    uintptr_t fixed[] = {0, UINTPTR_MAX, (uintptr_t)text_start - 1, (uintptr_t)text_end,
        (uintptr_t)transient_start - 1, (uintptr_t)transient_end,
        (uintptr_t)trusted_runtime_landing};
    unsigned count = 0;
    for (unsigned i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        assert(check_target(fixed[i]) == expected(fixed[i])); count++;
    }
    /* Every byte, not just block starts or aligned instruction addresses. */
    for (uintptr_t p = (uintptr_t)transient_start; p < (uintptr_t)transient_end; p++) {
        assert(check_target(p) == expected(p)); count++;
    }
    for (uintptr_t p = (uintptr_t)text_start; p < (uintptr_t)text_end; p++) {
        assert(check_target(p) == expected(p)); count++;
    }
    /* Instrumented code elsewhere carries the pair; uninstrumented code does not. */
    assert(check_target((uintptr_t)trusted_runtime_landing) == 0);
#ifdef WINDOW_PREDICATE
    assert(check_target((uintptr_t)other_module_target) == 0);
#else
    assert(check_target((uintptr_t)other_module_target) == 1);
#endif
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
#ifdef FLAGLESS_BOUNCER
    assert(check_target((uintptr_t)flagless_bouncer) == 1);
    for (uint64_t count = 0; count < 3; count++) {
        checkpoint_cnt = count;
        assert(flagless_bouncer() == (count != 0));
    }
#endif
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
                       *(["-DWINDOW_PREDICATE"] if window else []),
                       *(["-DFLAGLESS_BOUNCER"] if flagless else []),
                       str(root / "policy.c"), str(root / "policy.S"), "-o", str(root / "policy")]
            built = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run(launcher + [str(root / "policy")], capture_output=True,
                                 text=True, timeout=15)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    def test_x64_exact_target_policy(self):
        if platform.machine() not in ("x86_64", "amd64"):
            self.skipTest("requires native x64")
        arch = X64Architecture()
        scratch = tuple(arch.abi.get_register(name) for name in ("r8", "r9"))
        self._execute(arch, "gcc", [], "rdi", scratch, "mov eax,")

    def test_aarch64_exact_target_policy(self):
        arch = AArch64Architecture()
        scratch = tuple(arch.abi.get_register(name) for name in ("x8", "x9", "x10"))
        for window in (False, True):
            with self.subTest(window=window):
                self._execute(arch, "aarch64-linux-gnu-gcc",
                              ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"],
                              "x0", scratch, "mov w0,", window=window)

    def test_only_the_combined_mode_keeps_the_window_and_return_clause(self):
        ret, br = SimpleNamespace(mnemonic="ret"), SimpleNamespace(mnemonic="br")
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            with self.subTest(isa=arch.name):
                self.assertEqual(arch.indirect_branch_check_options(ret), {})
                self.assertEqual(arch.indirect_branch_check_options(br), {})
        bti = AArch64BTIArchitecture()
        self.assertEqual(bti.indirect_branch_check_options(ret), {"window": True, "ret_clause": True})
        self.assertEqual(bti.indirect_branch_check_options(br), {"window": True})

    def test_aarch64_signed_targets_keep_the_exact_policy_and_original_pointer(self):
        arch = AArch64Architecture()
        for encoded, operand in (('22081fd7', 'x1'), ('43083fd7', 'x2'),
                                 ('3f081fd6', 'x1'), ('ff0b5fd6', 'x30')):
            inst, = aarch64_decoder().disasm(bytes.fromhex(encoded), 0)
            edge = gtirb.Edge.Type.Return if inst.mnemonic.startswith('ret') else gtirb.Edge.Type.Branch
            with self.subTest(instruction=str(inst)):
                self.assertEqual(arch.indirect_branch_operand(edge, inst), operand)
                self.assertEqual(arch.indirect_branch_check_options(inst), {'strip_pac': True})
                self.assertTrue(arch.dift_should_skip_instruction(inst))
        scratch = tuple(arch.abi.get_register(name) for name in ('x8', 'x9', 'x10'))
        self._execute(arch, 'aarch64-linux-gnu-gcc',
                      ['qemu-aarch64', '-cpu', 'max', '-L', '/usr/aarch64-linux-gnu'],
                      'x0', scratch, 'mov w0,', signed=True)

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

    def test_riscv_direct_pairs_are_not_checked(self):
        from unittest.mock import Mock

        from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder

        from teapot.arch import RISCV64Architecture

        # The production decoder. tail: auipc t1,0; jr 0(t1), the target named by
        # PCREL HI/LO relocations; the lift gives it an indirect edge (here the
        # only one, as if listed first). call: auipc ra,0; jalr ra,0(ra) with a PLT relocation.
        # jump: jalr zero,8(a5), a real register target. ret.
        module = gtirb.Module(name="rv", isa=gtirb.Module.ISA.ValidButUnsupported,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        ir = gtirb.IR(modules=[module])
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, address=0x1000, contents=bytes.fromhex(
            "17030000" "67000300" "97000000" "e7800000" "67808700" "67800000" "67800000"))
        blocks = {name: gtirb.CodeBlock(offset=offset, size=size, byte_interval=interval)
                  for name, offset, size in (("tail", 0, 8), ("call", 8, 8), ("jump", 16, 4),
                                             ("ret", 20, 4), ("target", 24, 4))}
        attrs = gtirb.SymbolicExpression.Attribute
        target = gtirb.Symbol(name="target", payload=blocks["target"], module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, target, {attrs.PCREL, attrs.HI})
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name=".Lpcrel_hi", payload=blocks["tail"], module=module), {attrs.PCREL, attrs.LO})
        interval.symbolic_expressions[8] = gtirb.SymAddrConst(0, target, {attrs.PLT})

        def edge(source, kind, direct, to=blocks["target"]):
            ir.cfg.add(gtirb.Edge(blocks[source], to, gtirb.Edge.Label(kind, direct=direct)))

        edge("tail", gtirb.Edge.Type.Branch, False, gtirb.ProxyBlock(module=module))
        edge("call", gtirb.Edge.Type.Call, False, gtirb.ProxyBlock(module=module))
        edge("jump", gtirb.Edge.Type.Branch, False, gtirb.ProxyBlock(module=module))
        edge("ret", gtirb.Edge.Type.Return, False, gtirb.ProxyBlock(module=module))
        visitor = TransientIndirectBranchCheckDestPass.__new__(TransientIndirectBranchCheckDestPass)
        visitor.arch = RISCV64Architecture()
        visitor.decoder = CachedGtirbInstructionDecoder(module.isa)
        visitor.reg_manager = None
        visitor.transient_section = section
        (visitor.transient_section_start_symbol, visitor.transient_section_end_symbol,
         visitor.text_section_start_symbol, visitor.text_section_end_symbol) = (
            gtirb.Symbol(name=name) for name in ("ts", "te", "xs", "xe"))
        visitor.insert_at = Mock()
        ordinary = SimpleNamespace(get_name=lambda: "f" + SYMBOL_SUFFIX)
        checked = set()
        for name in ("tail", "call", "jump", "ret"):
            visitor.insert_at.reset_mock()
            visitor.visit_code_block(blocks[name], ordinary)
            if visitor.insert_at.called:
                checked.add(name)
        self.assertEqual(checked, {"jump", "ret"})


if __name__ == "__main__":
    unittest.main()
