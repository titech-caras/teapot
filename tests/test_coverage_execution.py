"""Speculative coverage reaches the fuzzer through rollbacks and nested windows.

Chains of Teapot's own checkpoint, trampoline and coverage-push code run on the
real runtime with nested speculation (tests/fixtures/coverage_checkpoint.c):
natively on x64, under QEMU on AArch64 and RISC-V. Built with COVERAGE, as for
a fuzzer, each rollback hands the fuzzer's Sanitizer Coverage callback exactly
the guards of the window it undoes, newest first, after the memory log; built
without it, the pushes reach nothing, which is why a rewrite for such a runtime
leaves them out.
"""
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from uuid import uuid4

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.configs.slots import AARCH64_SHADOW_STACK_SIZE
from teapot.utils.misc import generate_distinct_label_name
from test_nested_checkpoint_execution import probe

RUNTIME = Path(__file__).resolve().parents[1] / "libcheckpoint"
# The hook each guard is pushed before: the outer window's, the inner window's,
# and the outer window's after the inner rollback.
GUARDS = {"probe_outer": 0, "probe_inner": 1, "probe_inner_restored": 2}
# Free at those calls: not an argument, not a checked or spare register.
PUSH_REGISTERS = {"x64": ("rax",), "aarch64": ("x12", "x13"), "riscv64": ("t5", "t6")}


def x64_probe(arch, count, taken):
    """test_nested_checkpoint_execution.probe for x64: one chain, two windows."""
    text, transient = uuid4(), uuid4()
    name = f"probe_{count}_{taken}"

    def checkpoint(block):
        return arch.checkpoint_patch(block, vector_case=0)(SimpleNamespace(scratch_registers=("rax",))).replace(
            ".L__after_checkpoint__teapot__", f".Lafter_{block.hex}")

    counter = generate_distinct_label_name(".__branch_counter_", text)
    nested_counter = generate_distinct_label_name(".__branch_counter_", transient)
    fall, branch = f".Lfall_{name}", f".Lbranch_{name}"
    trampoline = arch.trampoline_patch(text, transient, "je", "", fall, branch)(SimpleNamespace())
    condition = f"mov ecx, {1 - taken}\ncmp ecx, 0"
    return f"""
        .text
        .globl {name}
        .type {name}, @function
        {name}:
            push rbx
            {condition}
            {checkpoint(text)}
            call probe_finished
            pop rbx
            ret
        {trampoline}
        {fall}:
            mov esi, 1
            jmp .Lbody_{name}
        {branch}:
            xor esi, esi
        .Lbody_{name}:
            pushfq
            pop rdx
            mov rdi, qword ptr [rip + checkpoint_cnt]
            cmp rdi, 2
            je .Ldeep_{name}
            call probe_outer
            {condition}
            {checkpoint(transient)}
            call probe_inner_restored
            jmp restore_checkpoint_ROB_LEN
        .Ldeep_{name}:
            call probe_inner
            jmp restore_checkpoint_ROB_LEN
        .data
        .balign 4
        {counter}:
        {nested_counter}:
            .long 0
        """


def with_coverage_pushes(arch, text):
    """Put Teapot's coverage push for each hook's guard right before its call."""
    def push(match):
        patch = arch.coverage_patch(GUARDS[match.group(3)])(
            SimpleNamespace(scratch_registers=PUSH_REGISTERS[arch.name]))
        return f"{match.group(1)}{patch}\n{match.group(1)}{match.group(2)} {match.group(3)}"
    result, count = re.subn(r"^([ \t]*)(bl|call) (probe_outer|probe_inner|probe_inner_restored)[ \t]*$", push, text,
                            flags=re.M)
    assert count == 3, count
    return result


def program(arch):
    probes = []
    for count in range(3):
        for taken in range(2):
            text = x64_probe(arch, count, taken) if arch.name == "x64" else probe(arch, count, taken)
            probes.append(with_coverage_pushes(arch, text))
    # The guard section Teapot's coverage pass emits for three transient blocks.
    guards = ('.section .teapot_guards,"aw",@progbits\n.balign 4\n'
              ".globl __guard_start__teapot__, __guard_end__teapot__\n"
              "__guard_start__teapot__:\n.zero 12\n__guard_end__teapot__:\n")
    syntax = ".intel_syntax noprefix\n" if arch.name == "x64" else ""
    return syntax + "\n".join(probes) + guards + '\n.section .note.GNU-stack,"",@progbits\n'


class CoverageExecutionTests(unittest.TestCase):
    def check_arch(self, arch, compiler, emulator):
        if not shutil.which(compiler) or not shutil.which("cmake") or (emulator and not shutil.which(emulator)):
            self.skipTest(f"requires {compiler}, {emulator or 'native execution'} and cmake")
        for coverage in (True, False):
            with self.subTest(coverage=coverage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                # The runtime's record and the fingerprint a module record names
                # come from configuring the runtime in this coverage mode.
                contract = root / "contract-build"
                command = ["cmake", "-S", str(RUNTIME), "-B", str(contract), "-DBUILD_TESTING=OFF",
                           f"-DCHECKPOINT_ARCH={arch.name if arch.name != 'x64' else 'x86_64'}",
                           f"-DTEAPOT_ENABLE_COVERAGE={'ON' if coverage else 'OFF'}"]
                if emulator:
                    command += ["-DCMAKE_SYSTEM_NAME=Linux", f"-DCMAKE_SYSTEM_PROCESSOR={arch.name}",
                                f"-DCMAKE_C_COMPILER={compiler}", f"-DCMAKE_ASM_COMPILER={compiler}"]
                configure = subprocess.run(command, text=True, capture_output=True)
                self.assertEqual(configure.returncode, 0, configure.stdout + configure.stderr)
                assembly = root / "probes.S"
                assembly.write_text(program(arch))
                executable = root / "probes"
                command = [compiler, "-O2", "-no-pie", "-DENABLE_NESTED_SPECULATION", "-DDISABLE_DIFT_RUNTIME",
                           "-DDIFT_XOR_MASK=0", "-fno-stack-protector",
                           "-DCOVERAGE" if coverage else "-DEXPECT_NO_COVERAGE",
                           "-I", str(RUNTIME / "include"), "-I", str(contract / "include"),
                           str(Path(__file__).with_name("fixtures") / "coverage_checkpoint.c"),
                           str(assembly), str(RUNTIME / f"asm/checkpoint_{arch.name}.S"),
                           str(RUNTIME / "asm/storage.S"), str(contract / "contract/runtime_contract_record.S"),
                           str(RUNTIME / "tests/contract_module_record.c")]
                command += [str(RUNTIME / "src" / source) for source in (
                    "checkpoint.c", "signal_handler.c", "dift_support.c", "report_gadget.c",
                    "dift_wrappers/dift_wrappers.c")]
                if arch.name == "riscv64":
                    command += ["-Wl,--no-relax"]
                result = subprocess.run(command + ["-o", str(executable), "-lm"], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                run = [str(executable)]
                if emulator:
                    run = [emulator, "-L", "/usr/" + compiler[:-len("-gcc")]] + run
                    if arch.name == "aarch64":
                        # Room for the runtime's fixed-offset helper stack, as in
                        # test_nested_checkpoint_execution.
                        run[1:1] = ["-R", "0x40000000000", "-s", str(4 * AARCH64_SHADOW_STACK_SIZE)]
                result = subprocess.run(run, text=True, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("6 coverage chains passed", result.stdout)

    @unittest.skipUnless(platform.machine() == "x86_64", "requires native x64")
    def test_x64_coverage_through_nested_rollbacks(self):
        self.check_arch(X64Architecture(), "gcc", None)

    def test_aarch64_coverage_through_nested_rollbacks(self):
        self.check_arch(AArch64Architecture(), "aarch64-linux-gnu-gcc", "qemu-aarch64")

    def test_riscv64_coverage_through_nested_rollbacks(self):
        self.check_arch(RISCV64Architecture(), "riscv64-linux-gnu-gcc", "qemu-riscv64")


if __name__ == "__main__":
    unittest.main()
