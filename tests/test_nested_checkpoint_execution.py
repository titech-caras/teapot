"""Link emitted RISC checkpoints/trampolines to the real nested runtime."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from uuid import uuid4

from teapot.arch import AArch64Architecture, RISCV64Architecture
from teapot.configs.slots import AARCH64_SHADOW_STACK_SIZE, RISCV64_ORIGINAL_TP_OFFSET
from teapot.utils.misc import generate_distinct_label_name


def checkpoint(arch, block, spares):
    # Rewriting normally namespaces patch-local labels for each insertion.
    return arch.checkpoint_patch(block, spares)(SimpleNamespace()).replace(
        ".L__after_checkpoint__teapot__", f".Lafter_{block.hex}")


def probe(arch, count, taken):
    text, transient = uuid4(), uuid4()
    name = f"probe_{count}_{taken}"
    spares = (("x10", "x11") if arch.name == "aarch64" else ("t3", "t4"))[:count]
    outer = checkpoint(arch, text, spares)
    inner = checkpoint(arch, transient, spares)
    counter = generate_distinct_label_name(".__branch_counter_", text)
    nested_counter = generate_distinct_label_name(".__branch_counter_", transient)
    fall, branch = f".Lfall_{name}", f".Lbranch_{name}"
    # Both checkpoint copies use exactly the same saved-register assignment.
    trampoline = arch.trampoline_patch(
        text, transient, "b.eq" if arch.name == "aarch64" else "beq",
        "unused" if arch.name == "aarch64" else "a2, zero, unused",
        fall, branch, checkpoint_spare_registers=spares)(SimpleNamespace())
    if arch.name == "aarch64":
        condition = f"mov x8, #{1 - taken}\ncmp x8, #0"
        check = "cmp x16, #0x123\nb.ne 9f\ncmp x17, #0x456\nb.ne 9f"
        return f"""
        .text
        .global {name}
        .type {name}, %function
        {name}:
            mov x9, sp
            mov sp, x0
            stp x9, x30, [sp, #-16]!
            mov x16, #0x123
            mov x17, #0x456
            {condition}
            {outer}
            {check}
            bl probe_finished
            ldp x9, x30, [sp], #16
            mov sp, x9
            ret
        {trampoline}
        {fall}:
            mov x1, #1
            b .Lbody_{name}
        {branch}:
            mov x1, #0
        .Lbody_{name}:
            mrs x2, nzcv
            {check}
            ldr x0, =checkpoint_cnt
            ldr x0, [x0]
            cmp x0, #2
            b.eq .Ldeep_{name}
            bl probe_outer
            mov x16, #0x123
            mov x17, #0x456
            {condition}
            {inner}
            {check}
            bl probe_inner_restored
            b restore_checkpoint_ROB_LEN
        .Ldeep_{name}:
            bl probe_inner
            b restore_checkpoint_ROB_LEN
        9:
            brk #0
        .data
        .balign 4
        {counter}:
        {nested_counter}:
            .word 0
        """
    return f"""
        .option norelax
        .option norvc
        .text
        .global {name}
        .type {name}, @function
        {name}:
            addi sp, sp, -16
            sd ra, 0(sp)
            {arch.load_address('a3', f'scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}')}
            sd tp, 0(a3)
            li t0, 0x123
            li t1, 0x456
            li a2, {1 - taken}
            {outer}
            li a3, 0x123
            bne t0, a3, 9f
            li a3, 0x456
            bne t1, a3, 9f
            call probe_finished
            ld ra, 0(sp)
            addi sp, sp, 16
            ret
        {trampoline}
        {fall}:
            li a1, 1
            j .Lbody_{name}
        {branch}:
            li a1, 0
        .Lbody_{name}:
            li a3, 0x123
            bne t0, a3, 9f
            li a3, 0x456
            bne t1, a3, 9f
            {arch.load_address('a0', 'checkpoint_cnt')}
            ld a0, 0(a0)
            li a3, 2
            beq a0, a3, .Ldeep_{name}
            call probe_outer
            li t0, 0x123
            li t1, 0x456
            li a2, {1 - taken}
            {inner}
            li a3, 0x123
            bne t0, a3, 9f
            li a3, 0x456
            bne t1, a3, 9f
            call probe_inner_restored
            tail restore_checkpoint_ROB_LEN
        .Ldeep_{name}:
            call probe_inner
            tail restore_checkpoint_ROB_LEN
        9:
            ebreak
        .data
        .balign 4
        {counter}:
        {nested_counter}:
            .word 0
        """


class NestedCheckpointExecutionTests(unittest.TestCase):
    def check_arch(self, arch, prefix):
        compiler, emulator = prefix + "-gcc", "qemu-" + prefix.split("-")[0]
        if not shutil.which(compiler) or not shutil.which(emulator):
            self.skipTest(f"requires {compiler} and {emulator}")
        runtime = Path(__file__).resolve().parents[1] / "libcheckpoint"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly = root / "probe.S"
            assembly.write_text("\n".join(
                probe(arch, count, taken) for count in range(3) for taken in range(2)) +
                '\n.section .note.GNU-stack,"",@progbits\n')
            executable = root / "probe"
            command = [compiler, "-O2", "-no-pie", "-DENABLE_NESTED_SPECULATION",
                       "-DDISABLE_DIFT_RUNTIME", "-DDIFT_XOR_MASK=0", "-fno-stack-protector",
                       "-I", str(runtime / "include"),
                       str(Path(__file__).with_name("fixtures") / "nested_checkpoint.c"),
                       str(assembly), str(runtime / f"asm/checkpoint_{arch.name}.S"),
                       str(runtime / "asm/storage.S")]
            command += [str(runtime / "src" / source) for source in (
                "checkpoint.c", "signal_handler.c", "dift_support.c", "report_gadget.c",
                "dift_wrappers/dift_wrappers.c")]
            if arch.name == "riscv64":
                command += ["-Wl,--no-relax"]
            result = subprocess.run(command + ["-o", str(executable), "-lm"],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            emulator_args = [emulator, "-L", "/usr/" + prefix]
            if arch.name == "aarch64":
                # Leave room for the runtime's fixed-offset helper stack in
                # QEMU's guest stack mapping, as in the runtime execution suite.
                emulator_args += ["-R", "0x40000000000", "-s", str(4 * AARCH64_SHADOW_STACK_SIZE)]
            result = subprocess.run([*emulator_args, str(executable)],
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("6 nested checkpoint chains passed", result.stdout)

    def test_aarch64_nested_checkpoint_execution(self):
        self.check_arch(AArch64Architecture(), "aarch64-linux-gnu")

    def test_riscv64_nested_checkpoint_execution(self):
        self.check_arch(RISCV64Architecture(), "riscv64-linux-gnu")


if __name__ == "__main__":
    unittest.main()
