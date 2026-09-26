from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from teapot.arch import AArch64Architecture, RISCV64Architecture
from teapot.arch.decoders import aarch64_decoder, riscv64_decoder
from teapot.configs.runtime import SCRATCHPAD_SIZE
from teapot.configs.slots import AARCH64_SHADOW_STACK_SIZE, RISCV64_ORIGINAL_TP_OFFSET
from teapot.passes.common.dift.aarch64 import AArch64DiftPropagationPass
from teapot.passes.common.dift.riscv64 import RISCV64DiftPropagationPass


class RISCDiftHistoryTests(unittest.TestCase):
    def _check(self, arch, compiler, launcher, *, pair=False, spares=()):
        if not shutil.which(compiler) or not shutil.which(launcher[0]):
            self.skipTest("requires target compiler and execution environment")
        if arch.name == "aarch64":
            decoder = aarch64_decoder()
            instruction = bytes.fromhex("010800a9" if pair else "010000f9")
            pass_type = AArch64DiftPropagationPass
            source_names = ("x1", "x2") if pair else ("x1",)
            prologue = f"""
                mov x9, sp
                {arch.load_address('x10', 'test_stack_top')}
                mov sp, x10
            """
            epilogue = "mov sp, x9"
            data = f"""
                .balign 16
            test_stack:
                .skip {AARCH64_SHADOW_STACK_SIZE + 1024}
            test_stack_top:
                .skip 3072
            """
        else:
            arch.install_decoder_compat()
            decoder = riscv64_decoder()
            instruction = bytes.fromhex("2330b500")  # sd a1, 0(a0)
            pass_type = RISCV64DiftPropagationPass
            source_names = ("a1",)
            prologue = f"""
                {arch.load_address('t2', f'scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}')}
                sd tp, 0(t2)
            """
            epilogue = data = ""
        inst = next(decoder.disasm(instruction, 0x1000))
        source_regs = {arch.abi.get_register(name) for name in source_names}
        source_ids = [arch.dift_register_id(arch.abi.get_register(name)) for name in source_names]
        dift = pass_type(SimpleNamespace(abi=arch.abi), None, None, arch,
                         dift_layout=SimpleNamespace(xor_mask=0), insert_memlog=True)
        live_registers = set(arch.abi.all_registers()) - {
            arch.abi.get_register(name) for name in spares}
        widths = (16,) if pair else (8, 24) if spares else (1, 2, 3, 4, 7, 8, 10, 16, 24, 64)
        for width in widths:
            with self.subTest(arch=arch.name, width=width, pair=pair), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                patch = dift._build_patch(
                    inst, source_regs, set(), clear_dest_tags=False,
                    mem_read=None, mem_write=arch.memory_operand(inst), mem_write_size=width,
                    live_registers=live_registers)
                (root / "patch.S").write_text(f"""
                    .text
                    .global update_tags
                update_tags:
                    {prologue}
                    {patch(SimpleNamespace(stack_adjustment=0))}
                    {epilogue}
                    ret
                    .bss
                    {data}
                    .section .note.GNU-stack,"",%progbits
                """)
                (root / "check.c").write_text("""
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
struct entry history[64];
struct entry *memory_history_top = history;
unsigned char scratchpad[SCRATCHPAD_BYTES] __attribute__((aligned(16)));
unsigned char dift_reg_tags[48];
extern void update_tags(unsigned char *tags);
static sigjmp_buf fault_return;
static void fault_handler(int signal) {
    (void)signal;
    siglongjmp(fault_return, 1);
}
static int try_update(unsigned char *tags) {
    if (sigsetjmp(fault_return, 1)) return 1;
    update_tags(tags);
    return 0;
}
static int try_replay(struct entry *entry) {
    if (sigsetjmp(fault_return, 1)) return 1;
    volatile unsigned char *dst = entry->addr;
    const unsigned char *src = (const unsigned char *)&entry->data;
    for (size_t i = 0; i < entry->size; ++i) dst[i] = src[i];
    return 0;
}
int main(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *mapping = mmap(NULL, 4 * page, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED || mprotect(mapping + page, 2 * page,
            PROT_READ | PROT_WRITE) != 0) return 10;
    unsigned char *tags = mapping + page, *original = malloc(2 * page);
    if (!original) return 11;
    size_t starts[] = {1, 2 * page - WIDTH, page - WIDTH / 2};
    dift_reg_tags[SOURCE0] = 0x15;
#ifdef PAIR
    dift_reg_tags[SOURCE1] = 0x22;
#endif
    for (size_t mode = 0; mode < sizeof(starts) / sizeof(starts[0]); ++mode) {
        size_t start = starts[mode];
        for (size_t i = 0; i < 2 * page; ++i) tags[i] = i % 251 + 1;
        memcpy(original, tags, 2 * page);
        memset(history, 0xa5, sizeof(history));
        memory_history_top = history;
        update_tags(tags + start);
        if (memory_history_top - history != (WIDTH + 7) / 8) return 1;
        size_t logged = 0;
        for (struct entry *p = history; p < memory_history_top; ++p) {
            size_t size = WIDTH - logged < 8 ? WIDTH - logged : 8;
            if (p->addr != tags + start + logged || p->size != size) return 2;
            if (memcmp(&p->data, original + start + logged, size)) return 3;
            for (size_t i = size; i < sizeof(p->data); ++i)
                if (((unsigned char *)&p->data)[i] != 0xa5) return 4;
            logged += size;
        }
        if (logged != WIDTH) return 5;
        for (size_t i = 0; i < 2 * page; ++i) {
            unsigned char expected = original[i];
            if (i >= start && i < start + WIDTH) {
                expected = 0x15;
#ifdef PAIR
                if (i - start >= WIDTH / 2) expected = 0x22;
#endif
            }
            if (tags[i] != expected) return 6;
        }
        while (memory_history_top != history) {
            struct entry *p = --memory_history_top;
            memcpy(p->addr, &p->data, p->size);
        }
        if (memcmp(tags, original, 2 * page)) return 7;
    }
    struct sigaction action = { .sa_handler = fault_handler };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL)) return 12;
    for (int readable = 0; readable <= 1; ++readable) {
        size_t prefix = WIDTH / 2;
        unsigned char *start = tags + page - prefix;
        for (size_t i = 0; i < 2 * page; ++i) tags[i] = i % 251 + 1;
        memcpy(original, tags, 2 * page);
        memory_history_top = history;
        if (mprotect(tags + page, page, readable ? PROT_READ : PROT_NONE)) return 13;
        if (!try_update(start)) return 14;
        size_t expected_entries = prefix / 8 + readable;
        if ((size_t)(memory_history_top - history) != expected_entries) return 15;
        int replay_faults = 0;
        while (memory_history_top != history)
            replay_faults += try_replay(--memory_history_top);
        if (readable && replay_faults != 1) return 16;
        if (mprotect(tags + page, page, PROT_READ | PROT_WRITE)) return 17;
        if (memcmp(tags, original, 2 * page)) return 18;
    }
    free(original);
    return munmap(mapping, 4 * page) != 0;
}
""")
                command = [compiler, "-O2", "-no-pie", f"-DWIDTH={width}",
                           f"-DSOURCE0={source_ids[0]}", f"-DSCRATCHPAD_BYTES={SCRATCHPAD_SIZE}",
                           str(root / "check.c"), str(root / "patch.S"), "-o", str(root / "check")]
                if pair:
                    command.extend(["-DPAIR", f"-DSOURCE1={source_ids[1]}"])
                if arch.name == "riscv64":
                    command.append("-Wl,--no-relax")
                compiled = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                result = subprocess.run(launcher + [str(root / "check")],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_aarch64_batched_tag_history(self):
        self._check(AArch64Architecture(), "aarch64-linux-gnu-gcc",
                    ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"])

    def test_aarch64_pair_tags_stay_distinct(self):
        self._check(AArch64Architecture(), "aarch64-linux-gnu-gcc",
                    ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"], pair=True)

    def test_riscv64_batched_tag_history(self):
        self._check(RISCV64Architecture(), "riscv64-linux-gnu-gcc",
                    ["qemu-riscv64", "-L", "/usr/riscv64-linux-gnu"])

    def test_lra_selected_registers_preserve_tag_history(self):
        for spares in (("x14", "x15"), ("x14", "x15", "x16", "x17", "nzcv")):
            with self.subTest(spares=spares):
                self._check(AArch64Architecture(), "aarch64-linux-gnu-gcc",
                            ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"], spares=spares)
        for spares in (("t3", "t4"), ("t3", "t4", "t5", "t6")):
            with self.subTest(spares=spares):
                self._check(RISCV64Architecture(), "riscv64-linux-gnu-gcc",
                            ["qemu-riscv64", "-L", "/usr/riscv64-linux-gnu"], spares=spares)


if __name__ == "__main__":
    unittest.main()
