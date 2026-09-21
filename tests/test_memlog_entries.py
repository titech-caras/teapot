from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import capstone_gt

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.configs.runtime import MEMORY_HISTORY_ENTRY_SIZE, MEMORY_HISTORY_SIZE_OFFSET
from teapot.passes.transient.memlog.aarch64 import AArch64TransientMemlogPass


class MemlogEntryTests(unittest.TestCase):
    def _check(self, arch, names, compiler, launcher):
        if not shutil.which(compiler) or launcher and not shutil.which(launcher[0]):
            self.skipTest("requires target compiler and execution environment")
        regs = [arch.abi.get_register(name) for name in names]
        for width in (1, 2, 3, 4, 7, 8, 10, 16, 24, 64):
            with self.subTest(arch=arch.name, width=width), tempfile.TemporaryDirectory() as directory:
                if arch.name == "aarch64":
                    decoder = capstone_gt.Cs(capstone_gt.CS_ARCH_ARM64, capstone_gt.CS_MODE_ARM)
                    decoder.detail = True
                    inst = next(decoder.disasm(bytes.fromhex("030000f9"), 0x1000))
                    memlog = AArch64TransientMemlogPass(
                        SimpleNamespace(abi=arch.abi), None, None, arch)
                    patch = memlog._build_patch(inst, arch.memory_operand(inst), width)
                    snippet = patch(SimpleNamespace(scratch_registers=regs, stack_adjustment=0))
                else:
                    snippet = arch.memlog_snippet(*regs, width)
                root = Path(directory)
                (root / "log.S").write_text(
                    (".intel_syntax noprefix\n" if arch.name == "x64" else "") +
                    ".text\n.global log_history\nlog_history:\n" + snippet +
                    '\nret\n.section .note.GNU-stack,"",%progbits\n')
                (root / "check.c").write_text("""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
struct entry history[16];
struct entry *memory_history_top = history;
extern void log_history(unsigned char *data);
int main(void) {
    unsigned char data[80], original[80];
    for (size_t i = 0; i < sizeof(data); i++) data[i] = i + 1;
    memcpy(original, data, sizeof(data));
    for (size_t offset = 0; offset < 8; offset++) {
        memset(history, 0xa5, sizeof(history));
        log_history(data + offset);
        size_t logged = 0;
        for (struct entry *p = history; p < memory_history_top; p++) {
            size_t size = WIDTH - logged < 8 ? WIDTH - logged : 8;
            if (p->addr != data + offset + logged || p->size != size) return 1;
            if (memcmp(&p->data, original + offset + logged, size)) return 2;
            for (size_t i = size; i < sizeof(p->data); i++)
                if (((unsigned char *)&p->data)[i] != 0xa5) return 3;
            for (size_t i = 0; i < sizeof(p->padding); i++) {
                if (p->padding[i] != 0xa5) {
                    fprintf(stderr, "memlog modified padding at width=%d entry=%zu byte=%zu\\n",
                            WIDTH, (size_t)(p - history), i);
                    return 4;
                }
            }
            logged += size;
        }
        if (logged != WIDTH || (unsigned char *)memory_history_top - (unsigned char *)history
                != ((WIDTH + 7) / 8) * ENTRY_SIZE) return 5;
        memset(data + offset, 0, WIDTH);
        while (memory_history_top != history) {
            struct entry *p = --memory_history_top;
            memcpy(p->addr, &p->data, p->size);
        }
        if (memcmp(data, original, sizeof(data))) return 6;
    }
    return 0;
}
_Static_assert(sizeof(struct entry) == ENTRY_SIZE, "history stride");
_Static_assert(offsetof(struct entry, size) == SIZE_OFFSET, "size offset");
""")
                command = [compiler, "-O2", "-no-pie", f"-DWIDTH={width}",
                           f"-DENTRY_SIZE={MEMORY_HISTORY_ENTRY_SIZE}",
                           f"-DSIZE_OFFSET={MEMORY_HISTORY_SIZE_OFFSET}",
                           str(root / "check.c"), str(root / "log.S"), "-o", str(root / "check")]
                if arch.name == "riscv64":
                    command.append("-Wl,--no-relax")
                compiled = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                result = subprocess.run(launcher + [str(root / "check")],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(platform.machine() == "x86_64", "requires native x64")
    def test_x64_entries(self):
        self._check(X64Architecture(), ("rdi", "rsi", "rdx"), "cc", [])

    def test_aarch64_entries(self):
        self._check(AArch64Architecture(), ("x0", "x1", "x2"), "aarch64-linux-gnu-gcc",
                    ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"])

    def test_riscv64_entries(self):
        self._check(RISCV64Architecture(), ("a0", "t0", "t1"), "riscv64-linux-gnu-gcc",
                    ["qemu-riscv64", "-L", "/usr/riscv64-linux-gnu"])


if __name__ == "__main__":
    unittest.main()
