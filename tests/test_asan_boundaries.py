from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.configs.runtime import ASAN_TAG_STORAGE_MTE, ASAN_TAG_STORAGE_SHADOW, SYMBOL_SUFFIX


class AsanBoundaryTests(unittest.TestCase):
    WIDTHS = (1, 2, 3, 4, 5, 7, 8, 10, 16, 24, 32, 64, 128)

    def test_policy_allocates_the_end_register(self):
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            storages = (ASAN_TAG_STORAGE_SHADOW, ASAN_TAG_STORAGE_MTE) if arch.name == "aarch64" \
                else (ASAN_TAG_STORAGE_SHADOW,)
            for storage in storages:
                for enabled in (True, False):
                    policy = arch.create_transient_mem_operand_policy_pass(
                        SimpleNamespace(abi=arch.abi), None, None,
                        dift_layout=SimpleNamespace(asan_shadow_offset=0),
                        enable_asan_check=enabled, asan_tag_storage=storage)
                    for width in (1, 2, 8, 16):
                        with self.subTest(arch=arch.name, storage=storage, enabled=enabled, width=width):
                            if arch.name == "x64":
                                with mock.patch.object(type(arch), "mem_operand_registers", return_value=set()):
                                    patch = policy._build_patch(
                                        None, "[rdi]", width, conditional=None,
                                        mem_operand=None, write_reg=arch.abi.get_register("rax"))
                            else:
                                patch = policy._build_patch(None, None, width, [], None)
                            expected = 5 if enabled and width > 1 else 4
                            if arch.name == "x64" and not enabled:
                                expected = 3
                            self.assertEqual(patch.constraints.scratch_registers, expected)

    def test_small_shadow_checks_are_unrolled(self):
        cases = ((X64Architecture(), ("rdi", "rsi", "rdx", "rcx"), "jmp"),
                 (AArch64Architecture(), ("x0", "x1", "x2", "x3"), "b"),
                 (RISCV64Architecture(), ("a0", "t0", "t1", "t2"), "j"))
        for arch, names, branch in cases:
            addr, shadow, scratch, end = (arch.abi.get_register(name) for name in names)
            for width in (1, 2, 8, 9, 16):
                with self.subTest(arch=arch.name, width=width):
                    snippet = arch.asan_check_snippet(
                        addr, width, ".Lok", shadow_offset=0, shadow_reg=shadow,
                        scratch_reg=scratch, end_reg=end)
                    back_edge = ("jmp .Lok_shadow_loop" if arch.name == "x64" else
                                 f"{branch} .L__asan_shadow_check_loop{SYMBOL_SUFFIX}")
                    self.assertEqual(back_edge in snippet, width > 8)
                    if width > 1:
                        with self.assertRaises(ValueError):
                            arch.asan_check_snippet(
                                addr, width, ".Lok", shadow_offset=0,
                                shadow_reg=shadow, scratch_reg=scratch)

    def _check(self, arch, compiler, launcher, names, result, *, mte=False):
        if not shutil.which(compiler) or launcher and not shutil.which(launcher[0]):
            self.skipTest("requires target compiler and execution environment")
        addr, shadow, scratch, end = (arch.abi.get_register(name) for name in names)
        assembly = [".intel_syntax noprefix" if arch.name == "x64" else "", ".text"]
        for width in self.WIDTHS:
            ok = f".Lcheck_ok_{width}"
            snippet = arch.asan_check_snippet(
                addr, width, ok, shadow_offset=0, shadow_reg=shadow,
                scratch_reg=scratch, end_reg=end,
                tag_storage=ASAN_TAG_STORAGE_MTE if mte else ASAN_TAG_STORAGE_SHADOW)
            assembly.append(f".global check_{width}\ncheck_{width}:\n" +
                            snippet.replace(SYMBOL_SUFFIX, f"_width_{width}") +
                            f"\n{result} 0\nret\n{ok}:\n{result} 1\nret\n")
        assembly.append('.section .note.GNU-stack,"",%progbits\n')
        declarations = "\n".join(f"extern int check_{width}(uintptr_t);" for width in self.WIDTHS)
        entries = ",".join(f"{{{width}, check_{width}}}" for width in self.WIDTHS)
        source = """
#include <stdint.h>
#include <stdio.h>
#include <string.h>
""" + declarations + """
struct check { unsigned width; int (*run)(uintptr_t); };
static const struct check checks[] = {
""" + entries + "\n};\n" + (self._mte_source() if mte else self._shadow_source())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "checks.S").write_text("\n".join(assembly))
            (root / "check.c").write_text(source)
            compiled = subprocess.run([
                compiler, "-O2", "-no-pie", str(root / "check.c"), str(root / "checks.S"),
                "-o", str(root / "check"),
            ], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            run = subprocess.run(launcher + [str(root / "check")], capture_output=True, text=True,
                                 timeout=30)
            if mte and run.returncode == 77:
                self.skipTest("execution environment does not provide MTE allocation tags")
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    @staticmethod
    def _shadow_source():
        return """
int main(void) {
    unsigned char shadow[32] __attribute__((aligned(16)));
    const unsigned char tags[] = {0, 1, 2, 3, 4, 5, 6, 7, 0x80, 0xf1, 0xfa, 0xff};
    unsigned failures = 0;
    for (unsigned c = 0; c < sizeof(checks) / sizeof(checks[0]); c++) {
        unsigned width = checks[c].width;
        for (unsigned offset = 0; offset < 16; offset++) {
            unsigned first = offset / 8, last = (offset + width - 1) / 8;
            for (unsigned slot = first; slot <= last; slot++) {
                for (unsigned t = 0; t < sizeof(tags); t++) {
                    memset(shadow, 0xff, sizeof(shadow));
                    memset(shadow + first, 0, last - first + 1);
                    shadow[slot] = tags[t];
                    int expected = 1;
                    for (unsigned i = offset; i < offset + width; i++) {
                        unsigned char tag = shadow[i / 8];
                        if (tag && (tag >= 8 || i % 8 >= tag)) expected = 0;
                    }
                    /* Only the shadow is dereferenced by the generated check. */
                    uintptr_t address = ((uintptr_t)shadow << 3) + offset;
                    int actual = checks[c].run(address);
                    if (actual != expected) {
                        if (failures++ < 10)
                            fprintf(stderr, "width=%u offset=%u slot=%u tag=%u got=%d expected=%d\\n",
                                    width, offset, slot, tags[t], actual, expected);
                    }
                }
            }
        }
    }
    if (failures) fprintf(stderr, "%u boundary mismatches\\n", failures);
    return failures != 0;
}
"""

    @staticmethod
    def _mte_source():
        return """
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#ifndef HWCAP2_MTE
#define HWCAP2_MTE (1UL << 18)
#endif
#ifndef PROT_MTE
#define PROT_MTE 0x20
#endif
#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL 55
#endif
static void set_tag(uintptr_t address, unsigned tag) {
    uintptr_t tagged = address | ((uintptr_t)tag << 56);
    __asm__ volatile(".arch armv8.5-a+memtag\\nstg %0, [%0]" :: "r"(tagged) : "memory");
}
int main(void) {
    if (!(getauxval(AT_HWCAP2) & HWCAP2_MTE)) return 77;
    /* Tagged addresses enabled; both hardware tag-fault modes remain disabled. */
    if (prctl(PR_SET_TAGGED_ADDR_CTRL, 1UL | (0xffffUL << 3), 0, 0, 0)) return 2;
    size_t size = (size_t)sysconf(_SC_PAGESIZE);
    void *memory = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_MTE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return 3;
    uintptr_t base = (uintptr_t)memory;
    const unsigned logical_tags[] = {0, 7, 15};
    unsigned failures = 0;
    for (unsigned c = 0; c < sizeof(checks) / sizeof(checks[0]); c++) {
        unsigned width = checks[c].width;
        for (unsigned offset = 0; offset < 32; offset++) {
            unsigned first = offset / 16, last = (offset + width - 1) / 16;
            for (unsigned t = 0; t < sizeof(logical_tags) / sizeof(logical_tags[0]); t++) {
                unsigned logical = logical_tags[t];
                for (unsigned slot = 0; slot < 12; slot++) {
                    for (unsigned i = 0; i < 12; i++) set_tag(base + 16 * i, logical);
                    set_tag(base + 16 * slot, logical ^ 1);
                    int expected = slot < first || slot > last;
                    int actual = checks[c].run((base + offset) | ((uintptr_t)logical << 56));
                    if (actual != expected) {
                        if (failures++ < 10)
                            fprintf(stderr, "MTE width=%u offset=%u slot=%u tag=%u got=%d expected=%d\\n",
                                    width, offset, slot, logical, actual, expected);
                    }
                }
            }
        }
    }
    if (munmap(memory, size)) return 4;
    if (failures) fprintf(stderr, "%u MTE boundary mismatches\\n", failures);
    return failures != 0;
}
"""

    @unittest.skipUnless(platform.machine() == "x86_64", "requires native x64")
    def test_x64_shadow(self):
        self._check(X64Architecture(), "cc", [], ("rdi", "rsi", "rdx", "rcx"), "mov eax,")

    def test_aarch64_shadow(self):
        self._check(AArch64Architecture(), "aarch64-linux-gnu-gcc",
                    ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"],
                    ("x0", "x1", "x2", "x3"), "mov w0,")

    def test_riscv64_shadow(self):
        self._check(RISCV64Architecture(), "riscv64-linux-gnu-gcc",
                    ["qemu-riscv64", "-L", "/usr/riscv64-linux-gnu"],
                    ("a0", "t0", "t1", "t2"), "li a0,")

    def test_aarch64_mte(self):
        qemu = shutil.which("qemu-aarch64-mte") or "qemu-aarch64"
        self._check(AArch64Architecture(), "aarch64-linux-gnu-gcc",
                    [qemu, "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"],
                    ("x0", "x1", "x2", "x3"), "mov w0,", mte=True)


if __name__ == "__main__":
    unittest.main()
