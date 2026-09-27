from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from teapot.arch.x64.architecture import X64Architecture
from teapot.configs.runtime import MEMORY_HISTORY_ENTRY_SIZE, MEMORY_HISTORY_SIZE_OFFSET, SCRATCHPAD_SIZE
from teapot.arch.decoders import x64_decoder
from teapot.passes.transient.lazy_dift import transient_replay_pass
from dift_replay_test_support import replay_asm


@unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc"),
                     "requires native x64 and a C compiler")
class X64DiftHistoryTests(unittest.TestCase):
    def test_tag_writes_and_history_cover_exactly_the_same_bytes(self):
        arch = X64Architecture()
        dift = transient_replay_pass(arch,
            SimpleNamespace(abi=arch.abi), None, None,
            dift_layout=SimpleNamespace(xor_mask=0), insert_memlog=True)
        inst = next(x64_decoder().disasm(bytes.fromhex('488907'), 0x1000))
        # Non-power-of-two tails cover x87 and multi-value memory widths too.
        for size in (1, 2, 3, 4, 8, 10, 16, 24, 32, 64):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                patch = replay_asm(dift, inst,
                    set(), set(), clear_dest_tags=True, mem_read=None,
                    mem_write="[rdi]", mem_write_size=size)
                (root / "patch.S").write_text(
                    ".intel_syntax noprefix\n.text\n.globl update_tags\n"
                    "update_tags:\n" + patch +
                    '\nret\n.section .note.GNU-stack,"",@progbits\n')
                (root / "check.c").write_text("""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
struct entry history[64];
struct entry *memory_history_top = history;
unsigned char scratchpad[SCRATCHPAD_BYTES] __attribute__((aligned(16)));
uintptr_t old_rsp;
extern void update_tags(unsigned char *tags);
int main(void) {
    unsigned char tags[80], original[80];
    for (size_t i = 0; i < sizeof(tags); ++i) tags[i] = i + 1;
    memcpy(original, tags, sizeof(tags));
    update_tags(tags + 1);
    size_t logged = 0;
    for (struct entry *p = history; p < memory_history_top; ++p) {
        if (p->size == 0 || p->size > 8 || p->addr != tags + 1 + logged) return 1;
        logged += p->size;
    }
    if (logged != WIDTH) return 2;
    for (size_t i = 0; i < sizeof(tags); ++i)
        if (tags[i] != (i >= 1 && i < WIDTH + 1 ? 0 : original[i])) return 3;
    while (memory_history_top != history) {
        struct entry *p = --memory_history_top;
        memcpy(p->addr, &p->data, p->size);
    }
    return memcmp(tags, original, sizeof(tags)) != 0;
}
""" + f"""
_Static_assert(sizeof(struct entry) == {MEMORY_HISTORY_ENTRY_SIZE}, "history stride");
_Static_assert(offsetof(struct entry, size) == {MEMORY_HISTORY_SIZE_OFFSET}, "size offset");
""")
                compiled = subprocess.run([
                    "cc", "-O2", "-no-pie", f"-DWIDTH={size}", f"-DSCRATCHPAD_BYTES={SCRATCHPAD_SIZE}",
                    str(root / "check.c"), str(root / "patch.S"),
                    "-o", str(root / "check"),
                ], capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                result = subprocess.run([str(root / "check")], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
