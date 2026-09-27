"""Execute replay and reader ordering, rather than matching code templates."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.passes.transient.lazy_dift import transient_replay_pass


class LazyDiftTests(unittest.TestCase):
    def _pass(self, arch):
        return transient_replay_pass(arch, SimpleNamespace(abi=arch.abi), None, None,
                                     dift_layout=SimpleNamespace(xor_mask=0))

    def _execute(self, arch, replay, source):
        cc = 'gcc' if arch.name == 'x64' else arch.name + '-linux-gnu-gcc'
        launcher = [] if arch.name == 'x64' else ['qemu-' + arch.name, '-L', '/usr/' + arch.name + '-linux-gnu']
        if not shutil.which(cc) or (launcher and not shutil.which(launcher[0])):
            self.skipTest('target compiler and execution environment required')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ir = replay._parse_and_optimize_llvm(replay._format_llvm_ir(
                '\n'.join(replay.llvm_ir), target_triple=replay.target_triple))
            # Validate the exact extractor too: no hidden runtime calls/pools.
            replay._extract_function_asm(replay.target_machine.emit_assembly(ir))
            (root/'replay.o').write_bytes(replay.target_machine.emit_object(ir))
            (root/'check.c').write_text(source)
            flags = ['-march=rv64gc', '-mabi=lp64d', '-Wl,--no-relax'] if arch.name == 'riscv64' else []
            result = subprocess.run([cc, '-O2', '-no-pie', *flags, root/'check.c', root/'replay.o',
                                     '-o', root/'check'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([*launcher, root/'check'], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_replay_logs_exact_bytes_and_applies_queue_after_destination_update(self):
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            for width in (1, 2, 3, 4, 7, 8, 10, 16, 24, 32, 64):
                with self.subTest(arch=arch.name, width=width):
                    replay = self._pass(arch)
                    replay._reset()
                    address = replay._load('i64', replay._build_gep('i64', 'scratchpad', 0,
                                                               ptr_type=replay.SCRATCHPAD_ARR_TYPE))
                    replay._store_shadow_mem_tags('64', address, 0, width)
                    replay._store('i8', '17', replay._build_gep('i8', 'dift_reg_tags', 0,
                                                            ptr_type=replay.DIFT_REG_TAGS_TYPE))
                    replay._after_instruction_effects(object())
                    self._execute(arch, replay, r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
struct entry history[64], *memory_history_top = history;
extern unsigned char dift_reg_tags[48];
extern uint64_t scratchpad[];
unsigned char dift_reg_queued_tags[48] __attribute__((aligned(16)));
unsigned char dift_reg_queue_pending[8];
extern void func(void);
int main(void) {
    unsigned char tags[80], before[80];
    for (unsigned i=0; i<sizeof tags; ++i) tags[i] = i;
    memcpy(before, tags, sizeof tags);
    scratchpad[0] = (uintptr_t)(tags + 3); /* deliberately unaligned */
    dift_reg_tags[0] = 128;
    dift_reg_queued_tags[0] = 32;
    dift_reg_queued_tags[47] = 2;
    dift_reg_queue_pending[0] = 1;
    func();
    assert(dift_reg_tags[0] == 49 && dift_reg_tags[47] == 2);
    assert(!dift_reg_queue_pending[0]);
    for (unsigned i=0; i<48; ++i) assert(!dift_reg_queued_tags[i]);
    for (unsigned i=0; i<sizeof tags; ++i)
        assert(tags[i] == (i>=3 && i<3+WIDTH ? 64 : before[i]));
    unsigned extent = 0;
    for (struct entry *e=history; e<memory_history_top; ++e) {
        assert(e->addr == tags+3+extent);
        assert(e->size && e->size<=8 && extent+e->size<=WIDTH);
        assert(!memcmp(&e->data, before+3+extent, e->size));
        extent += e->size;
    }
    assert(extent == WIDTH);
    while (memory_history_top != history) {
        struct entry *e = --memory_history_top;
        memcpy(e->addr, &e->data, e->size);
    }
    assert(!memcmp(tags, before, sizeof tags));
    return 0;
}
'''.replace('WIDTH', str(width)))

    def test_faulting_tag_store_keeps_a_replayable_history_prefix(self):
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            with self.subTest(arch=arch.name):
                replay = self._pass(arch)
                replay._reset()
                address = replay._load('i64', replay._build_gep('i64', 'scratchpad', 0,
                                                           ptr_type=replay.SCRATCHPAD_ARR_TYPE))
                replay._store_shadow_mem_tags('64', address, 0, 16)
                self._execute(arch, replay, r'''
#include <assert.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
struct entry history[64], *memory_history_top = history;
extern uint64_t scratchpad[];
unsigned char dift_reg_queued_tags[48] __attribute__((aligned(16)));
unsigned char dift_reg_queue_pending[8];
extern void func(void);
static sigjmp_buf fault;
static void handler(int sig) { (void)sig; siglongjmp(fault, 1); }
int main(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *map = mmap(0, 2*page, PROT_READ|PROT_WRITE,
                             MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(map != MAP_FAILED);
    struct sigaction action = { .sa_handler = handler };
    sigemptyset(&action.sa_mask);
    assert(!sigaction(SIGSEGV, &action, 0));
    for (int readable=0; readable<2; ++readable) {
        assert(!mprotect(map+page, page, PROT_READ|PROT_WRITE));
        memset(map, 17, 2*page);
        assert(!mprotect(map+page, page, readable ? PROT_READ : PROT_NONE));
        memory_history_top = history;
        scratchpad[0] = (uintptr_t)(map+page-8);
        if (!sigsetjmp(fault, 1)) { func(); assert(0 && "expected real memory fault"); }
        /* The successful first word is always logged; a store fault also
           publishes the second word, but a failed read does not. */
        assert(memory_history_top-history == 1+readable);
        assert(!mprotect(map+page, page, PROT_READ|PROT_WRITE));
        for (struct entry *e=history; e<memory_history_top; ++e) {
            assert(e->addr == map+page-8+8*(e-history) && e->size == 8);
            assert(e->data == UINT64_C(0x1111111111111111));
        }
        while (memory_history_top != history) {
            struct entry *e = --memory_history_top;
            memcpy(e->addr, &e->data, e->size);
        }
        for (size_t i=0; i<2*page; ++i) assert(map[i] == 17);
    }
    return munmap(map, 2*page) != 0;
}
''')

    def test_queued_update_stays_inside_false_load_condition(self):
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            with self.subTest(arch=arch.name):
                replay = self._pass(arch)
                replay._reset()
                condition = replay._load('i64', replay._build_gep('i64', 'scratchpad', 0,
                                                               ptr_type=replay.SCRATCHPAD_ARR_TYPE))
                empty = replay._icmp('eq', 'i64', condition, 0)
                replay._br_cond(empty, '%done', '%load')
                replay._label('load')
                replay._store('i8', 17, replay._build_gep('i8', 'dift_reg_tags', 0,
                                                       ptr_type=replay.DIFT_REG_TAGS_TYPE))
                replay._after_instruction_effects(object())
                replay._br('%done')
                replay._label('done')
                self._execute(arch, replay, r'''
#include <assert.h>
#include <stdint.h>
extern unsigned char dift_reg_tags[48];
extern uint64_t scratchpad[];
unsigned char dift_reg_queued_tags[48] __attribute__((aligned(16)));
unsigned char dift_reg_queue_pending[8];
void *memory_history_top;
extern void func(void);
int main(void) {
    dift_reg_tags[0] = 128;
    dift_reg_queued_tags[0] = 32;
    dift_reg_queue_pending[0] = 1;
    scratchpad[0] = 0;
    func();
    assert(dift_reg_tags[0] == 128 && dift_reg_queued_tags[0] == 32);
    assert(dift_reg_queue_pending[0] == 1);
    scratchpad[0] = 1;
    func();
    assert(dift_reg_tags[0] == 49 && !dift_reg_queued_tags[0]);
    assert(!dift_reg_queue_pending[0]);
    return 0;
}
''')
