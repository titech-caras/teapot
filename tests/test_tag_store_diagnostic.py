"""Bounded native/QEMU counting fixture; this is not a speed measurement."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from tag_store_diagnostic import COUNTERS, FIELDS, WIDTHS, counting_replay


class TagStoreDiagnosticTests(unittest.TestCase):
    def test_bounded_actual_store_counts(self):
        temporary = tempfile.TemporaryDirectory(prefix='tag-counting-')
        self.addCleanup(temporary.cleanup)
        evidence = Path(os.environ.get('TAG_ELISION_EVIDENCE', temporary.name))
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            with self.subTest(arch=arch.name):
                root = evidence / ('diagnostic-' + arch.name)
                root.mkdir()
                replay = counting_replay(arch, SimpleNamespace(abi=arch.abi),
                                          dift_layout=SimpleNamespace(xor_mask=0))
                replay._reset()
                # Four sites include first-byte-equal but rest-different words,
                # repeated no-ops, equal-after-change, and disjoint widths.
                for site, width in enumerate(WIDTHS):
                    replay.diagnostic_site = site
                    ptr = replay._load('i64', replay._build_gep('i64', 'scratchpad', site,
                                                              ptr_type=replay.SCRATCHPAD_ARR_TYPE))
                    replay._store_shadow_mem_tags('64', ptr, 0, width)
                raw = replay._format_llvm_ir('\n'.join(replay.llvm_ir), target_triple=replay.target_triple)
                (root/'replay.ll').write_text(raw)
                module = replay._parse_and_optimize_llvm(raw)
                assembly = replay.target_machine.emit_assembly(module)
                replay._extract_function_asm(assembly)
                (root/'replay.s').write_text(assembly)
                (root/'replay.o').write_bytes(replay.target_machine.emit_object(module))
                # This is a structural old-read check, in addition to dynamic
                # counters: exactly one original shadow load per real chunk.
                self.assertEqual(raw.count('load volatile i8,'), 1)
                self.assertEqual(raw.count('load volatile i16,'), 1)
                self.assertEqual(raw.count('load volatile i32,'), 1)
                self.assertEqual(sum('load volatile i64' in line and '!alias.scope !0' in line
                                     for line in raw.splitlines()), 1)
                source = SOURCE.replace('@COUNTERS@', str(COUNTERS))
                (root/'fixture.c').write_text(source)
                cc = 'gcc' if arch.name == 'x64' else arch.name + '-linux-gnu-gcc'
                self.assertIsNotNone(shutil.which(cc), cc)
                flags = ['-march=rv64gc', '-mabi=lp64d', '-Wl,--no-relax'] if arch.name == 'riscv64' else []
                build = subprocess.run([cc, '-O2', '-no-pie', *flags, root/'fixture.c', root/'replay.o',
                                        '-o', root/'fixture'], capture_output=True, text=True)
                (root/'build.stdout').write_text(build.stdout)
                (root/'build.stderr').write_text(build.stderr)
                self.assertEqual(build.returncode, 0, build.stderr)
                launch = [] if arch.name == 'x64' else ['qemu-'+arch.name, '-L', '/usr/'+arch.name+'-linux-gnu']
                run = subprocess.run([*launch, root/'fixture'], capture_output=True, text=True, timeout=30)
                (root/'run.stdout').write_text(run.stdout)
                (root/'run.stderr').write_text(run.stderr)
                (root/'run.exit').write_text(str(run.returncode)+'\n')
                self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
                rows = []
                for line in run.stdout.splitlines():
                    case, site, width, *values = map(int, line.split())
                    row = {'case': case, 'site': site, 'width': width,
                           **dict(zip(FIELDS, values))}
                    row['bytes'] = {name: value*width for name, value in zip(FIELDS, values)}
                    rows.append(row)
                self.assertEqual(len(rows), 12)
                # Cases reset counters and history. 0: initial, repeated,
                # mixed changed, repeat. 1: read-only fault then retry.
                # 2: failed old load then retry. Earlier sites also retry.
                for row in rows:
                    expected = ([4, 4, 2 if row['width'] == 1 else 1,
                                 2 if row['width'] == 1 else 3, 4, 4,
                                 2 if row['width'] == 1 else 3,
                                 2 if row['width'] == 1 else 3]
                                if row['case'] == 0 else
                                [2, 2, 2, 0, 2, 1 if row['site'] == 3 else 2, 0, 0]
                                if row['case'] == 1 else
                                [2, 1 if row['site'] == 3 else 2,
                                 1 if row['site'] == 3 else 2, 0,
                                 1 if row['site'] == 3 else 2,
                                 1 if row['site'] == 3 else 2, 0, 0])
                    self.assertEqual([row[f] for f in FIELDS], expected, row)
                (root/'counts.json').write_text(json.dumps(rows, indent=2)+'\n')


SOURCE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t pad[7]; };
struct entry history[64], *memory_history_top = history;
uint64_t tag_store_diagnostic[@COUNTERS@] __attribute__((aligned(16)));
unsigned char dift_reg_queued_tags[48] __attribute__((aligned(16)));
unsigned char dift_reg_queue_pending[8];
extern uint64_t scratchpad[];
extern void func(void);
static sigjmp_buf fault;
static void handler(int sig) { (void)sig; siglongjmp(fault, 1); }
static void dump(unsigned kind) {
    const unsigned widths[] = {1,2,4,8};
    for (unsigned site=0; site<4; ++site) {
        printf("%u %u %u", kind, site, widths[site]);
        for (unsigned field=0; field<8; ++field)
            printf(" %llu", (unsigned long long)tag_store_diagnostic[(site*4+site)*8+field]);
        puts("");
    }
}
int main(void) {
    unsigned char tags[64];
    memset(tags, 17, sizeof tags);
    for (unsigned site=0; site<4; ++site) scratchpad[site] = (uintptr_t)(tags+site*9+1);
    func(); func();
    for (unsigned site=0; site<4; ++site) {
        unsigned width = 1u << site;
        memset((void *)scratchpad[site], 19, width);
        if (width > 1) *(unsigned char *)scratchpad[site] = 64;
    }
    func();
    for (unsigned site=0; site<4; ++site)
        if (site) ((unsigned char *)scratchpad[site])[(1u << site)-1] = 3;
    func();
    assert(memory_history_top-history == 16); /* diagnostics never elide */
    dump(0);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *map = mmap(0, page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(map != MAP_FAILED);
    struct sigaction sa = {.sa_handler=handler};
    sigemptyset(&sa.sa_mask); assert(!sigaction(SIGSEGV,&sa,0));
    for (unsigned kind=1; kind<=2; ++kind) {
        memset(tag_store_diagnostic,0,sizeof tag_store_diagnostic);
        memory_history_top=history;
        memset(tags,64,sizeof tags); memset(map,64,page);
        scratchpad[3]=(uintptr_t)(map+1);
        assert(!mprotect(map,page,kind == 1 ? PROT_READ : PROT_NONE));
        if (!sigsetjmp(fault,1)) { func(); assert(0 && "fault required"); }
        assert(memory_history_top-history == (kind == 1 ? 4 : 3));
        assert(!mprotect(map,page,PROT_READ|PROT_WRITE));
        func(); /* preserve first attempt counts; retry is not an original pass */
        assert(memory_history_top-history == (kind == 1 ? 8 : 7));
        dump(kind);
    }
    return munmap(map,page) != 0;
}
'''
