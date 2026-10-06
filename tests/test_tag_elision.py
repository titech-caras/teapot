"""Exact full-width no-op primitive differential gates, with explicit proof."""
import os
from pathlib import Path
import tempfile
import unittest

from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.passes.transient.lazy_dift import ReplayEffect
from tag_elision_support import replay_for, emit_object, build_run, install_fault_boundaries

WIDTHS = (1,2,3,4,7,8,10,15,16,24,32,64)
LANES = ((X64Architecture, 'x64'), (AArch64Architecture, 'aarch64-shadow'),
         (AArch64Architecture, 'aarch64-mte'), (RISCV64Architecture, 'riscv64'))


class TagElisionTests(unittest.TestCase):
    def test_exact_width_overlap_nesting_queue_and_fault_differentials(self):
        temporary=tempfile.TemporaryDirectory(prefix='tag-elision-')
        self.addCleanup(temporary.cleanup)
        evidence=Path(os.environ.get('TAG_ELISION_EVIDENCE',temporary.name))
        for kind, mode in LANES:
            with self.subTest(mode=mode):
                arch = kind()
                root = evidence / mode
                root.mkdir()
                objects = []
                declarations = []
                tables = []
                for proof in (False, True):
                    names = []
                    for width in WIDTHS:
                        name = f'{"candidate" if proof else "baseline"}_{width}'
                        replay = replay_for(arch, proof=proof)
                        ptr = replay._load('i64', replay._build_gep('i64','scratchpad',0,
                                                                  ptr_type=replay.SCRATCHPAD_ARR_TYPE))
                        tag = replay._load('i8', '@dift_reg_tags')
                        replay._store_shadow_mem_tags(tag,ptr,0,width)
                        replay._store('i8', 17, '@dift_reg_tags')
                        replay._after_instruction_effects(object())
                        objects.append(emit_object(replay,name,root))
                        declarations.append(f'extern void {name}(void);')
                        names.append(name)
                    tables.append('{'+','.join(names)+'}')
                for proof in (False, True):
                    for width in (1,2,4,8):
                        name = f'fault_{int(proof)}_{width}'
                        replay = replay_for(arch, proof=proof)
                        ptr = replay._load('i64', replay._build_gep('i64','scratchpad',0,
                                                                  ptr_type=replay.SCRATCHPAD_ARR_TYPE))
                        install_fault_boundaries(replay)
                        replay._store_shadow_mem_tags('64',ptr,0,width)
                        objects.append(emit_object(replay,name,root))
                        declarations.append(f'extern void {name}(void);')
                for proof in (False, True):
                    replay=replay_for(arch,proof=proof)
                    ptr=replay._load('i64','@scratchpad')
                    replay._store_shadow_mem_tags('64',ptr,0,15)
                    replay._store('i8',17,'@dift_reg_tags')
                    prefix=tuple(replay.llvm_ir)
                    replay.llvm_ir=[]
                    replay._after_instruction_effects(object())
                    suffix=tuple(replay.llvm_ir)
                    replay.effects=[ReplayEffect(0,prefix,frozenset({'reader'}),True,False),
                                    ReplayEffect(1,suffix,frozenset(),False,True)]
                    self.assertEqual(replay._required_prefix({'reader'}),1)
                    self.assertEqual(replay._required_prefix(set(),memory=True),1)
                    self.assertEqual(replay._required_prefix(set(),queue=True),2)
                    for name,body in ((f'prefix_{int(proof)}',prefix),(f'suffix_{int(proof)}',suffix)):
                        replay.llvm_ir=list(body)
                        objects.append(emit_object(replay,name,root))
                        declarations.append(f'extern void {name}(void);')
                source = SOURCE.replace('@DECLARATIONS@','\n'.join(declarations))
                source = source.replace('@TABLES@', ','.join(tables))
                source = source.replace('@WIDTHS@', ','.join(map(str,WIDTHS)))
                output = build_run(arch,mode,root,source,objects)
                self.assertIn('differentials PASS', output)


SOURCE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
struct entry { unsigned char *addr; uint64_t data; uint8_t size; uint8_t pad[7]; };
struct entry history[256], *memory_history_top=history;
unsigned char dift_reg_tags[48] __attribute__((aligned(16)));
unsigned char dift_reg_queued_tags[48] __attribute__((aligned(16)));
unsigned char dift_reg_queue_pending[8];
uint64_t scratchpad[32768] __attribute__((aligned(64)));
uint64_t tag_elision_bounds[2], tag_elision_fault_stage;
void *tag_elision_fault_address;
@DECLARATIONS@
typedef void (*replay_fn)(void);
static replay_fn functions[2][12]={@TABLES@};
static replay_fn faults[2][4]={{fault_0_1,fault_0_2,fault_0_4,fault_0_8},
                              {fault_1_1,fault_1_2,fault_1_4,fault_1_8}};
static unsigned widths[12]={@WIDTHS@};
static sigjmp_buf fault;
static volatile unsigned signals;
static void handler(int sig) { (void)sig; ++signals; siglongjmp(fault,1); }
static unsigned chunks(unsigned width) {
    unsigned count=0;
    while (width) { unsigned chunk=8; while(chunk>width) chunk/=2; width-=chunk; ++count; }
    return count;
}
static unsigned expected(unsigned char *p,unsigned width,unsigned tag,unsigned proof) {
    unsigned count=0;
    while(width) {
        unsigned chunk=8; while(chunk>width) chunk/=2;
        unsigned equal=1; for(unsigned i=0;i<chunk;++i) equal &= p[i]==tag;
        uintptr_t first=(uintptr_t)p,last=first+chunk-1;
        unsigned safe=first>=tag_elision_bounds[0] && last<tag_elision_bounds[1] && last>=first;
        count += !(proof && safe && equal);
        width-=chunk; p+=chunk;
    }
    return count;
}
static void undo(struct entry *bound) {
    while(memory_history_top!=bound) {
        struct entry *e=--memory_history_top;
        assert(e->size==1 || e->size==2 || e->size==4 || e->size==8);
        memcpy(e->addr,&e->data,e->size);
    }
}
static void invoke(unsigned variant,unsigned index,unsigned char *p,unsigned tag) {
    unsigned want=expected(p,widths[index],tag,variant);
    struct entry *before=memory_history_top;
    scratchpad[0]=(uintptr_t)p;
    dift_reg_tags[0]=tag; dift_reg_queued_tags[0]=32; dift_reg_queued_tags[47]=2;
    dift_reg_queue_pending[0]=1;
    functions[variant][index]();
    assert(memory_history_top-before==want);
    for(unsigned i=0;i<widths[index];++i) assert(p[i]==tag);
    assert(dift_reg_tags[0]==49 && dift_reg_tags[47]==2 && !dift_reg_queue_pending[0]);
    for(unsigned i=0;i<48;++i) assert(!dift_reg_queued_tags[i]);
}
int main(void) {
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    unsigned char *map=mmap(0,3*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    unsigned char *bad=mmap(0,page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(map!=MAP_FAILED && bad!=MAP_FAILED);
    tag_elision_fault_address=bad;
    struct sigaction sa={.sa_handler=handler}; sigemptyset(&sa.sa_mask);
    assert(!sigaction(SIGSEGV,&sa,0));
    unsigned scenarios=0, injected=0, protection=0;
    unsigned char before[80],outer[80],snapshot[80];
    for(unsigned index=0;index<12;++index) for(unsigned initial=0;initial<3;++initial)
    for(unsigned alignment=0;alignment<3;++alignment) {
        for(unsigned variant=0;variant<2;++variant) {
            unsigned char *p=map+page-9+alignment;
            tag_elision_bounds[0]=(uintptr_t)map; tag_elision_bounds[1]=(uintptr_t)(map+3*page);
            memset(p,initial==0?64:17,80);
            if(initial==2) { memset(p,64,80); p[widths[index]-1]=3; }
            memcpy(before,p,80); memory_history_top=history;
            invoke(variant,index,p,64); memcpy(outer,p,80);
            struct entry *inner=memory_history_top;
            invoke(variant,index,p,64); /* changed earlier, equal now */
            invoke(variant,index,p+1,128); /* overlapping multi-byte write */
            invoke(variant,index,p+1,128); /* repeat after prior change */
            undo(inner); assert(!memcmp(p,outer,80));
            undo(history); assert(!memcmp(p,before,80));
            if(!variant) memcpy(snapshot,p,80); else assert(!memcmp(p,snapshot,80));
        }
        ++scenarios;
    }
    /* Faults before/after old load, partial log fields, complete top
       publication, and the actual changed store, for every real width. */
    for(unsigned wi=0;wi<4;++wi) for(unsigned stage=1;stage<=7;++stage) {
        for(unsigned variant=0;variant<2;++variant) {
            unsigned width=1u<<wi;
            memset(map,17,32); memory_history_top=history;
            tag_elision_bounds[0]=(uintptr_t)map; tag_elision_bounds[1]=(uintptr_t)(map+page);
            scratchpad[0]=(uintptr_t)(map+1); tag_elision_fault_stage=stage;
            unsigned oldsignals=signals;
            if(!sigsetjmp(fault,1)) { faults[variant][wi](); assert(0 && "injected fault required"); }
            assert(signals==oldsignals+1);
            assert(memory_history_top-history==(stage>=6));
            for(unsigned i=0;i<width;++i) assert(map[1+i]==(stage==7?64:17));
            if(stage>=6) { assert(history[0].addr==map+1 && history[0].size==width); }
            undo(history); for(unsigned i=0;i<32;++i) assert(map[i]==17);
            tag_elision_fault_stage=0;
            faults[variant][wi](); /* retry after rollback */
            assert(memory_history_top==history+1);
            undo(history); for(unsigned i=0;i<32;++i) assert(map[i]==17);
        }
        ++injected;
    }
    /* Equal read-only stores must still fault: deny the proof for the whole
       chunk, including an unaligned chunk that crosses into another page. */
    for(unsigned wi=0;wi<4;++wi) for(unsigned readable=0;readable<2;++readable)
    for(unsigned cross=0;cross<2;++cross) for(unsigned initial=17;initial<=64;initial+=47)
    for(unsigned low=0;low<2;++low) for(unsigned variant=0;variant<2;++variant) {
        unsigned width=1u<<wi;
        assert(!mprotect(map,3*page,PROT_READ|PROT_WRITE)); memset(map,initial,3*page);
        unsigned char *bad_page=map+(low?0:page);
        unsigned char *p=cross && width>1 ? map+page-width/2 : bad_page+1;
        tag_elision_bounds[0]=(uintptr_t)(low?map+page:map);
        tag_elision_bounds[1]=(uintptr_t)(low?map+3*page:map+page);
        memory_history_top=history; scratchpad[0]=(uintptr_t)p;
        assert(!mprotect(bad_page,page,readable?PROT_READ:PROT_NONE));
        unsigned oldsignals=signals;
        if(!sigsetjmp(fault,1)) { faults[variant][wi](); assert(0 && "equal store must fault"); }
        assert(signals==oldsignals+1);
        assert(memory_history_top-history==readable);
        assert(!mprotect(bad_page,page,PROT_READ|PROT_WRITE));
        /* RV64 may lower an unaligned i64 volatile store to byte stores.
           Compare its partial-write observation too, then restore all bytes. */
        if(!variant) memcpy(snapshot,p,width); else assert(!memcmp(snapshot,p,width));
        undo(history); for(unsigned i=0;i<width;++i) assert(p[i]==initial);
        ++protection;
    }
    /* Memlog restart: an ordinary LIFO entry's destination becomes read-only
       only after the proof-bound window ended. The failed pop is retained for
       retry just as the runtime's separate replay-restart tests require. */
    for(unsigned variant=0;variant<2;++variant) {
        memset(map,17,page); memory_history_top=history;
        tag_elision_bounds[0]=(uintptr_t)map; tag_elision_bounds[1]=(uintptr_t)(map+page);
        scratchpad[0]=(uintptr_t)(map+1); faults[variant][3]();
        tag_elision_bounds[0]=tag_elision_bounds[1]=0;
        assert(!mprotect(map,page,PROT_READ));
        struct entry *entry=memory_history_top-1;
        if(!sigsetjmp(fault,1)) { *(volatile uint64_t *)entry->addr=entry->data; assert(0); }
        assert(memory_history_top==history+1);
        assert(!mprotect(map,page,PROT_READ|PROT_WRITE)); undo(history);
        for(unsigned i=0;i<page;++i) assert(map[i]==17);
    }
    /* Prefix materialization must neither drop the pending suffix nor
       apply/clear its attacker queue early, even when every chunk is equal. */
    replay_fn prefixes[]={prefix_0,prefix_1},suffixes[]={suffix_0,suffix_1};
    for(unsigned variant=0;variant<2;++variant) {
        memset(map,64,page); memory_history_top=history;
        tag_elision_bounds[0]=(uintptr_t)map; tag_elision_bounds[1]=(uintptr_t)(map+page);
        scratchpad[0]=(uintptr_t)(map+1);
        dift_reg_tags[0]=128; dift_reg_queued_tags[0]=32; dift_reg_queue_pending[0]=1;
        prefixes[variant]();
        assert(dift_reg_tags[0]==17 && dift_reg_queued_tags[0]==32 && dift_reg_queue_pending[0]==1);
        assert(memory_history_top-history==(variant?0:4));
        suffixes[variant]();
        assert(dift_reg_tags[0]==49 && !dift_reg_queued_tags[0] && !dift_reg_queue_pending[0]);
        undo(history);
    }
    printf("differentials PASS scenarios=%u injected=%u protection=%u restart=2 prefixes=2\n",scenarios,injected,protection);
    assert(!munmap(map,3*page) && !munmap(bad,page)); return 0;
}
'''
