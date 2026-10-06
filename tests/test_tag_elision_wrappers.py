"""Execute the real all-live wrappers around the comparison/branch body."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from teapot.configs.slots import AARCH64_SHADOW_STACK_SIZE, RISCV64_ORIGINAL_TP_OFFSET
from teapot.configs.runtime import SCRATCHPAD_SIZE
from tag_elision_support import replay_for, format_ir, build_run
from test_tag_elision import LANES
from test_x64_rep_dift import wrapped_patch, runner_function


class TagElisionWrapperTests(unittest.TestCase):
    def test_actual_branch_preserves_live_machine_state(self):
        temporary=tempfile.TemporaryDirectory(prefix='tag-elision-wrappers-')
        self.addCleanup(temporary.cleanup)
        evidence=Path(os.environ.get('TAG_ELISION_EVIDENCE',temporary.name))
        for kind, mode in LANES:
            with self.subTest(mode=mode):
                arch=kind()
                root=evidence / ('wrappers-'+mode)
                root.mkdir()
                replay=replay_for(arch,proof=True)
                replay.rewriting_ctx=SimpleNamespace(_abi=arch.abi)
                ptr=replay._load('i64','@scratchpad')
                tag=replay._load('i8','@dift_reg_tags')
                replay._store_shadow_mem_tags(tag,ptr,0,15)
                raw=format_ir(replay,'func')
                (root/'body.ll').write_text(raw)
                module=replay._parse_and_optimize_llvm(raw)
                body=replay._extract_function_asm(replay.target_machine.emit_assembly(module))
                live=set(arch.abi.all_registers())
                plan=replay._plan_scratch_registers(2,live)
                body,registers,_=replay._allocate_replay_scratch(body,replay._get_register_usage(body),live)
                patch=replay._build_optimized_dift_values_patch(body,registers,scratch_plan=plan)
                if arch.name=='x64':
                    snippet=wrapped_patch(arch,patch)
                    assembly='.intel_syntax noprefix\n.text\n'+runner_function('probe',b'\x90',snippet,'')
                    checks=X64_CHECKS
                else:
                    snippet=patch(SimpleNamespace(stack_adjustment=0))
                    if arch.name=='aarch64':
                        assembly=f'''
                        .text
                        .global probe
                    probe:
                        mov x9,sp
                        {arch.load_address('x10','test_stack_top')}
                        mov sp,x10
                        mov x14,#0x1234
                        mov x10,#0xa0000000
                        msr nzcv,x10
                        movi v0.16b,#0x55
                        movi v31.16b,#0x77
                        {snippet}
                        mrs x10,nzcv
                        mov w0,#1
                        mov x11,#0xa0000000
                        cmp x10,x11
                        b.ne 1f
                        mov x11,#0x1234
                        cmp x14,x11
                        b.ne 1f
                        umov x10,v0.d[1]
                        {arch.mov_u64('x11',0x5555555555555555)}
                        cmp x10,x11
                        b.ne 1f
                        umov x10,v31.d[1]
                        {arch.mov_u64('x11',0x7777777777777777)}
                        cmp x10,x11
                        b.ne 1f
                        mov w0,#0
                    1:
                        mov sp,x9
                        ret
                        .bss
                        .balign 16
                        .skip {AARCH64_SHADOW_STACK_SIZE+4096}
                    test_stack_top:
                        .skip 4096
                        '''
                    else:
                        snippet=snippet.replace('.attribute arch, "rv64imafd"\n','')
                        assembly=f'''
                        .attribute arch,"rv64imafd"
                        .text
                        .global probe
                    probe:
                        {arch.load_address('t2',f'scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}')}
                        sd tp,0(t2)
                        {arch.load_address('t2','saved_special')}
                        sd sp,0(t2)
                        sd gp,8(t2)
                        sd tp,16(t2)
                        li t3,0x1234
                        li t0,0x65
                        fscsr t0
                        li t0,0x55
                        fmv.d.x ft0,t0
                        {snippet}
                        li a0,1
                        li t4,0x1234
                        bne t3,t4,1f
                        frcsr t0
                        li t4,0x65
                        bne t0,t4,1f
                        fmv.x.d t0,ft0
                        li t4,0x55
                        bne t0,t4,1f
                        {arch.load_address('t2','saved_special')}
                        ld t0,0(t2)
                        bne sp,t0,1f
                        ld t0,8(t2)
                        bne gp,t0,1f
                        ld t0,16(t2)
                        bne tp,t0,1f
                        li a0,0
                    1:
                        ret
                        '''
                    checks='assert(probe() == 0);'
                assembly+='\n.section .note.GNU-stack,"",%progbits\n'
                path=root/'probe.S'
                path.write_text(assembly)
                source=SOURCE.replace('@CHECKS@',checks).replace('@SCRATCHPAD_WORDS@',str(SCRATCHPAD_SIZE//8))
                result=build_run(arch,mode,root,source,[path])
                self.assertIn('wrapper PASS',result)


X64_CHECKS=r'''
    uint64_t state[40]={0};
    state[0]=0x1111; state[1]=0x2222; state[2]=0x3333; state[3]=0x4444;
    state[4]=initial == 64 ? 0x647 : 0x202;
    probe(state);
    assert(state[0]==0x1111 && state[1]==0x2222 && state[2]==0x3333 && state[3]==0x4444);
    assert((state[4]&0xcd5)==((initial == 64 ? 0x647 : 0x202)&0xcd5));
    for(unsigned i=0;i<10;++i) assert(state[5+i]==0x123400+i);
    for(unsigned i=16;i<32;++i) assert(state[i]==0x12345678);
'''

SOURCE=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t pad[7]; };
struct entry history[64], *memory_history_top=history;
unsigned char dift_reg_tags[48] __attribute__((aligned(16)));
unsigned char dift_reg_queued_tags[48] __attribute__((aligned(16)));
unsigned char dift_reg_queue_pending[8];
uint64_t scratchpad[@SCRATCHPAD_WORDS@] __attribute__((aligned(64)));
uint64_t old_rsp,tag_elision_bounds[2],saved_special[3];
extern int probe();
int main(void) {
    unsigned char tags[32];
    for(unsigned initial=17;initial<=64;initial+=47) {
        memset(tags,initial,sizeof tags); memory_history_top=history;
        tag_elision_bounds[0]=(uintptr_t)tags; tag_elision_bounds[1]=(uintptr_t)(tags+sizeof tags);
        scratchpad[0]=(uintptr_t)(tags+1); dift_reg_tags[0]=64;
        @CHECKS@
        assert(memory_history_top-history==(initial==64?0:4));
        for(unsigned i=1;i<16;++i) assert(tags[i]==64);
    }
    puts("wrapper PASS changed/equal; live GPRs, flags/control, SIMD/FP, special state");
    return 0;
}
'''
