"""LOOP's outcome probe must undo exactly its ECX/RCX decrement, flags intact."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from uuid import uuid4

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import gtirb
from teapot.arch import X64Architecture
from teapot.utils.misc import generate_distinct_label_name
from teapot.utils.nested_policy import checkpoint_branch
from test_start_symbols import module_with_interval


class HashedLoopTests(unittest.TestCase):
    def test_llvm_relaxation_preserves_ecx_width(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        for opcode in (0xe0, 0xe1, 0xe2, 0xe3):
            with self.subTest(opcode=opcode):
                ir, module, interval = module_with_interval(bytes([0x67, opcode, 0, 0xc3, 0xc3]))
                branch = gtirb.CodeBlock(size=3, byte_interval=interval)
                fall = gtirb.CodeBlock(size=1, offset=3, byte_interval=interval)
                target = gtirb.CodeBlock(size=1, offset=4, byte_interval=interval)
                for name, schema in (("functionEntries", "mapping<UUID,set<UUID>>"),
                                     ("functionBlocks", "mapping<UUID,set<UUID>>"),
                                     ("functionNames", "mapping<UUID,UUID>"),
                                     ("elfSymbolInfo", "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")):
                    module.aux_data[name] = gtirb.AuxData({}, schema)
                module.aux_data["sectionProperties"] = gtirb.AuxData(
                    {interval.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
                ir.cfg.update({gtirb.Edge(branch, target, gtirb.Edge.Label(
                    type=gtirb.Edge.Type.Branch, conditional=True, direct=True)),
                    gtirb.Edge(branch, fall, gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough))})
                arch = X64Architecture()
                object.__setattr__(arch, "hashed_nested", True)
                arch.relax_conditional_branches(module, direct_pads={})
                count_branches = [instruction for block in module.code_blocks
                                  for instruction in decoder.disasm(block.contents, block.address)
                                  if instruction.mnemonic in ("loop", "loope", "loopne", "jecxz", "jrcxz")]
                self.assertEqual(len(count_branches), 1)
                self.assertEqual(count_branches[0].addr_size, 4)

    def test_real_entries_match_model_and_original_count(self):
        if not shutil.which("gcc") or not shutil.which("cmake"):
            self.skipTest("requires gcc and cmake")
        runtime = Path(__file__).resolve().parents[1] / "libcheckpoint"
        arch = X64Architecture()
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        cases = []
        assembly = ['.intel_syntax noprefix']
        for opcode, mnemonic in ((0xe2, "loop"), (0xe1, "loope"), (0xe0, "loopne"), (0xe3, "jrcxz")):
            for width in (64, 32):
                instruction = next(decoder.disasm(bytes(([0x67] if width == 32 else []) + [opcode, 0]), 0))
                branch = checkpoint_branch(arch, instruction)
                self.assertEqual(instruction.addr_size, width // 8)
                for count in (1, 0):
                    index = len(cases)
                    is_loop = mnemonic.startswith("loop")
                    after = (count - 1) & ((1 << width) - 1) if is_loop else count
                    taken = int(after != 0) if is_loop else int(count == 0)
                    flags = 0x95 if mnemonic == "loopne" else 0x44
                    cases.append((after, taken, flags))
                    block, transient = uuid4(), uuid4()
                    patch = arch.checkpoint_patch(block, use_scratch_registers=False, vector_case=0,
                        site_index=index, branch=branch)(SimpleNamespace())
                    patch = patch.replace('.L__after_checkpoint__teapot__', f'.Lafter_{index}').replace(
                        '.L__checkpoint_taken__teapot__', f'.Ltaken_{index}')
                    trampoline = arch.trampoline_patch(block, transient, *branch,
                        f'.Lselected_{index}', f'.Lselected_{index}')(SimpleNamespace())
                    counter = generate_distinct_label_name('.__branch_counter_', block)
                    assembly.append(f'''
.text
.globl loop_probe_{index}
loop_probe_{index}:
    push rbx
    mov rcx, {count}
    mov eax, 0
    cmp eax, {1 if mnemonic == 'loopne' else 0}
    {patch}
    {branch[0]} .Lnormal_{index}
.Lnormal_{index}:
    mov rdi, rcx
    pushfq
    pop rsi
    mov edx, 0
    call loop_observe
    pop rbx
    ret
{trampoline}
.Lselected_{index}:
    mov rdi, rcx
    pushfq
    pop rsi
    mov edx, 1
    call loop_observe
    jmp restore_checkpoint_ROB_LEN
.set {counter}, loop_sites+{12 * index}
''')
        assembly.append('.section .note.GNU-stack,"",@progbits')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def run(args):
                result = subprocess.run(list(map(str, args)), cwd=root, text=True, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, f"{args}\n{result.stdout}\n{result.stderr}")
                return result
            run(['cmake', '-S', runtime, '-B', root / 'runtime', '-DBUILD_TESTING=OFF',
                 '-DTEAPOT_BUILD_NESTED_RUNTIME=ON', '-DTEAPOT_ENABLE_DIFT_RUNTIME=OFF'])
            run(['cmake', '--build', root / 'runtime', '--target', 'checkpoint_nested_hashed', '-j1'])
            (root / 'probe.S').write_text('\n'.join(assembly))
            (root / 'cases.h').write_text('\n'.join(f'extern void loop_probe_{i}(void);' for i in range(len(cases))) +
                '\nstatic void (*probes[])(void) = {' + ','.join(f'loop_probe_{i}' for i in range(len(cases))) + '};\n' +
                'static const uint64_t expected[][3] = {' + ','.join(
                    '{' + f'UINT64_C({count}),{taken},{flags}' + '}' for count, taken, flags in cases) + '};\n')
            (root / 'driver.c').write_text(DRIVER)
            flags = ['-O2', '-fno-pie', '-no-pie', '-DDIFT_XOR_MASK=0', '-DENABLE_NESTED_SPECULATION',
                     '-DENABLE_HASHED_NESTED', '-DTEST_CONTRACT_REQUIRED=LIBCHECKPOINT_CAPABILITY_HASHED_NESTED',
                     '-I', runtime / 'include', '-I', runtime / 'tests', '-I', root / 'runtime/include', '-I', root]
            run(['gcc', *flags, 'driver.c', 'probe.S', runtime / 'tests/contract_module_record.c',
                 root / 'runtime/libcheckpoint_nested_hashed.a', '-lm', '-o', 'probe'])
            result = run([root / 'probe'])
            self.assertIn('32 LOOP/count-zero cases passed', result.stdout)


DRIVER = r'''
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "checkpoint.h"
#include "nested_policy.h"
#include "nested_model.h"
#include "cases.h"
struct teapot_nested_site loop_sites[sizeof(probes)/sizeof(*probes)];
uint32_t __guard_start__teapot__[1], __guard_end__teapot__[1];
extern uintptr_t checkpoint_target_metadata[];
static unsigned current, selected, seen;
void __asan_init(void) {}
void __asan_poison_memory_region(void const volatile *p,size_t n) {(void)p;(void)n;}
void __asan_unpoison_memory_region(void const volatile *p,size_t n) {(void)p;(void)n;}
void loop_observe(uint64_t count, uint64_t flags, int transient) {
    assert(count == expected[current][0]);
    assert((flags & 0x8d5) == expected[current][2]);
    assert(checkpoint_target_metadata[CHECKPOINT_TARGET_OUTCOME/8] == expected[current][1]);
    assert(checkpoint_cnt == (unsigned)transient);
    if (transient) { assert(selected); ++seen; }
}
int main(int argc,char **argv) {
    libcheckpoint_enable(argc,argv);
    uint32_t generation=0;
    for(current=0;current<sizeof(probes)/sizeof(*probes);++current) {
        for(selected=0;selected<2;++selected) {
            struct teapot_nested_site model={0};
            model.arch[expected[current][1]]=selected ? 0:2;
            loop_sites[current]=model;
            seen=0;
            assert(model_decision(&model,current,expected[current][1],0,&generation,teapot_nested_seed_word)==selected);
            probes[current]();
            assert(seen==selected && generation==teapot_nested_root_gen);
            assert(memcmp(&model,&loop_sites[current],sizeof(model))==0);
        }
    }
    puts("32 LOOP/count-zero cases passed (selected and skipped, RCX/ECX, original flags)");
}
'''
