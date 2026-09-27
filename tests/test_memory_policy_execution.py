"""Memory checks follow accesses, not whether their result has a tracked tag."""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import gtirb
from gtirb_rewriting import Assembler

from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.arch.decoders import x64_decoder, aarch64_decoder, riscv64_decoder
from teapot.configs.runtime import SCRATCHPAD_SIZE
from teapot.configs.tags import TAG_ATTACKER, TAG_ATTACKER_INDIRECT, TAG_SECRET, TAG_SECRET_INDIRECT
from test_live_register_preservation import make_module


class MemoryPolicyExecutionTests(unittest.TestCase):
    def test_risc_fp_and_simd_loads_get_checks_without_destination_taint(self):
        for arch, isa, decoder, encoded, scratch in (
                (AArch64Architecture(), gtirb.Module.ISA.ARM64, aarch64_decoder(),
                 '000040fd', ('x9','x10','x11','x12','x13')),
                (AArch64Architecture(), gtirb.Module.ISA.ARM64, aarch64_decoder(),
                 '0000c03d', ('x9','x10','x11','x12','x13')),
                (RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported, riscv64_decoder(),
                 '07b50500', ('t0','t1','t2','t3','t4'))):
            with self.subTest(arch=arch.name, bytes=encoded):
                data = bytes.fromhex(encoded)
                _, module, block, _, _ = make_module(arch, isa, data)
                inst, = decoder.disasm(data, block.address)
                policy = arch.create_transient_mem_operand_policy_pass(
                    SimpleNamespace(abi=arch.abi), None, None,
                    dift_layout=SimpleNamespace(asan_shadow_offset=0), enable_asan_check=True)
                info = policy._build_policy_patch(inst, 0, 0, block)
                self.assertIsNotNone(info)
                asm = info.patch(SimpleNamespace(stack_adjustment=0,
                    scratch_registers=tuple(arch.abi.get_register(n) for n in scratch)))
                self.assertIn('KASPER_CACHE', asm)
                self.assertIn('KASPER_MDS', asm)
                self.assertNotIn('dift_reg_queued_tags', asm)
                if arch.name == 'riscv64':
                    self.assertIn('frcsr', asm)
                    self.assertIn('fsd f31,', asm)
                    self.assertIn('fld f31,', asm)
                assembler = Assembler(module, allow_undef_symbols=True)
                assembler.assemble(asm)
                emitted = assembler.finalize().text_section.data
                self.assertTrue(emitted)
                self.assertEqual(sum(i.size for i in decoder.disasm(emitted, 0)), len(emitted))

    @unittest.skipUnless(platform.machine() == 'x86_64' and shutil.which('gcc'), 'requires native x64 compiler')
    def test_false_cmov_still_checks_memory_but_does_not_queue_tags(self):
        arch = X64Architecture()
        inst, = x64_decoder().disasm(bytes.fromhex('480f4407'), 0)  # cmove rax,[rdi]
        policy = arch.create_transient_mem_operand_policy_pass(
            SimpleNamespace(abi=arch.abi), None, None,
            dift_layout=SimpleNamespace(asan_shadow_offset=0), enable_asan_check=True)
        # Keep the real address/tag/range-check code; stub only the reporter's
        # external runtime call so the emitted patch can execute in isolation.
        with mock.patch.object(type(arch), 'report_gadget_snippet',
                side_effect=lambda kind, **kwargs: f'inc qword ptr {kind}'):
            patch = policy._build_patch(inst, '[rdi]', 8, conditional='e',
                mem_operand=arch.memory_operand(inst), write_reg=arch.abi.get_register('rax'))
            asm = patch(SimpleNamespace(scratch_registers=tuple(arch.abi.get_register(n)
                for n in ('r8', 'r9', 'r10', 'rcx', 'rdx'))))
        source = f'''
            #include <assert.h>
            #include <stdint.h>
            #include <string.h>
            unsigned char scratchpad[{SCRATCHPAD_SIZE}], dift_reg_tags[48], dift_reg_queued_tags[48];
            unsigned char dift_reg_queue_pending[8];
            uint64_t KASPER_CACHE, KASPER_MDS;
            extern void check(uintptr_t, int);
            int main(void) {{
                unsigned char shadow[8] __attribute__((aligned(8)));
                const unsigned tags[] = {{{TAG_SECRET}, {TAG_ATTACKER_INDIRECT}, {TAG_ATTACKER}, 0}};
                const unsigned queued[] = {{0, {TAG_SECRET_INDIRECT}, {TAG_SECRET}, {TAG_ATTACKER_INDIRECT}}};
                for (int condition=0; condition<2; ++condition) for (unsigned i=0; i<4; ++i) {{
                    memset(dift_reg_tags, 0, sizeof dift_reg_tags);
                    memset(dift_reg_queued_tags, 0, sizeof dift_reg_queued_tags);
                    dift_reg_queue_pending[0] = 0;
                    memset(shadow, i<2 ? 0 : 255, sizeof shadow);
                    KASPER_CACHE=KASPER_MDS=0;
                    dift_reg_tags[5]=tags[i];
                    check((uintptr_t)shadow << 3, condition);
                    assert(KASPER_CACHE == (i==0));
                    assert(KASPER_MDS == (i==1 || i==2));
                    assert(dift_reg_queued_tags[0] == (condition ? queued[i] : 0));
                    assert(dift_reg_queue_pending[0] == (condition && queued[i] ? 1 : 0));
                }}
            }}
        '''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'check.c').write_text(source)
            (root/'check.S').write_text('.intel_syntax noprefix\n.text\n.globl check\ncheck:\ncmp esi,1\n'
                                      + asm + '\nret\n.section .note.GNU-stack,"",@progbits\n')
            build = subprocess.run(['gcc','-O2','-no-pie',str(root/'check.c'),str(root/'check.S'),
                                    '-o',str(root/'check')], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(root/'check')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
