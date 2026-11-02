"""Execute the new predicates with the ISA's real address and tag emitters."""
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb
from gtirb_rewriting import Assembler
from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.passes.transient.gadget_policy.store import TransientStorePolicyPass
from teapot.passes.transient.indirect_branch_check_pass import TransientIndirectTargetPolicyPass
from test_live_register_preservation import make_module
from runtime_contract_support import fixture_layout


CASES = (
    (X64Architecture, gtirb.Module.ISA.X64, 'gcc', (), '.intel_syntax noprefix\n',
     'mov byte ptr [rdi+rsi], 7', 'call rdi', 'jmp rdi', 'ret', ('r8', 'r9', 'r10'), 'rdi'),
    (AArch64Architecture, gtirb.Module.ISA.ARM64, 'aarch64-linux-gnu-gcc', ('qemu-aarch64',), '',
     'strb w2,[x0,x1]', 'blr x0', 'br x0', 'ret', ('x9', 'x10', 'x11', 'x12'), 'x0'),
    (RISCV64Architecture, gtirb.Module.ISA.ValidButUnsupported, 'riscv64-linux-gnu-gcc', ('qemu-riscv64',),
     '.option norvc\n', 'sb a1,0(a0)', 'jalr ra,0(a0)', 'jalr zero,0(a0)', 'ret',
     ('t0', 't1', 't2'), 'a0'),
)


def build_info(case, assembly, target=False, direct=False):
    kind, isa, _, _, prefix, *rest = case
    arch = kind()
    ir, module, block, abi, _ = make_module(arch, isa, b'')
    if isinstance(assembly, bytes):
        code = assembly
    else:
        assembler = Assembler(module)
        assembler.assemble(prefix + assembly)
        code = assembler.finalize().text_section.data
    block.byte_interval.contents = code
    block.byte_interval.size = block.size = len(code)
    from teapot.liveness import LiveRegisterManager
    manager = LiveRegisterManager(module, abi)
    instructions = list(manager.decoder.get_instructions(block))
    if target:
        ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                             gtirb.Edge.Label(gtirb.EdgeType.Call, direct=direct)))
    cls = TransientIndirectTargetPolicyPass if target else TransientStorePolicyPass
    policy = cls(manager, block.section, manager.decoder, arch, dift_layout=fixture_layout(arch.name))
    info = policy._build_policy_patch(instructions[-1], len(instructions)-1,
                                     sum(i.size for i in instructions[:-1]), block)
    return arch, module, block, info


class TaggedSinksTests(unittest.TestCase):
    def test_store_exemptions_match_loads(self):
        forms = (('mov [rsp],rax', 'mov [rip],rax'),
                 ('str x1,[x0]', 'str x1,[sp]'),
                 ('sd a1,0(a0)', 'sd a1,0(sp)', 'sd a1,0(gp)', 'sd a1,0(tp)', 'sd a1,0(zero)'))
        for case, stores in zip(CASES, forms):
            for i, store in enumerate(stores):
                with self.subTest(isa=case[0].__name__, store=store):
                    _, _, _, info = build_info(case, store)
                    self.assertEqual(info is not None, i == 0)
                    if info:
                        self.assertFalse(info.queues_tags)

    def test_read_modify_write_and_implicit_stores(self):
        for store in ('add qword ptr [rdi],1', 'setne byte ptr [rdi]', 'push rax', 'call rax',
                      'fstp qword ptr [rdi]', 'movdqu [rdi],xmm0', 'maskmovdqu xmm0,xmm1'):
            with self.subTest(store=store):
                self.assertIsNotNone(build_info(CASES[0], store)[3])

    def test_returns_are_excluded_even_with_an_indirect_call_edge(self):
        for case in CASES:
            with self.subTest(isa=case[0].__name__):
                self.assertIsNone(build_info(case, case[8], target=True)[3])

    def test_resolved_register_edges_remain_indirect_instructions(self):
        for case in CASES:
            with self.subTest(isa=case[0].__name__):
                self.assertIsNotNone(build_info(case, case[6], target=True, direct=True)[3])
        self.assertIsNone(build_info(CASES[0], '.byte 0xe8,0,0,0,0', target=True, direct=True)[3])

    def test_x64_memory_target_uses_scalar_pointer_load_tags(self):
        arch, _, _, info = build_info(CASES[0], 'call qword ptr [rdi]', target=True)
        self.assertTrue(info.reads_memory_tags)
        self.assertEqual({r.name for r in info.tag_registers}, {'rdi'})
        self._execute(CASES[0], 'call qword ptr [rdi]', target=True, memory=True)
        self._execute(CASES[0], 'call qword ptr [rdi]', target=True, memory=True, address_tag=4)
        self._execute(CASES[0], 'call qword ptr [rdi]', target=True, memory=True, address_tag=8)

    def test_predicates_execute_on_all_three_isas(self):
        for case in CASES:
            for text, target in ((case[5], False), (case[6], True), (case[7], True)):
                with self.subTest(isa=case[0].__name__, instruction=text):
                    self._execute(case, text, target=target)

    def test_aarch64_pac_branches_report_stripped_targets(self):
        # blraa x0, x1 and braaz x0 are checked like blr/br; retaa stays a return.
        for code in (bytes.fromhex('01083fd7'), bytes.fromhex('1f081fd6')):
            with self.subTest(code=code.hex()):
                self._execute(CASES[1], code, target=True, pac=True)
        self.assertIsNone(build_info(CASES[1], bytes.fromhex('ff0b5fd6'), target=True)[3])

    def _execute(self, case, instruction, *, target=False, memory=False, address_tag=0, pac=False):
        _, _, compiler, launch, prefix, _, _, _, _, scratch, address_name = case
        if not shutil.which(compiler) or launch and not shutil.which(launch[0]):
            self.skipTest('requires target compiler and emulator')
        arch, _, _, info = build_info(case, instruction, target=target)
        self.assertIsNotNone(info)
        def reporter(kind, *args, **kwargs):
            if arch.name == 'x64':
                return f'mov reported_tag, {kwargs["tag_reg"]}\nmov reported_address, {kwargs["addr_reg"]}\n'
            address, tag, temp = args[:3]
            return arch.load_address(temp, 'reported_tag') + (
                f'str {tag}, [{temp}]\n' if arch.name == 'aarch64' else f'sd {tag}, 0({temp})\n') + \
                arch.load_address(temp, 'reported_address') + (
                f'str {address}, [{temp}]\n' if arch.name == 'aarch64' else f'sd {address}, 0({temp})\n')
        # Only reporting is replaced. The tag merge, mask, address calculation
        # and pointer memory-tag load are the production patch.
        with patch.object(type(arch), 'report_gadget_snippet', side_effect=reporter):
            asm = info.patch(SimpleNamespace(stack_adjustment=0,
                scratch_registers=tuple(arch.abi.get_register(n) for n in scratch)))
        tag_id = arch.dift_register_id(arch.abi.get_register(address_name))
        xor = fixture_layout(arch.name).xor_mask
        source = f'''
            #include <assert.h>
            #include <stdint.h>
            #include <sys/mman.h>
            unsigned char dift_reg_tags[48];
            uint64_t reported_tag, reported_address;
            extern void probe(uintptr_t, uintptr_t);
            int main(void) {{
                unsigned char data[32];
                uintptr_t value = (uintptr_t)data | {0x5a << 48 if pac else 0}ull, pointer = value;
                unsigned char *shadow = 0;
                if ({int(memory)}) {{
                    value = (uintptr_t)&pointer;
                    shadow = (void *)(value ^ {xor}ull);
                    assert(mmap((void *)((uintptr_t)shadow & ~4095ull),4096,3,
                                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) != MAP_FAILED);
                }}
                const unsigned tags[] = {{0, 1, 2, 4, 8, 15, 128}};
                for (unsigned i=0;i<sizeof(tags)/sizeof(*tags);++i) {{
                    reported_tag=reported_address=0;
                    dift_reg_tags[{tag_id}]={address_tag if memory else 'tags[i]'};
                    if (shadow) *shadow=tags[i];
                    probe(value,0);
                    unsigned expected_tag = tags[i] | {address_tag};
                    assert(reported_tag == ((expected_tag & 10) ? expected_tag : 0));
                    assert(reported_address == ((expected_tag & 10) ?
                        ({'pointer' if memory else 'value'} & ~{1 if arch.name == 'riscv64' and target else 0}ull
                         & ~{0x7f << 48 if pac else 0}ull) : 0));
                }}
                return 0;
            }}
        '''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'probe.c').write_text(source)
            (root/'probe.S').write_text(prefix + '.text\n.globl probe\nprobe:\n' + asm +
                                        '\nret\n.section .note.GNU-stack,"",%progbits\n')
            build = subprocess.run([compiler,'-static','-O2','-no-pie',str(root/'probe.c'),str(root/'probe.S'),
                                    '-o',str(root/'probe')],capture_output=True,text=True)
            self.assertEqual(build.returncode,0,build.stderr)
            run = subprocess.run([*launch,str(root/'probe')],capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
