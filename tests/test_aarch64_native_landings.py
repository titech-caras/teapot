import unittest
from pathlib import Path
import shutil
import subprocess
import tempfile

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext

from teapot.arch.aarch64.bti import AArch64BTIArchitecture
from teapot.passes.common.aarch64_outline_native_landings_pass import AArch64OutlineNativeLandingsPass
from test_live_register_preservation import make_module


class NativeLandingTests(unittest.TestCase):
    def test_native_instruction_is_preserved_outside_normal_text(self):
        for word in (0xd503233f, 0xd503237f, 0xd503245f, 0xd503249f, 0xd50324df,
                     0xd4207d00, 0xd4400240):
            with self.subTest(word=hex(word)):
                arch = AArch64BTIArchitecture()
                ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ARM64,
                                                     word.to_bytes(4, 'little') + bytes.fromhex('c0035fd6'))
                normal = block.section
                ctx = RewritingContext(module, Function.build_functions(module))
                transform = AArch64OutlineNativeLandingsPass(normal, arch.MAGIC_WORDS)
                transform.begin_module(module, [], ctx)
                ctx.apply()
                self.assertEqual(transform.outlined, 1)
                helpers = [s for s in module.sections if s.name == transform.SECTION]
                self.assertEqual(len(helpers), 1)
                decoder = GtirbInstructionDecoder(module.isa)
                normal_instructions = [i for b in normal.code_blocks for i in decoder.get_instructions(b)]
                self.assertNotIn(word, [int.from_bytes(i.bytes, 'little') for i in normal_instructions])
                self.assertEqual({i.mnemonic for i in normal_instructions}, {'b', 'ret'})
                native_instructions = [i for b in helpers[0].code_blocks for i in decoder.get_instructions(b)]
                self.assertEqual([int.from_bytes(i.bytes, 'little') for i in native_instructions].count(word), 1)
                self.assertTrue(any(e.source.section is normal and e.target.section is helpers[0]
                                    for e in ir.cfg if isinstance(e.target, gtirb.CodeBlock)))
                self.assertTrue(any(e.source.section is helpers[0] and e.target.section is normal
                                    for e in ir.cfg if isinstance(e.target, gtirb.CodeBlock)))

    def test_complete_teapot_marker_is_retained(self):
        arch = AArch64BTIArchitecture()
        _, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ARM64,
                                             arch.nop_bytes + bytes.fromhex('c0035fd6'))
        ctx = RewritingContext(module, Function.build_functions(module))
        transform = AArch64OutlineNativeLandingsPass(block.section, arch.MAGIC_WORDS)
        transform.begin_module(module, [], ctx)
        ctx.apply()
        self.assertEqual(transform.outlined, 0)

    @unittest.skipUnless(all(shutil.which(x) for x in
        ('ddisasm', 'aarch64-linux-gnu-gcc', 'qemu-aarch64')), 'AArch64 execution tools required')
    def test_pac_authentication_with_pauth_enabled_and_disabled(self):
        # These are the classic SP-only PAC hint forms. This does not claim
        # support for FEAT_PAuth_LR's PC-dependent PACM mode or async unwind.
        import os
        for sign, authenticate in ((25, 29), (27, 31)):
            with self.subTest(sign=sign), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, original = root / 'input.S', root / 'original'
                source.write_text('''
.text
.global _start
.type _start, %%function
_start:
 cmp xzr,xzr
 adr x9, resumed
 bl leaf
resumed:
 mov x8, #93
 svc #0
.size _start,.-_start
.type leaf, %%function
leaf:
 hint #%d
 b.ne failed
 hint #%d
 cmp x9,x30
 cset w0,ne
 ret
failed:
 mov w0,#99
 mov x8,#93
 svc #0
.size leaf,.-leaf
.section .note.GNU-stack,"",%%progbits
''' % (sign, authenticate))
                compiler = ['aarch64-linux-gnu-gcc', '-nostdlib', '-no-pie', '-Wa,--fatal-warnings']
                subprocess.run(compiler + [str(source), '-o', str(original)], check=True, capture_output=True)
                lifted = root / 'lifted.gtirb'
                subprocess.run(['ddisasm', str(original), '--ir', str(lifted), '-j1'],
                               check=True, capture_output=True)
                ir = gtirb.IR.load_protobuf(lifted)
                module = ir.modules[0]
                section = next(s for s in module.sections if s.name == '.text')
                context = RewritingContext(module, Function.build_functions(module))
                transform = AArch64OutlineNativeLandingsPass(section, AArch64BTIArchitecture.MAGIC_WORDS)
                transform.begin_module(module, [], context)
                context.apply()
                self.assertEqual(transform.outlined, 1)
                rewritten, printed, binary = root / 'rewritten.gtirb', root / 'printed.S', root / 'rewritten'
                ir.save_protobuf(rewritten)
                subprocess.run([os.environ.get('PPRINTER_PATH', 'gtirb-pprinter'), '--ir', str(rewritten),
                                '--asm', str(printed)], check=True, capture_output=True)
                subprocess.run(compiler + [str(printed), '-o', str(binary)], check=True, capture_output=True)
                for cpu in ('max,pauth=on', 'max,pauth=off'):
                    for target in (original, binary):
                        executed = subprocess.run(['qemu-aarch64', '-cpu', cpu, str(target)],
                                                  capture_output=True, timeout=10)
                        if b"Property '.pauth' not found" in executed.stderr:
                            self.skipTest('QEMU lacks configurable pointer authentication')
                        self.assertEqual(executed.returncode, 0, (cpu, str(target), executed.stderr))


if __name__ == '__main__':
    unittest.main()
