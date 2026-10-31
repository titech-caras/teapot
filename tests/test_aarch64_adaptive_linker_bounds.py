"""Linker-generated A53 erratum thunks belong to the adaptive copy extent."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from elftools.elf.elffile import ELFFile


LINKER = os.environ.get('LLD_PATH') or shutil.which('ld.lld')
ASSEMBLER = shutil.which('aarch64-linux-gnu-as')
FRAGMENT = Path(__file__).resolve().parents[1] / 'scripts/AArch64AdaptiveFault.ld'
BOUND = '.__transient_end__teapot__'
SOURCE = '''
.section .teapot_transient,"ax",@progbits
.balign 65536
.globl _start
_start:
.space 0xff8
adrp x0, target
ldr x1, [x1]
ldr x2, [x0]
ret
{bound}
.section teapot_fault_sites,"a",@progbits
.space 32
.quad .__transient_end__teapot__ - .
.section .data,"aw",@progbits
.balign 4096
target: .xword 0
.section .text,"ax",@progbits
.globl caller
caller: bl external
ret
'''


@unittest.skipUnless(LINKER and ASSEMBLER, 'A64 assembler and LLD are required')
class AdaptiveLinkerBoundsTests(unittest.TestCase):
    def command(self, argv, *, success=True):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=30)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def assemble(self, root, bound):
        source, obj = root / 'fixture.S', root / 'fixture.o'
        source.write_text(SOURCE.format(bound=bound))
        self.command([ASSEMBLER, source, '-o', obj])
        return obj

    def test_real_erratum_thunk_is_inside_final_rounded_bound_before_plt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            obj = self.assemble(root, f'.global {BOUND}\n.hidden {BOUND}')
            with obj.open('rb') as stream:
                elf = ELFFile(stream)
                symbols = elf.get_section_by_name('.symtab')
                end, = symbols.get_symbol_by_name(BOUND)
                self.assertEqual(end['st_shndx'], 'SHN_UNDEF')
                self.assertEqual(end['st_info']['bind'], 'STB_GLOBAL')
                self.assertEqual(end['st_other']['visibility'], 'STV_HIDDEN')
                relocation, = elf.get_section_by_name('.relateapot_fault_sites').iter_relocations()
                self.assertEqual(symbols.get_symbol(relocation['r_info_sym']).name, BOUND)
            missing = self.command([LINKER, '--shared', '--fix-cortex-a53-843419',
                                    obj, '-o', root / 'missing.so'], success=False)
            self.assertIn(BOUND.encode(), missing.stderr)
            output = root / 'fixed.so'
            self.command([LINKER, '--shared', '--fix-cortex-a53-843419',
                          '-T', FRAGMENT, obj, '-o', output])
            with output.open('rb') as stream:
                elf = ELFFile(stream)
                transient = elf.get_section_by_name('.teapot_transient')
                plt = elf.get_section_by_name('.plt')
                symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
                end, = [s for s in symbols if s.name == BOUND]
                thunks = [s for s in symbols if s.name.startswith('__CortexA53843419_')]
                self.assertTrue(thunks, 'the fixture must actually trigger LLD erratum repair')
                begin, finish = transient['sh_addr'], transient['sh_addr'] + transient['sh_size']
                self.assertEqual(end['st_value'], finish)
                self.assertEqual((begin % 65536, finish % 65536), (0, 0))
                self.assertEqual(plt['sh_addr'], finish)
                for thunk in thunks:
                    self.assertGreaterEqual(thunk['st_value'], begin)
                    self.assertLessEqual(thunk['st_value'] + 8, finish)
                table = elf.get_section_by_name('teapot_fault_sites')
                relative = int.from_bytes(table.data()[32:40], 'little', signed=True)
                self.assertEqual(table['sh_addr'] + 32 + relative, finish)

    def test_emitted_bound_stays_undefined_in_assembled_object(self):
        from teapot.preprocess.fault_risc_windows import add_risc_fault_windows
        from test_fault_risc_windows import RiscWindowEmissionTests
        printer = os.environ.get('PPRINTER_PATH') or shutil.which('gtirb-pprinter')
        if not printer:
            self.skipTest('gtirb-pprinter is required to inspect emitted bound relocations')
        module, section, bounds, manager, _ = RiscWindowEmissionTests().fixture('aarch64')
        bounds[1].name = BOUND
        add_risc_fault_windows(module, section, bounds, manager, 'aarch64')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ir, assembly, obj = root / 'emitted.gtirb', root / 'emitted.S', root / 'emitted.o'
            module.ir.save_protobuf(ir)
            self.command([printer, '--ir', ir, '--asm', assembly])
            self.command([ASSEMBLER, assembly, '-o', obj])
            with obj.open('rb') as stream:
                elf = ELFFile(stream)
                symbols = elf.get_section_by_name('.symtab')
                end, = symbols.get_symbol_by_name(BOUND)
                self.assertEqual(end['st_shndx'], 'SHN_UNDEF')
                self.assertEqual(end['st_info']['bind'], 'STB_GLOBAL')
                self.assertEqual(end['st_other']['visibility'], 'STV_HIDDEN')
                references = [r for r in elf.get_section_by_name('.relateapot_fault_sites').iter_relocations()
                              if r['r_offset'] in (32, 48)]
                self.assertEqual(len(references), 2)
                self.assertTrue(all(symbols.get_symbol(r['r_info_sym']).name == BOUND for r in references))

if __name__ == '__main__':
    unittest.main()
