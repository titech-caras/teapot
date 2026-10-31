"""Inspect the generated component BTI/PAC layout after a real A64 link."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from elftools.elf.elffile import ELFFile
from experiments.reusable_libraries.rewrite_components import component_layout


ASSEMBLER = shutil.which('aarch64-linux-gnu-as')
LINKER = os.environ.get('LLD_PATH') or shutil.which('ld.lld')


@unittest.skipUnless(ASSEMBLER and LINKER, 'A64 assembler and LLD required')
class ComponentBTILayoutTests(unittest.TestCase):
    def command(self, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_two_components_guard_probes_and_preinit_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            components = [dict(component_id=key, guard_count=1) for key in ('a'*16, 'b'*16)]
            objects = []
            for index, component in enumerate(components):
                key = component['component_id']
                source = root/f'component-{index}.S'
                source.write_text(f'''
.section .teapot_bti_normal,"ax",@progbits
.balign 16
.long 0xd50324df, 0xd280a29f, 0xd65f03c0
.section .teapot_transient,"ax",@progbits
.long 0xd65f03c0
.section .teapot_component_guards.{key},"aw",@progbits
.balign {4 if index == 0 else 16}
.global __guard_start__teapot___{key}, __guard_end__teapot___{key}
__guard_start__teapot___{key}: .long 0
__guard_end__teapot___{key}:
''')
                obj = source.with_suffix('.o')
                self.command([ASSEMBLER, source, '-o', obj])
                objects.append(obj)
            runtime = root/'runtime.S'
            runtime.write_text('''
.text
.global _start, libcheckpoint_prepare_aarch64_bti_pac_components
_start:
libcheckpoint_prepare_aarch64_bti_pac_components: ret
.data
.quad 0
.section .teapot_bti_probe,"ax",@progbits
.balign 4
.global teapot_bti_probe_valid, teapot_bti_probe_invalid, teapot_bti_probe_brk, teapot_bti_probe_hlt
teapot_bti_probe_valid: .long 0xd50324df
teapot_bti_probe_invalid: .long 0xd503201f
teapot_bti_probe_brk: .long 0xd4200000
teapot_bti_probe_hlt: .long 0xd4400000
.section .preinit_array,"aw",@preinit_array
.global __teapot_bti_component_preinit
__teapot_bti_component_preinit: .quad libcheckpoint_prepare_aarch64_bti_pac_components
''')
            self.command([ASSEMBLER, runtime, '-o', root/'runtime.o'])
            layout = root/'layout.ld'
            layout.write_text(component_layout(components, 'aarch64-bti-pac'))
            binary = root/'linked'
            self.command([LINKER, '-T', layout, *objects, root/'runtime.o', '-o', binary])
            with binary.open('rb') as stream:
                elf = ELFFile(stream)
                self.assertEqual(elf['e_machine'], 'EM_AARCH64')
                symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}
                low, high = (symbols['__teapot_bti_guard_'+end] for end in ('start', 'end'))
                self.assertEqual((low % 65536, high-low), (0, 131072))
                transient = symbols['__teapot_bti_transient_start']
                self.assertEqual(transient % 65536, 0)
                self.assertEqual(symbols['__teapot_bti_transient_end']-transient, 8)
                section = elf.get_section_by_name('.teapot_bti_normal')
                data = section.data()
                self.assertEqual(data.count(struct.pack('<III', 0xd50324df, 0xd280a29f, 0xd65f03c0)), 2)
                offset = transient-section['sh_addr']
                self.assertEqual(data[offset:offset+8], struct.pack('<II', 0xd65f03c0, 0xd65f03c0))
                for name, word in (('valid', 0xd50324df), ('invalid', 0xd503201f),
                                   ('brk', 0xd4200000), ('hlt', 0xd4400000)):
                    pc = symbols['teapot_bti_probe_'+name]
                    self.assertTrue(transient < pc < high)
                    self.assertEqual(data[pc-section['sh_addr']:pc-section['sh_addr']+4], struct.pack('<I', word))
                preinit = elf.get_section_by_name('.preinit_array')
                self.assertEqual(int.from_bytes(preinit.data(), 'little'),
                                 symbols['libcheckpoint_prepare_aarch64_bti_pac_components'])
                self.assertFalse(low <= preinit['sh_addr'] < high)
                self.assertEqual([symbols['__teapot_component_guard_base_'+c['component_id']] for c in components], [0, 4])
