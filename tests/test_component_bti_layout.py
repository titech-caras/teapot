"""Check the generated final-link contract using real ELF sections/relocations."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from elftools.elf.elffile import ELFFile
from experiments.reusable_libraries.rewrite_components import component_layout
from experiments.reusable_libraries.validate_link import validate_bti_layout


class ComponentBTILayoutTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('cc'), 'ELF compiler/linker required')
    def test_two_objects_one_guard_probes_and_preinit(self):
        # The linker layout is ISA-independent; these are data encodings, not
        # host-executed instructions. Execution is covered by the AArch64 gate.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            components = [dict(component_id=key, guard_count=1) for key in ('a' * 16, 'b' * 16)]
            objects = []
            for index, component in enumerate(components):
                key = component['component_id']
                source = root / f'component-{index}.S'
                source.write_text(f'''
.section .teapot_bti_normal,"ax",@progbits
.balign 16
.long 0xd50324df, 0xd280a29f, 0xd65f03c0
.section .teapot_transient,"ax",@progbits
.long 0xd65f03c0
.section .teapot_component_guards.{key},"aw",@progbits
.global __guard_start__teapot___{key}, __guard_end__teapot___{key}
__guard_start__teapot___{key}: .long 0
__guard_end__teapot___{key}:
.section .note.GNU-stack,"",@progbits
''')
                obj = source.with_suffix('.o')
                subprocess.run(['cc', '-c', str(source), '-o', str(obj)], check=True, capture_output=True)
                objects.append(obj)
            runtime = root / 'runtime.S'
            runtime.write_text('''
.text
.global _start, libcheckpoint_prepare_aarch64_bti_pac_components
_start:
libcheckpoint_prepare_aarch64_bti_pac_components: .long 0
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
.section .note.GNU-stack,"",@progbits
''')
            layout, binary = root / 'layout.ld', root / 'linked'
            layout.write_text(component_layout(components, 'aarch64-bti-pac'))
            subprocess.run(['cc', '-no-pie', '-nostdlib', *map(str, objects), str(runtime),
                            '-Wl,-T,' + str(layout), '-o', str(binary)], check=True, capture_output=True)
            with binary.open('rb') as stream:
                elf = ELFFile(stream)
                symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}
                ranges = {kind: tuple(symbols['__teapot_linked_' + kind + '_' + end]
                                      for end in ('start', 'end')) for kind in ('normal', 'transient')}
                lo, hi = validate_bti_layout(elf, symbols.__getitem__, ranges)
                self.assertEqual(hi - lo, 131072)
                self.assertLess(ranges['normal'][1], hi)
                for name, bad in (('__teapot_bti_guard_end', hi - 4),
                                  ('__teapot_bti_text_end', ranges['normal'][1] - 4),
                                  ('teapot_bti_probe_invalid', lo),
                                  ('__teapot_bti_component_preinit', lo),
                                  ('libcheckpoint_prepare_aarch64_bti_pac_components', lo)):
                    broken = dict(symbols, **{name: bad})
                    with self.subTest(symbol=name), self.assertRaises(ValueError):
                        validate_bti_layout(elf, broken.__getitem__, ranges)
