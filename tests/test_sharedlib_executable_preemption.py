"""Executable dynsym definitions preempt only ordinary selected-DSO imports."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

import gtirb
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from experiments.reusable_libraries import rewrite_components as driver
from tools.sharedlib import convert
from teapot.configs.runtime import is_generated_name


class ExecutablePreemptionTests(unittest.TestCase):
    def test_main_preempts_got_plt_but_not_local_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, library = root / 'lib.c', root / 'libpreempt.so'
            source.write_text('int api(void) { return 7; }\nint data = 3;\n'
                              'int call(void) { return api(); }\nint *get(void) { return &data; }\n'
                              'void *ptr = &api;\n')
            subprocess.run(['gcc', '-O0', '-fPIC', '-shared', '-nostdlib',
                            '-Wl,-soname,libpreempt.so', str(source), '-o', str(library)], check=True)
            selected = convert.inspect(library, 'selected')
            definitions = {s['name']: s for s in selected['symbols'] if s['name'] in ('api', 'data')}
            main = dict(path='/main', role='executable', machine='EM_X86_64', elf_flags=0, entry=0,
                        needed=['libpreempt.so'], soname=None, versions=[], version_definitions=[],
                        symbols=[copy.deepcopy(s) for s in definitions.values()])
            self.assertEqual(convert.validate_closure(main, [selected], []), ['libpreempt.so'])
            self.assertEqual(set(selected['executable_interpositions']), {'api', 'data'})
            self.assertNotIn('api', driver.exports(selected, convert))
            self.assertNotIn('data', driver.exports(selected, convert, False))
            context = dict(selected_libraries=[('libpreempt.so', 'bytes')],
                           bindings=[('api', 'executable'), ('call', 'libpreempt.so')])
            self.assertIn(('api', 'executable'), driver.component_bindings(selected, convert, context))
            before = convert.ordinary_object_recipe(selected, {'allow_ambiguous_data_pointers': False})
            after = convert.ordinary_object_recipe(dict(selected, executable_interpositions=[]),
                                                  {'allow_ambiguous_data_pointers': False})
            self.assertNotEqual(before, after)

            module = gtirb.Module(name='lib', isa=gtirb.Module.ISA.X64)
            gtirb.IR(modules=[module])
            text = gtirb.Section(name='.text', module=module)
            data = gtirb.Section(name='.data', module=module)
            got = gtirb.Section(name='.got', module=module)
            info, locals_, forwarding, slots = {}, {}, {}, []
            for name, row in definitions.items():
                interval = gtirb.ByteInterval(address=row['address'], contents=bytes(8),
                                              section=text if name == 'api' else data)
                block = (gtirb.CodeBlock if name == 'api' else gtirb.DataBlock)(
                    size=8, byte_interval=interval)
                symbol = gtirb.Symbol(name=name, payload=block, module=module)
                info[symbol] = (row['size'], row['type'][4:], 'GLOBAL', 'DEFAULT', row['section'])
                locals_[name] = symbol
            local_expression = gtirb.SymAddrConst(0, locals_['api'])
            locals_['api'].referent.byte_interval.symbolic_expressions[1] = local_expression
            with library.open('rb') as stream:
                elf = ELFFile(stream)
                types = set()
                for section in elf.iter_sections():
                    if not isinstance(section, RelocationSection):
                        continue
                    table = elf.get_section(section['sh_link'])
                    for relocation in section.iter_relocations():
                        name = table.get_symbol(relocation['r_info_sym']).name
                        if name not in locals_:
                            continue
                        types.add(relocation['r_info_type'])
                        interval = gtirb.ByteInterval(address=relocation['r_offset'],
                                                      contents=bytes(8), section=got)
                        block = gtirb.DataBlock(size=8, byte_interval=interval)
                        slot = gtirb.Symbol(name='slot_' + name, payload=block, module=module)
                        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, locals_[name])
                        forwarding[slot] = locals_[name]
                        slots.append((slot, name))
                self.assertEqual(types, {1, 6, 7})  # R_X86_64_64, GLOB_DAT, JUMP_SLOT
            module.aux_data['elfSymbolInfo'] = gtirb.AuxData(
                info, 'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
            module.aux_data['symbolForwarding'] = gtirb.AuxData(forwarding, 'mapping<UUID,UUID>')
            collisions = [gtirb.Symbol(name='.L__component_interposed_' + name, module=module)
                          for name in definitions]
            with self.assertRaisesRegex(convert.Unsupported, 'UNRECOVERED_INTERPOSITION'):
                convert.bind_executable_interpositions(module, selected)
            for symbol in collisions:
                module.symbols.discard(symbol)
            convert.bind_executable_interpositions(module, selected)
            for slot, name in slots:
                target = forwarding[slot]
                self.assertEqual(target.name, name)
                self.assertIsInstance(target.referent, gtirb.ProxyBlock)
                self.assertIs(slot.referent.byte_interval.symbolic_expressions[0].symbol, target)
                self.assertEqual(info[locals_[name]][2], 'LOCAL')
                self.assertFalse(is_generated_name(locals_[name].name))
            self.assertIs(local_expression.symbol, locals_['api'])

            for failure in ('symbolic', 'external_duplicate'):
                with self.subTest(failure=failure):
                    other = copy.deepcopy(selected)
                    external = []
                    if failure == 'symbolic':
                        other['symbolic_lookup'] = True
                    else:
                        external = [dict(other, path='/external', role='external', soname='external.so')]
                    with self.assertRaisesRegex(convert.Unsupported, 'AMBIGUOUS_GLOBAL_BINDING'):
                        convert.validate_closure(main, [other], external)


if __name__ == '__main__':
    unittest.main()
