import unittest

import gtirb

from tools.sharedlib import convert as converter


class SelectedLifecycleTests(unittest.TestCase):
    def fixture(self, role='selected'):
        module = gtirb.Module(name='life', isa=gtirb.Module.ISA.X64,
                              file_format=gtirb.Module.FileFormat.ELF)
        gtirb.IR(modules=[module])
        for key, schema in (
            ('elfSymbolInfo', 'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>'),
            ('sectionProperties', 'mapping<UUID,tuple<uint64_t,uint64_t>>'),
            ('symbolicExpressionSizes', 'mapping<Offset,uint64_t>'),
            ('alignment', 'mapping<UUID,uint64_t>')):
            module.aux_data[key] = gtirb.AuxData({}, schema)
        sections = {}
        for name, address in (('.init', 0x1000), ('.fini', 0x1100), ('.fini_array', 0x2000)):
            section = gtirb.Section(name=name, module=module)
            contents = bytes(16) if name.endswith('array') else b'\xc3'
            interval = gtirb.ByteInterval(address=address, contents=contents, section=section)
            if name.endswith('array'):
                for i in range(2):
                    gtirb.DataBlock(size=8, offset=i * 8, byte_interval=interval)
                module.aux_data['sectionProperties'].data[section] = (15, 3)
            else:
                block = gtirb.CodeBlock(size=1, byte_interval=interval)
                module.aux_data['elfDynamic' + ('Init' if name == '.init' else 'Fini')] = gtirb.AuxData(block, 'UUID')
            sections[name] = section
        item = {'role': role, 'path': '/input', 'soname': 'liblife.so' if role == 'selected' else None,
                'lifecycle': {'DT_INIT': 0x1000, 'DT_FINI': 0x1100}}
        return module, item, sections

    def test_preserves_bodies_and_moves_fini_array_without_losing_bytes(self):
        module, item, sections = self.fixture()
        block = module.aux_data['elfDynamicInit'].data
        desc = converter.preserve_selected_lifecycle(module, item, 100)
        self.assertNotIn('elfDynamicInit', module.aux_data)
        self.assertNotIn('elfDynamicFini', module.aux_data)
        self.assertTrue(sections['.init'].name.startswith('.text.'))
        array = next(s for s in module.sections if s.name == '.init_array.00200')
        self.assertIs(next(iter(array.byte_intervals)).symbolic_expressions[0].symbol.referent, block)
        fini = sections['.fini_array']
        self.assertTrue(fini.name.startswith('.data.'))
        self.assertEqual(next(iter(fini.byte_intervals)).contents, bytes(16))
        begin, end = [next(module.symbols_named(name)) for name in desc['fini_array']]
        self.assertEqual(begin.referent.address, 0x2000)
        self.assertEqual(end.referent.address + end.referent.size, 0x2010)
        self.assertTrue(end.at_end)
        self.assertEqual(module.aux_data['sectionProperties'].data[fini], (1, 3))

    def test_executable_keeps_its_inert_dynamic_fini(self):
        module, item, sections = self.fixture('executable')
        desc = converter.preserve_selected_lifecycle(module, item, None)
        self.assertIn('elfDynamicInit', module.aux_data)
        self.assertIn('elfDynamicFini', module.aux_data)
        self.assertIsNone(desc['fini'])
        self.assertEqual(sections['.init'].name, '.init')

    def test_missing_fini_array_bytes_rejected(self):
        module, item, sections = self.fixture()
        interval = next(iter(sections['.fini_array'].byte_intervals))
        next(b for b in interval.blocks if b.offset == 8).byte_interval = None
        with self.assertRaisesRegex(converter.Unsupported, 'UNRECOVERED_FINI_ARRAY'):
            converter.preserve_selected_lifecycle(module, item, 100)


if __name__ == '__main__':
    unittest.main()
