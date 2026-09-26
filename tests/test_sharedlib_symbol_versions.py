"""Selected ELF versions become exact static identities; libc remains external."""
import copy
import importlib.util
from pathlib import Path
import unittest

import gtirb

spec = importlib.util.spec_from_file_location('sharedlib_version_converter',
    Path(__file__).resolve().parents[1] / 'tools/sharedlib/convert.py')
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)


class SelectedSymbolVersionsTests(unittest.TestCase):
    def module(self, defined):
        module = gtirb.Module(name='versions', isa=gtirb.Module.ISA.X64,
                              file_format=gtirb.Module.FileFormat.ELF)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name='.text', module=module)
        interval = gtirb.ByteInterval(address=0x1000, contents=b'\xc3\xc3', section=section)
        targets = ([gtirb.CodeBlock(size=1, offset=i, byte_interval=interval) for i in range(2)]
                   if defined else [gtirb.ProxyBlock(module=module) for _ in range(2)])
        symbols = [gtirb.Symbol(name='api', payload=target, module=module) for target in targets]
        external = gtirb.Symbol(name='printf', payload=gtirb.ProxyBlock(module=module), module=module)
        module.aux_data['elfSymbolInfo'] = gtirb.AuxData(
            {s: (1, 'FUNC', 'GLOBAL', 'DEFAULT', 1 if defined and s != external else 0)
             for s in symbols + [external]}, 'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
        module.aux_data['elfSymbolTabIdxInfo'] = gtirb.AuxData(
            {s: [] for s in symbols + [external]}, 'mapping<UUID,sequence<tuple<string,uint64_t>>>')
        definitions = {2: (['LIBTEST_1'], 0), 3: (['LIBTEST_2', 'LIBTEST_1'], 0)} if defined else {}
        needed = {'libc.so.6': {4: 'GLIBC_2.2.5'}}
        if not defined:
            needed['libversions.so'] = {2: 'LIBTEST_1', 3: 'LIBTEST_2'}
        module.aux_data['elfSymbolVersions'] = gtirb.AuxData(
            (definitions, needed, {symbols[0]: (2, defined), symbols[1]: (3, False), external: (4, False)}),
            'tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,mapping<string,mapping<uint16_t,string>>,mapping<UUID,tuple<uint16_t,bool>>>')
        return module, symbols, targets, external

    def item(self, role):
        return {'path': '/input', 'soname': 'libversions.so' if role == 'selected' else None,
                'role': role, 'resolve_selected_versions': True}

    def test_definitions_imports_default_alias_and_external_requirements(self):
        library, definitions, targets, libc = self.module(True)
        caller, imports, proxies, caller_libc = self.module(False)
        for module, role in ((library, 'selected'), (caller, 'executable')):
            converter.resolve_selected_symbol_versions(module, self.item(role), {'libversions.so'})
        self.assertEqual([s.name for s in definitions], [s.name for s in imports])
        self.assertNotEqual(definitions[0].name, definitions[1].name)
        self.assertEqual([s.referent for s in definitions], targets)
        self.assertEqual([s.referent for s in imports], proxies)
        public = list(library.symbols_named('api'))
        self.assertEqual(len(public), 1)
        self.assertIs(public[0].referent, targets[1])
        for module, external in ((library, libc), (caller, caller_libc)):
            _, needed, entries = module.aux_data['elfSymbolVersions'].data
            self.assertEqual(entries[external], (4, False))
            self.assertEqual(needed['libc.so.6'], {4: 'GLIBC_2.2.5'})
            self.assertEqual(external.name, 'printf')
            self.assertEqual(len(entries), 1)

    def test_namespace_collision_is_rejected(self):
        module, _, _, _ = self.module(False)
        gtirb.Symbol(name='__teapot_selected_version_input', module=module)
        with self.assertRaisesRegex(converter.Unsupported, 'RESERVED_VERSION_SYMBOL'):
            converter.resolve_selected_symbol_versions(module, self.item('executable'), {'libversions.so'})

    def test_missing_version_or_exact_symbol_is_rejected(self):
        symbol = {'name': 'api', 'version': 'LIBTEST_1', 'version_library': 'libversions.so',
                  'binding': 'STB_GLOBAL', 'visibility': 'STV_DEFAULT', 'section': 'SHN_UNDEF'}
        executable = dict(self.item('executable'), machine='EM_X86_64', needed=['libversions.so'],
                          symbols=[symbol], versions=[{'library': 'libversions.so', 'versions': ['LIBTEST_1']}])
        library = dict(self.item('selected'), machine='EM_X86_64', needed=[], versions=[],
                       version_definitions=[{'name': 'LIBTEST_1'}],
                       symbols=[dict(symbol, section=1, version_library=None)])
        self.assertEqual(converter.validate_closure(executable, [library], []), ['libversions.so'])
        for field, value in (('version_definitions', []), ('symbols', [dict(library['symbols'][0], name='different')])):
            broken = copy.deepcopy(library)
            broken[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(converter.Unsupported, 'MISSING_SELECTED_SYMBOL_VERSION'):
                converter.validate_closure(executable, [broken], [])


if __name__ == '__main__':
    unittest.main()
