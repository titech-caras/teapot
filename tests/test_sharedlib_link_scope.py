import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from elftools.elf.elffile import ELFFile

spec = importlib.util.spec_from_file_location('sharedlib_link_scope_converter',
    Path(__file__).resolve().parents[1] / 'tools/sharedlib/convert.py')
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)


class SelectedLinkScopeTests(unittest.TestCase):
    def test_external_scope_is_breadth_first_and_excludes_unused_providers(self):
        def provider(name, role, needed=()):
            return {'soname': name, 'role': role, 'needed': list(needed)}
        selected = [provider('selected', 'selected', ('deep', 'first'))]
        external = [provider('unused', 'external'),
                    provider('deep', 'external', ('first',)),
                    provider('second', 'external', ('deep',)),
                    provider('first', 'external', ('second',))]
        result = converter.external_load_order(
            {'needed': ['selected', 'first', 'second']}, selected, external)
        self.assertEqual([item['soname'] for item in result], ['first', 'second', 'deep'])

    def test_inferred_private_definitions_do_not_export_or_change_weak_imports(self):
        module = gtirb.Module(name='lib', isa=gtirb.Module.ISA.X64,
                              file_format=gtirb.Module.FileFormat.ELF)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name='.text', module=module)
        interval = gtirb.ByteInterval(address=0x1000, contents=b'\xc3', section=section)
        body = gtirb.CodeBlock(size=1, byte_interval=interval)
        info = {}
        symbols = {}
        for name, payload, binding, visibility in (
                ('exported', body, 'GLOBAL', 'DEFAULT'),
                ('inferred_anchor', body, 'GLOBAL', 'DEFAULT'),
                ('hidden_body', body, 'GLOBAL', 'HIDDEN'),
                ('absolute_anchor', 0x1234, 'GLOBAL', 'DEFAULT'),
                ('optional_import', gtirb.ProxyBlock(module=module), 'WEAK', 'DEFAULT')):
            symbol = gtirb.Symbol(name=name, payload=payload, module=module)
            symbols[name] = symbol
            info[symbol] = (0, 'NOTYPE', binding, visibility, 0)
        module.aux_data['elfSymbolInfo'] = gtirb.AuxData(info,
            'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
        item = {'symbols': [{'name': 'exported', 'section': 1,
                            'binding': 'STB_GLOBAL', 'visibility': 'STV_DEFAULT'}]}
        converter.localize_private_library_definitions(module, item)
        self.assertEqual(info[symbols['exported']][2], 'GLOBAL')
        self.assertEqual(info[symbols['optional_import']][2], 'WEAK')
        for name in ('inferred_anchor', 'hidden_body', 'absolute_anchor'):
            self.assertEqual(info[symbols[name]][2], 'LOCAL')

    @unittest.skipUnless(shutil.which('gcc') and shutil.which('objcopy'), 'ELF build tools required')
    def test_weak_import_opt_in_and_unnamed_fde_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / 'input.c', root / 'libscope.so'
            source.write_text('''
                extern int optional(void) __attribute__((weak));
                __attribute__((noinline,visibility("hidden")))
                int internal(int n) { return n + 3; }
                int exported(int n) { return internal(n) + (optional ? optional() : 0); }
            ''')
            subprocess.run(['gcc', '-O2', '-fPIC', '-shared', '-nostdlib', str(source),
                '-Wl,-soname,libscope.so,-Bsymbolic,-z,nodelete', '-o', str(binary)],
                check=True, capture_output=True)
            with binary.open('rb') as stream:
                elf = ELFFile(stream)
                address = elf.get_section_by_name('.symtab').get_symbol_by_name('internal')[0]['st_value']
            subprocess.run(['objcopy', '--strip-symbol=internal', str(binary)],
                           check=True, capture_output=True)
            with self.assertRaisesRegex(converter.Unsupported, 'WEAK_BINDING'):
                converter.inspect(binary, 'selected')
            item = converter.inspect(binary, 'selected', preserve_weak_imports=True)
            frames = [fde for fde in item['application_fdes'] if fde['start'] == address]
            self.assertEqual(len(frames), 1)
            self.assertGreater(frames[0]['size'], 0)
            self.assertEqual(frames[0]['names'], [])
            imports = [s for s in item['symbols'] if s['name'] == 'optional']
            self.assertEqual(len(imports), 1)
            self.assertEqual(imports[0]['binding'], 'STB_WEAK')
            self.assertEqual(imports[0]['section'], 'SHN_UNDEF')


if __name__ == '__main__':
    unittest.main()
