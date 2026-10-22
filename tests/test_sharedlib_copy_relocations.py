"""Only loader-initialized copies of retained external data are admissible."""
import copy
import unittest

import gtirb

from tools.sharedlib import convert as converter
from experiments.reusable_libraries.validate_link import unique_symbol_address


class ExternalCopyRelocationTests(unittest.TestCase):
    def test_final_copy_aliases_allow_string_offsets_and_exact_versioned_base_lookup(self):
        class Symbol(dict):
            @property
            def entry(self):
                return self
        first = Symbol(st_name=1, st_value=0x5000, st_size=8, st_shndx=4,
                       st_info={'bind': 'STB_GLOBAL', 'type': 'STT_OBJECT'},
                       st_other={'visibility': 'STV_DEFAULT'})
        second = Symbol(copy.deepcopy(first), st_name=30)
        aliases = {'stdin': 'stdin', 'stdin@@GLIBC_TEST': 'stdin'}
        symbols = {'stdin': [first, second]}
        self.assertEqual(unique_symbol_address(symbols, 'stdin', aliases), 0x5000)
        self.assertEqual(unique_symbol_address(symbols, 'stdin@@GLIBC_TEST', aliases), 0x5000)
        with self.assertRaisesRegex(ValueError, 'unique definition'):
            unique_symbol_address(symbols, 'stdin@@OTHER', aliases)
        with self.assertRaisesRegex(ValueError, 'unique definition'):
            unique_symbol_address(symbols, 'stdin', {})

    def inputs(self, machine):
        symbol = dict(name='stdin', type='STT_OBJECT', binding='STB_GLOBAL',
                      visibility='STV_DEFAULT', section=4, address=0x5000, size=8,
                      version='GLIBC_TEST', version_library='libc.so.6', version_default=True)
        common = dict(machine=machine, elf_flags=0, versions=[], version_definitions=[])
        executable = dict(common, path='/main', role='executable', soname=None,
                          needed=['libselected.so', 'libc.so.6'], symbols=[symbol],
                          copy_relocations=[dict(address=0x5000, symbol=symbol)])
        selected = dict(common, path='/libselected.so', role='selected', soname='libselected.so',
                        needed=[], symbols=[])
        external = dict(common, path='/libc.so.6', role='external', soname='libc.so.6',
                        needed=[], symbols=[dict(symbol, address=0x6000, version_library=None)])
        return executable, selected, external

    def test_external_copy_resolves_on_all_three_isas_without_relaxing_other_duplicates(self):
        for machine in converter.ARCHITECTURES:
            with self.subTest(machine=machine):
                executable, selected, external = self.inputs(machine)
                self.assertEqual(converter.validate_closure(executable, [selected], [external]),
                                 ['libselected.so'])
                self.assertEqual(executable['copy_relocations'][0]['provider'], 'libc.so.6')
                ordinary = dict(executable['symbols'][0], name='ordinary', version=None)
                executable['symbols'].append(ordinary)
                external['symbols'].append(dict(ordinary, address=0x7000))
                with self.assertRaisesRegex(converter.Unsupported, 'AMBIGUOUS_GLOBAL_BINDING'):
                    converter.validate_closure(executable, [selected], [external])

    def test_copy_requires_external_forwarding_not_a_plain_bss_definition(self):
        for machine, isa in (('EM_X86_64', 'X64'), ('EM_AARCH64', 'ARM64'), ('EM_RISCV', 'RISCV64')):
            with self.subTest(machine=machine):
                executable, _, _ = self.inputs(machine)
                module = gtirb.Module(name='main', isa=getattr(gtirb.Module.ISA, isa),
                                      file_format=gtirb.Module.FileFormat.ELF)
                gtirb.IR(modules=[module])
                section = gtirb.Section(name='.bss', module=module)
                interval = gtirb.ByteInterval(address=0x5000, size=8, section=section)
                data = gtirb.DataBlock(size=8, byte_interval=interval)
                source = gtirb.Symbol(name='stdin_copy', payload=data, module=module)
                target = gtirb.Symbol(name='stdin', payload=gtirb.ProxyBlock(module=module), module=module)
                module.aux_data['elfSymbolInfo'] = gtirb.AuxData(
                    {source: (8, 'OBJECT', 'GLOBAL', 'DEFAULT', 4)},
                    'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
                with self.assertRaisesRegex(converter.Unsupported, 'missing external COPY forwarding'):
                    converter.validate_copy_forwarding(module, executable)
                module.aux_data['symbolForwarding'] = gtirb.AuxData({source: target}, 'mapping<UUID,UUID>')
                converter.validate_copy_forwarding(module, executable)
                target.referent = data
                with self.assertRaisesRegex(converter.Unsupported, 'missing external COPY forwarding'):
                    converter.validate_copy_forwarding(module, executable)


if __name__ == '__main__':
    unittest.main()
