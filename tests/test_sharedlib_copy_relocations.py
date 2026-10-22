"""Only loader-initialized copies of retained external data are admissible."""
import copy
import unittest
from unittest.mock import patch

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

    def test_final_copy_aliases_cannot_hide_any_complete_identity_difference(self):
        class Symbol(dict):
            @property
            def entry(self):
                return self
        first = Symbol(st_name=1, st_value=0x5000, st_size=8, st_shndx=4,
                       st_info={'bind': 'STB_GLOBAL', 'type': 'STT_OBJECT'},
                       st_other={'visibility': 'STV_DEFAULT'})
        for key, value in (('st_value', 0x5010), ('st_size', 16), ('st_shndx', 5),
                           ('st_info', {'bind': 'STB_WEAK', 'type': 'STT_OBJECT'}),
                           ('st_other', {'visibility': 'STV_HIDDEN'})):
            with self.subTest(key=key):
                second = Symbol(copy.deepcopy(first))
                second[key] = value
                with self.assertRaisesRegex(ValueError, 'unique definition'):
                    unique_symbol_address({'stdin': [first, second]}, 'stdin', {'stdin': 'stdin'})

    def test_identical_linker_copy_aliases_are_one_destination_but_versions_cannot_differ(self):
        class Table(dict):
            def get_symbol(self, index):
                return None
        class Relocation(dict):
            entry = {}
        class Elf:
            def get_section(self, index):
                return (Table(sh_type='SHT_DYNSYM') if index == 1 else
                        dict(sh_flags=3, sh_addr=0x5000, sh_size=8))
        symbol = self.inputs('EM_RISCV')[0]['symbols'][0]
        raw = {key: value for key, value in symbol.items() if not key.startswith('version')}
        relocation = Relocation(r_info_sym=0, r_offset=0x5000)
        aliases = [symbol, copy.deepcopy(symbol)]
        with patch.object(converter, 'sym_record', return_value=raw):
            self.assertEqual(converter.copy_relocation_symbol(
                Elf(), {'sh_link': 1}, relocation, aliases, '/main', 'executable'), symbol)
            aliases[1]['version'] = 'OTHER'
            with self.assertRaisesRegex(converter.Unsupported, 'COPY_RELOCATION'):
                converter.copy_relocation_symbol(
                    Elf(), {'sh_link': 1}, relocation, aliases, '/main', 'executable')

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

    def test_selected_unknown_or_inexact_copy_provider_is_refused_on_every_isa(self):
        for machine in converter.ARCHITECTURES:
            for failure in ('selected', 'missing', 'unreachable', 'version', 'library',
                            'size', 'function', 'absolute', 'hidden', 'ambiguous'):
                with self.subTest(machine=machine, failure=failure):
                    executable, selected, external = self.inputs(machine)
                    candidate = external['symbols'][0]
                    if failure == 'selected':
                        selected['symbols'] = external['symbols']
                        external['symbols'] = []
                    elif failure == 'missing':
                        external['symbols'] = []
                    elif failure == 'unreachable':
                        executable['needed'] = ['libselected.so']
                    elif failure == 'version':
                        candidate['version'] = 'OTHER'
                    elif failure == 'library':
                        executable['symbols'][0]['version_library'] = 'unknown.so'
                    elif failure == 'size':
                        candidate['size'] = 16
                    elif failure == 'function':
                        candidate['type'] = 'STT_FUNC'
                    elif failure == 'absolute':
                        candidate['section'] = 'SHN_ABS'
                    elif failure == 'hidden':
                        candidate['visibility'] = 'STV_HIDDEN'
                    else:
                        selected['symbols'] = [copy.deepcopy(candidate)]
                    with self.assertRaisesRegex(converter.Unsupported, 'COPY_RELOCATION'):
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
