#!/usr/bin/env python3
"""ELF-only mutation tests for the narrow AArch64/RV64 startup contract.

Inputs are the unstripped GCC/glibc dynamic executable/selected-DSO pairs used
by the ordinary conversion harness, not source files or original objects.
These tests prove validation/rejection only, not successful reconstruction.
"""
import argparse
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import convert


class Mutation:
    def __init__(self, source):
        original = source.read_bytes()
        self.data = bytearray(original)
        self.elf = ELFFile(io.BytesIO(original))

    def offset(self, address):
        for section in self.elf.iter_sections():
            if section['sh_type'] != 'SHT_NOBITS' and section['sh_flags'] & 2 and \
                    section['sh_addr'] <= address < section['sh_addr'] + section['sh_size']:
                return section['sh_offset'] + address - section['sh_addr']
        raise AssertionError('unmapped fixture address ' + hex(address))

    def symbol(self, name):
        matches = [symbol for symbol in self.elf.get_section_by_name('.symtab').iter_symbols()
                   if symbol.name == name]
        assert len(matches) == 1, name
        return matches[0]

    def code(self, name, displacement, xor, size=4):
        offset = self.offset(self.symbol(name)['st_value'] + displacement)
        word = int.from_bytes(self.data[offset:offset + size], 'little')
        self.data[offset:offset + size] = (word ^ xor).to_bytes(size, 'little')

    def tag(self, name, value, change_type=False):
        section = self.elf.get_section_by_name('.dynamic')
        matches = [index for index, tag in enumerate(section.iter_tags())
                   if tag.entry.d_tag == name]
        assert len(matches) == 1, name
        offset = section['sh_offset'] + matches[0] * 16 + (0 if change_type else 8)
        struct.pack_into('<Q', self.data, offset, value)

    def section_field(self, name, field_offset, value):
        matches = [index for index, section in enumerate(self.elf.iter_sections())
                   if section.name == name]
        assert len(matches) == 1, name
        offset = self.elf['e_shoff'] + self.elf['e_shentsize'] * matches[0] + field_offset
        struct.pack_into('<Q', self.data, offset, value)

    def pointer(self, section_name, symbol_name):
        section = self.elf.get_section_by_name(section_name)
        struct.pack_into('<Q', self.data, section['sh_offset'], self.symbol(symbol_name)['st_value'])

    def relocation(self, symbol_name=None, symbol_replacement=None, type_replacement=None):
        dynsym = self.elf.get_section_by_name('.dynsym')
        names = {symbol.name: index for index, symbol in enumerate(dynsym.iter_symbols())}
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            for index, relocation in enumerate(section.iter_relocations()):
                if symbol_name is None or relocation['r_info_sym'] == names[symbol_name]:
                    symbol = names[symbol_replacement] if symbol_replacement else relocation['r_info_sym']
                    kind = type_replacement if type_replacement is not None else relocation['r_info_type']
                    struct.pack_into('<Q', self.data, section['sh_offset'] + index * section['sh_entsize'] + 8,
                                     (symbol << 32) | kind)
                    return
        raise AssertionError('missing fixture relocation ' + str(symbol_name))

    def interpreter(self):
        section = self.elf.get_section_by_name('.interp')
        self.data[section['sh_offset'] + 1] ^= 1

    def gp_symbol(self):
        section = self.elf.get_section_by_name('.symtab')
        index = next(index for index, symbol in enumerate(section.iter_symbols())
                     if symbol.name == '__global_pointer$')
        offset = section['sh_offset'] + index * section['sh_entsize'] + 8
        struct.pack_into('<Q', self.data, offset, self.symbol('__global_pointer$')['st_value'] + 8)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--external', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    results, accepted, sources = [], {}, {}

    def rejected(name, reason, callback):
        try:
            callback()
        except convert.Unsupported as error:
            assert str(error).startswith(reason + ':'), (name, reason, str(error))
            results.append({'name': name, 'expected': reason, 'rejection': str(error)})
        else:
            raise AssertionError(name + ': unsupported mutation accepted')

    def case(arch, role, name, reason, edit):
        source = args.inputs / arch / ('test_fuzz' if role == 'executable' else 'libhtp.so.2')
        mutation = Mutation(source)
        edit(mutation)
        path = args.out / (arch + '-' + name + '.elf')
        path.write_bytes(mutation.data)
        rejected(arch + '/' + name, reason, lambda: convert.inspect(path, role))

    for arch in ('aarch64', 'riscv64'):
        executable = convert.inspect(args.inputs / arch / 'test_fuzz', 'executable')
        library = convert.inspect(args.inputs / arch / 'libhtp.so.2', 'selected')
        external = [convert.inspect(path, 'external')
                    for path in sorted((args.external / arch / 'lib').iterdir())]
        order = convert.validate_closure(executable, [library], external)
        assert order == ['libhtp.so.2']
        accepted[arch] = (executable, library, external)
        sources[arch] = {Path(item['path']).name: item['sha256'] for item in [executable, library] + external}
        case(arch, 'executable', 'wrong-interpreter', 'UNSUPPORTED_INTERPRETER', lambda m: m.interpreter())
        case(arch, 'executable', 'wrong-abi', 'UNSUPPORTED_ABI_FLAGS',
             lambda m: struct.pack_into('<I', m.data, 48, 2))
        case(arch, 'selected', 'foreign-relocation', 'UNSUPPORTED_RELOCATION',
             lambda m, kind=8 if arch == 'aarch64' else 1025: m.relocation(type_replacement=kind))
        case(arch, 'selected', 'copy-relocation', 'COPY_RELOCATION',
             lambda m, kind=1024 if arch == 'aarch64' else 4: m.relocation(type_replacement=kind))
        case(arch, 'selected', 'wrong-init-array-address', 'MISMATCHED_DT_INIT_ARRAY',
             lambda m: m.tag('DT_INIT_ARRAY', m.elf.get_section_by_name('.init_array')['sh_addr'] + 8))
        case(arch, 'selected', 'wrong-init-array-size', 'MISMATCHED_DT_INIT_ARRAY',
             lambda m: m.tag('DT_INIT_ARRAYSZ', 16))
        case(arch, 'selected', 'selected-preinit-tag', 'UNSUPPORTED_DYNAMIC_TAG',
             lambda m: m.tag('DT_INIT_ARRAY', 32, change_type=True))
        case(arch, 'selected', 'wrong-registration-hook', 'UNSUPPORTED_CRT_CALLBACK_TARGET',
             lambda m: m.relocation('_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable'))
        case(arch, 'selected', 'changed-dtor-instruction', 'UNSUPPORTED_CRT_CALLBACK_BODY',
             lambda m: m.code('__do_global_dtors_aux', 0, 1))

    case('aarch64', 'selected', 'changed-init-body', 'UNSUPPORTED_CRT_CALLBACK_BODY',
         lambda m: m.code('_init', 0, 1))
    case('aarch64', 'selected', 'wrong-frame-target', 'UNSUPPORTED_CRT_CALLBACK_BODY',
         lambda m: m.code('frame_dummy', 4 if m.data[m.offset(m.symbol('frame_dummy')['st_value']):
             m.offset(m.symbol('frame_dummy')['st_value']) + 4] == bytes.fromhex('5f2403d5') else 0, 1))
    case('riscv64', 'selected', 'changed-frame-jump', 'UNSUPPORTED_CRT_CALLBACK_BODY',
         lambda m: m.code('frame_dummy', 0, 2, size=2))
    for name, reason, edit in (
        ('preinit-address', 'MISMATCHED_DT_PREINIT_ARRAY',
         lambda m: m.tag('DT_PREINIT_ARRAY', m.elf.get_section_by_name('.preinit_array')['sh_addr'] + 8)),
        ('preinit-size', 'MISMATCHED_DT_PREINIT_ARRAY', lambda m: m.tag('DT_PREINIT_ARRAYSZ', 16)),
        ('preinit-two-entries', 'UNSUPPORTED_CRT_CALLBACK_BODY',
         lambda m: (m.tag('DT_PREINIT_ARRAYSZ', 16), m.section_field('.preinit_array', 32, 16))),
        ('preinit-flags', 'UNSUPPORTED_CRT_CALLBACK_BODY', lambda m: m.section_field('.preinit_array', 8, 2)),
        ('preinit-retargeted', 'UNSUPPORTED_CRT_CALLBACK_TARGET', lambda m: m.pointer('.preinit_array', 'main')),
        ('preinit-wrong-register', 'UNSUPPORTED_CRT_CALLBACK_BODY', lambda m: m.code('load_gp', 0, 0x80)),
        ('preinit-wrong-gp', 'UNSUPPORTED_CRT_CALLBACK_BODY', lambda m: m.code('load_gp', 4, 1 << 20)),
        ('preinit-wrong-return', 'UNSUPPORTED_CRT_CALLBACK_BODY', lambda m: m.code('load_gp', 8, 1, size=2)),
        ('start-misses-gp', 'UNSUPPORTED_CRT_CALLBACK_BODY', lambda m: m.code('_start', 0, 1 << 21)),
        ('gp-symbol-mismatch', 'UNSUPPORTED_CRT_CALLBACK_BODY', lambda m: m.gp_symbol()),
    ):
        case('riscv64', 'executable', name, reason, edit)
    for arch, other in (('aarch64', 'riscv64'), ('riscv64', 'aarch64')):
        executable, library, external = accepted[arch]
        rejected(arch + '/mixed-selected', 'MIXED_ARCHITECTURES',
                 lambda: convert.validate_closure(executable, [accepted[other][1]], external))
        rejected(arch + '/mixed-external', 'MIXED_ARCHITECTURES',
                 lambda: convert.validate_closure(executable, [library], accepted[other][2]))
    summary = {'positive_closures': len(accepted), 'negative_passed': len(results),
               'cases': results, 'source_hashes': sources,
               'converter_sha256': convert.sha(convert.__file__),
               'driver_sha256': convert.sha(__file__), 'scope': 'preflight only; no lifting/linking'}
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print('Startup contract: {} positive closures, {} negative tests passed'.format(len(accepted), len(results)))


if __name__ == '__main__':
    main()
