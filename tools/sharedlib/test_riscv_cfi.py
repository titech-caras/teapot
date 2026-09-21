#!/usr/bin/env python3
"""Compare the RV64 ET_REL CFI reader with GNU ld's relocated CFI.

This is a reader regression, not a claim that the fixture's padding is runnable
code or that unwinding a converted application has been demonstrated.
"""
import argparse
import io
import json
from pathlib import Path
import struct
import subprocess

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import convert


FIXTURE = r"""
    .text
    .globl _start
    .type _start, @function
_start:
    .cfi_startproc
    addi sp, sp, -16
    .cfi_def_cfa_offset 16
    sd ra, 8(sp)
    .cfi_offset ra, -8
    .space 96
    .cfi_def_cfa_offset 32
    .space 300
    .cfi_def_cfa_offset 48
    .space 70000
    .cfi_def_cfa_offset 16
    ld ra, 8(sp)
    .cfi_restore ra
    addi sp, sp, 16
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size _start, .-_start
    .globl second
    .type second, @function
second:
    .cfi_startproc
    addi sp, sp, -32
    .cfi_def_cfa_offset 32
    sd s0, 16(sp)
    .cfi_offset s0, -16
    ld s0, 16(sp)
    .cfi_restore s0
    addi sp, sp, 32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size second, .-second
    # GNU as uses advance_loc1 rather than the 6-bit CFI encoding when it
    # creates relaxation relocations. Exercise SET6/SUB6 explicitly as well.
    .section .six_bit,"a",@progbits
.Lset6:
    .byte 0xc0
    .reloc .Lset6, R_RISCV_SET6, second + 2
    .reloc .Lset6, R_RISCV_SUB6, second
.Lsub6:
    .byte 0xcf
    .reloc .Lsub6, R_RISCV_SUB6, second
    .section .note.GNU-stack,"",@progbits
"""


def arithmetic_checks():
    # Independent psABI expectations, including signed addends and wraparound.
    cases = []
    for kind, width in ((1, 32), (2, 64), (53, 6), (54, 8), (55, 16), (56, 32)):
        cases.append((kind, 0, (1 << width) + 5, -2, 0, 3))
    for kind, width in ((33, 8), (34, 16), (35, 32), (36, 64)):
        cases.append((kind, (1 << width) - 2, 4, -1, 0, 1))
    for kind, width in ((37, 8), (38, 16), (39, 32), (40, 64)):
        cases.append((kind, 1, 4, -1, 0, (1 << width) - 2))
    cases.extend(((52, 0xd0, 0x42, -1, 0, 0xcf),
                  (53, 0xff, 0x82, -1, 0, 0xc1),
                  (57, 0xdeadbeef, 0x200, -4, 0x300, 0xfffffefc)))
    assert {case[0] for case in cases} == set(convert.RISCV_CFI_RELOCATIONS)
    for kind, value, symbol, addend, place, expected in cases:
        actual = convert.riscv_cfi_value(kind, value, symbol, addend, place)
        assert actual == expected, (kind, actual, expected)
    return len(cases)


def normalized(entries):
    result = []
    for entry in entries:
        if not isinstance(entry, FDE):
            continue
        start = entry['initial_location']
        rows = []
        for row in entry.get_decoded().table:
            rows.append({str(key): (value - start if key == 'pc' else repr(value))
                         for key, value in row.items()})
        result.append({'range': entry['address_range'], 'rows': rows,
                       'return_register': entry.cie['return_address_register']})
    return result


def negative_checks(source, output):
    data = source.read_bytes()
    elf = ELFFile(io.BytesIO(data))
    eh_index = elf.get_section_index('.eh_frame')
    eh = elf.get_section(eh_index)
    relocation_section = next(section for section in elf.iter_sections()
                              if isinstance(section, RelocationSection)
                              and section['sh_info'] == eh_index)
    relocation = next(relocation_section.iter_relocations())
    symbols = elf.get_section(relocation_section['sh_link'])
    offset = relocation_section['sh_offset']
    kind, symbol = relocation['r_info_type'], relocation['r_info_sym']
    mutations = (
        ('unknown-type', 'UNSUPPORTED_CFI_RELOCATION', [(8, (symbol << 32) | 9999)]),
        ('outside-section', 'INVALID_CFI_RELOCATION', [(0, eh['sh_size'])]),
        ('undefined-symbol', 'UNRESOLVED_CFI_RELOCATION', [(8, kind)]),
        ('bad-symbol-index', 'INVALID_CFI_RELOCATION',
         [(8, (symbols.num_symbols() << 32) | kind)]),
        ('nonzero-sub-addend', 'UNSUPPORTED_CFI_RELOCATION',
         [(8, (symbol << 32) | 39), (16, 1)]),
    )
    results = []
    for name, reason, edits in mutations:
        mutated = bytearray(data)
        for field, value in edits:
            struct.pack_into('<Q', mutated, offset + field, value)
        path = output / (name + '.o')
        path.write_bytes(mutated)
        with path.open('rb') as stream:
            try:
                convert.eh_cfi_entries(ELFFile(stream), path)
            except convert.Unsupported as error:
                assert str(error).startswith(reason + ':'), (name, str(error))
                results.append({'name': name, 'error': str(error)})
            else:
                raise AssertionError('invalid CFI relocation accepted: ' + name)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--as', dest='assembler', required=True)
    parser.add_argument('--ld', dest='linker', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--existing-object', type=Path)
    parser.add_argument('--existing-fdes', type=int)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    result = {'arithmetic_cases': arithmetic_checks(), 'commands': []}
    source, obj = args.out / 'fixture.S', args.out / 'fixture.o'
    source.write_text(FIXTURE)

    def run(command):
        command = [str(arg) for arg in command]
        completed = subprocess.run(command, capture_output=True, text=True)
        result['commands'].append({'argv': command, 'status': completed.returncode,
                                   'stdout': completed.stdout, 'stderr': completed.stderr})
        (args.out / 'commands.json').write_text(json.dumps(result['commands'], indent=2) + '\n')
        completed.check_returncode()

    run([args.assembler, '--version'])
    run([args.linker, '--version'])
    run([args.assembler, '-march=rv64gc', '-mabi=lp64d', '-o', obj, source])
    before = convert.sha(obj)
    with obj.open('rb') as stream:
        elf = ELFFile(stream)
        actual = normalized(convert.eh_cfi_entries(elf, obj))
        assert len(actual) == 2, actual
        eh_index = elf.get_section_index('.eh_frame')
        kinds = sorted({rel['r_info_type'] for section in elf.iter_sections()
                        if isinstance(section, RelocationSection) and section['sh_info'] == eh_index
                        for rel in section.iter_relocations()})
    # The fixture must really exercise every advance-width family, plus the
    # FDE start and range relocations, rather than only count unrelocated FDEs.
    assert {35, 39, 54, 55, 56, 57, 37, 38}.issubset(kinds), kinds
    result['fixture_relocations'] = kinds
    result['decoded_fixture'] = actual
    result['linked_layouts'] = []
    for address in (0x410000, 0x630000):
        linked = args.out / ('linked-' + hex(address))
        run([args.linker, '--no-relax', '-Ttext=' + hex(address), '-o', linked, obj])
        with linked.open('rb') as stream:
            elf = ELFFile(stream)
            expected = normalized(elf.get_dwarf_info().EH_CFI_entries())
            second = elf.get_section_by_name('.symtab').get_symbol_by_name('second')[0]['st_value']
            set6 = convert.riscv_cfi_value(53, 0xc0, second, 2, 0)
            set6 = convert.riscv_cfi_value(52, set6, second, 0, 0)
            sub6 = convert.riscv_cfi_value(52, 0xcf, second, 0, 0)
            assert elf.get_section_by_name('.six_bit').data() == bytes((set6, sub6)) == b'\xc2\xc9'
        assert actual == expected, (actual, expected)
        result['linked_layouts'].append({'text': address, 'path': str(linked),
                                         'sha256': convert.sha(linked)})
    assert convert.sha(obj) == before, 'reader changed the object'
    result['negative_cases'] = negative_checks(obj, args.out)
    result['object_sha256'] = before
    if args.existing_object:
        original_hash = convert.sha(args.existing_object)
        with args.existing_object.open('rb') as stream:
            entries = normalized(convert.eh_cfi_entries(ELFFile(stream), args.existing_object))
        if args.existing_fdes is not None:
            assert len(entries) == args.existing_fdes, len(entries)
        assert convert.sha(args.existing_object) == original_hash
        result['existing_object'] = {'path': str(args.existing_object), 'sha256': original_hash,
                                     'fdes': len(entries), 'decoded': entries}
    result['passed'] = True
    (args.out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print('RV64 CFI: {} arithmetic cases, 2 linked-layout comparisons, {} rejections; existing FDEs {}'.format(
        result['arithmetic_cases'], len(result['negative_cases']),
        result.get('existing_object', {}).get('fdes', 'not requested')), flush=True)


if __name__ == '__main__':
    main()
