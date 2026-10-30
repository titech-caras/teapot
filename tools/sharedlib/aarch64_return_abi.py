"""Carry DWARF-proved pointer returns through an ordinary AArch64 link.

This is an opt-in proof producer, not a function-name allowlist. Unsupported
types, split ranges, custom conventions and ambiguous definitions stay unknown.
The component driver carries these records into instrumentation metadata.
See AAPCS64, "Result return": a 64-bit pointer result is returned in x0.
https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#result-return
"""
from collections import defaultdict
import hashlib
import json
import re
from pathlib import Path

import gtirb
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile




def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def checked_elf(elf, executable=False):
    if (elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_AARCH64' or
            elf['e_type'] not in (('ET_EXEC',) if executable else ('ET_EXEC', 'ET_DYN'))):
        raise ValueError('pointer ABI evidence requires Linux ELF64 little-endian AArch64')


def inherited(die, name, seen=frozenset()):
    key = die.cu.cu_offset, die.offset
    if key in seen:
        raise ValueError('cyclic DWARF abstract/specification reference')
    if name in die.attributes:
        return die, die.attributes[name]
    found = []
    for reference in ('DW_AT_abstract_origin', 'DW_AT_specification'):
        if reference in die.attributes:
            value = inherited(die.get_DIE_from_attribute(reference), name, seen | {key})
            if value:
                found.append(value)
    if len(found) > 1:
        raise ValueError('ambiguous inherited DWARF attribute')
    return found[0] if found else None


def pointer_type(die):
    convention = inherited(die, 'DW_AT_calling_convention')
    if convention and convention[1].value != 1:  # DW_CC_normal
        return None
    type_ref = inherited(die, 'DW_AT_type')
    if type_ref is None:
        return None
    current = type_ref[0].get_DIE_from_attribute('DW_AT_type')
    seen, path = set(), []
    while current is not None:
        if current.offset in seen:
            raise ValueError('cyclic DWARF return type')
        seen.add(current.offset)
        path.append([current.offset, current.tag])
        if current.tag == 'DW_TAG_pointer_type':
            size = current.attributes.get('DW_AT_byte_size')
            size = size.value if size is not None else current.cu['address_size']
            address_class = current.attributes.get('DW_AT_address_class')
            return path if size == 8 and address_class is None else None
        if current.tag not in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type',
                                'DW_TAG_restrict_type', 'DW_TAG_atomic_type'):
            return None
        if 'DW_AT_type' not in current.attributes:
            return None
        current = current.get_DIE_from_attribute('DW_AT_type')
    return None


def dwarf_pointer_definitions(elf):
    """Only one contiguous, concrete, normal-convention C/C++ definition."""
    if not elf.has_dwarf_info():
        return []
    # --emit-relocs retains link-time relocation records in an already linked
    # ELF. Applying them a second time corrupts DWARF/CFI addresses (and its
    # absolute .rela.eh_frame offsets can exceed the section buffer).
    dwarf = elf.get_dwarf_info(relocate_dwarf_sections=elf['e_type'] == 'ET_REL')
    result = []
    for cu in dwarf.iter_CUs():
        language = cu.get_top_DIE().attributes.get('DW_AT_language')
        # DW_LANG C89, C, C++, C99, C++03, C++11, C11, C++14, C++17,
        # C++20, C17. Other languages need their own ABI mapping.
        if language is None or language.value not in (1, 2, 4, 12, 25, 26, 29, 33, 42, 43, 44):
            continue
        for die in cu.iter_DIEs():
            if die.tag != 'DW_TAG_subprogram' or 'DW_AT_ranges' in die.attributes:
                continue
            low, high = die.attributes.get('DW_AT_low_pc'), die.attributes.get('DW_AT_high_pc')
            if low is None or high is None or 'DW_AT_declaration' in die.attributes:
                continue
            path = pointer_type(die)
            name = (inherited(die, 'DW_AT_linkage_name') or inherited(die, 'DW_AT_MIPS_linkage_name') or
                    inherited(die, 'DW_AT_name'))
            if not path or name is None:
                continue
            try:
                name = name[1].value.decode('utf-8')
            except (UnicodeError, AttributeError):
                continue
            if not re.fullmatch(r'[A-Za-z_.$][A-Za-z0-9_.$]*', name):
                continue
            form = describe_form_class(high.form)
            end = low.value + high.value if form == 'constant' else high.value if form == 'address' else None
            if end is None or end <= low.value:
                continue
            result.append({'name': name, 'address': low.value, 'size': end - low.value,
                           'cu_offset': cu.cu_offset, 'die_offset': die.offset, 'type_path': path,
                           'return_kind': 'aapcs64-pointer64-x0'})
    return result


def executable_regions(elf):
    # Do not re-read an entire multi-megabyte text section for every block.
    return [(s['sh_addr'], s['sh_addr'] + s['sh_size'], s.data())
            for s in elf.iter_sections() if s['sh_flags'] & 6 == 6]


def source_bytes(regions, address, size):
    matches = [(begin, content) for begin, end, content in regions if begin <= address < address + size <= end]
    if len(matches) != 1:
        raise ValueError('function does not have one executable source extent')
    begin, content = matches[0]
    return content[address - begin:address - begin + size]


def produce(binary, original_ir):
    binary_hash, ir_hash = sha(binary), sha(original_ir)
    ir = gtirb.IR.load_protobuf(original_ir)
    if len(ir.modules) != 1 or ir.modules[0].isa != gtirb.Module.ISA.ARM64:
        raise ValueError('one original AArch64 module required')
    module = ir.modules[0]
    entry_owners = defaultdict(list)
    for function, entries in module.aux_data['functionEntries'].data.items():
        for entry in entries:
            entry_owners[entry].append(function)
    intervals = list(module.byte_intervals)
    rows, rejected = [], []
    with Path(binary).open('rb') as stream:
        elf = ELFFile(stream)
        checked_elf(elf)
        regions = executable_regions(elf)
        table = elf.get_section_by_name('.symtab')
        if table is None:
            raise ValueError('original symbol table required for DWARF binding')
        definitions = defaultdict(list)
        for row in dwarf_pointer_definitions(elf):
            definitions[row['name']].append(row)
        for name, candidates in sorted(definitions.items()):
            if len(candidates) != 1:
                rejected.append([name, 'ambiguous DWARF definitions'])
                continue
            row = candidates[0]
            symbols = [s for s in table.get_symbol_by_name(name) or () if
                       s['st_info']['type'] == 'STT_FUNC' and isinstance(s['st_shndx'], int)]
            matches = list(module.symbols_named(name))
            if (len(symbols) != 1 or len(matches) != 1 or matches[0].at_end or
                    not isinstance(matches[0].referent, gtirb.CodeBlock) or
                    (symbols[0]['st_value'], symbols[0]['st_size']) != (row['address'], row['size']) or
                    matches[0].referent.address != row['address']):
                rejected.append([name, 'original ELF/IR definition does not match DWARF extent'])
                continue
            symbol = matches[0]
            info = module.aux_data['elfSymbolInfo'].data[symbol]
            owners = entry_owners[symbol.referent]
            if len(owners) != 1 or info[:2] != (row['size'], 'FUNC'):
                rejected.append([name, 'ambiguous original function or mismatched size'])
                continue
            original = source_bytes(regions, row['address'], row['size'])
            covering = [bi for bi in intervals if bi.address is not None and
                         bi.address <= row['address'] < row['address'] + row['size'] <= bi.address + len(bi.contents)]
            if len(covering) != 1:
                rejected.append([name, 'original IR does not cover the complete function'])
                continue
            bi = covering[0]
            offset = row['address'] - bi.address
            if bytes(bi.contents[offset:offset + row['size']]) != original:
                rejected.append([name, 'original IR function bytes changed'])
                continue
            value = {**row, 'module_uuid': str(module.uuid), 'function_uuid': str(owners[0]),
                     'symbol_uuid': str(symbol.uuid), 'function_bytes_sha256': hashlib.sha256(original).hexdigest(),
                     'source_elf_sha256': binary_hash, 'source_ir_sha256': ir_hash}
            rows.append({'id': digest(value), **value})
    return {'format': 'teapot-aarch64-pointer-abi-v1', 'records': rows, 'rejected': rejected,
            'source_elf_sha256': binary_hash, 'source_ir_sha256': ir_hash}
