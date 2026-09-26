"""Carry DWARF-proved pointer returns through an ordinary AArch64 link.

This is an opt-in proof producer, not a function-name allowlist. Unsupported
types, split ranges, custom conventions and ambiguous definitions stay unknown.
The target record is non-loaded metadata with ordinary symbol relocations.
See AAPCS64, "Result return": a 64-bit pointer result is returned in x0.
https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#result-return
"""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct

import gtirb
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

from teapot.utils.return_abi import POINTER_RETURNS, SCHEMA, function_fingerprint


SECTION = '.teapot_function_abi'
RECORD = struct.Struct('<8s32sQQQ')
MAGIC = b'TPABI001'


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
    dwarf = elf.get_dwarf_info()
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


def assembly(manifest):
    result = ['.pushsection ' + SECTION + ',"",%progbits', '.balign 8']
    for row in manifest['records']:
        if row['id'] != digest({k: v for k, v in row.items() if k != 'id'}):
            raise ValueError('ABI manifest identity mismatch')
        if not re.fullmatch(r'[A-Za-z_.$][A-Za-z0-9_.$]*', row['name']):
            raise ValueError('unsupported ABI assembly symbol')
        result += ['.ascii "' + MAGIC.decode() + '"',
                   '.byte ' + ','.join(str(b) for b in bytes.fromhex(row['id'])),
                   '.quad ' + row['name'], '.quad .L__teapot_abi_end_' + row['id'], '.quad 1']
    return '\n'.join(result + ['.popsection', ''])


def annotate_assembly(text, manifest):
    """Bind the actual printed .size endpoint, including printer padding.

    Endpoints cannot be inferred by adding the original ELF size: an ordinary
    printer can include alignment NOPs or expand an instruction. This inserts
    only local labels and a non-loaded section into the exact original output.
    """
    if '.L__teapot_abi_end_' in text or SECTION in text:
        raise ValueError('reserved ABI assembly marker collision')
    rows = {r['name']: r for r in manifest['records']}
    if len(rows) != len(manifest['records']):
        raise ValueError('ambiguous ABI assembly names')
    seen = set()
    def replace(match):
        name = match.group(1)
        if name not in rows:
            return match.group(0)
        if match.group(2) != name or name in seen:
            raise ValueError('ambiguous printed ABI function endpoint')
        seen.add(name)
        return '.L__teapot_abi_end_' + rows[name]['id'] + ':\n' + match.group(0)
    annotated = re.sub(r'^\s*\.size\s+([A-Za-z_.$][A-Za-z0-9_.$]*),[ \t]*\.[ \t]*-[ \t]*'
                       r'([A-Za-z_.$][A-Za-z0-9_.$]*)[ \t]*$', replace, text, flags=re.MULTILINE)
    if seen != set(rows):
        raise ValueError('missing printed ABI function endpoints: ' + str(sorted(set(rows) - seen)[:5]))
    recovered = re.sub(r'^\.L__teapot_abi_end_[0-9a-f]{64}:\n', '', annotated, flags=re.MULTILINE)
    if recovered != text:
        raise ValueError('ABI annotation changed ordinary assembly')
    return annotated + '\n' + assembly(manifest)


def bind(binary, manifest, ir):
    binary_hash = sha(binary)
    if len(ir.modules) != 1 or ir.modules[0].isa != gtirb.Module.ISA.ARM64:
        raise ValueError('one linked AArch64 module required')
    module = ir.modules[0]
    if POINTER_RETURNS in module.aux_data:
        raise ValueError('pointer ABI evidence already present')
    wanted = {row['id']: row for row in manifest['records']}
    if len(wanted) != len(manifest['records']) or any(
            key != digest({k: v for k, v in row.items() if k != 'id'}) for key, row in wanted.items()):
        raise ValueError('duplicate or altered ABI records')
    contracts, seen = {}, set()
    blocks_at, entry_owners = defaultdict(list), defaultdict(list)
    for block in module.code_blocks:
        blocks_at[block.address].append(block)
    for function, entries in module.aux_data['functionEntries'].data.items():
        for entry in entries:
            entry_owners[entry].append(function)
    with Path(binary).open('rb') as stream:
        elf = ELFFile(stream)
        checked_elf(elf, executable=True)
        regions = executable_regions(elf)
        section = elf.get_section_by_name(SECTION)
        if section is None or section['sh_type'] != 'SHT_PROGBITS' or section['sh_flags'] or section['sh_size'] % RECORD.size:
            raise ValueError('missing, loaded or malformed ABI metadata')
        begin_file, end_file = section['sh_offset'], section['sh_offset'] + section['sh_size']
        if any(s['p_type'] == 'PT_LOAD' and max(begin_file, s['p_offset']) < min(end_file, s['p_offset'] + s['p_filesz'])
               for s in elf.iter_segments()):
            raise ValueError('ABI evidence overlaps a loaded segment')
        table = elf.get_section_by_name('.symtab')
        for magic, identity, begin, end, mask in RECORD.iter_unpack(section.data()):
            identity = identity.hex()
            if magic != MAGIC or identity not in wanted or identity in seen or mask != 1:
                raise ValueError('unknown/duplicate ABI identity or return kind')
            seen.add(identity)
            row = wanted[identity]
            symbols = [s for s in table.get_symbol_by_name(row['name']) or () if
                       s['st_info']['type'] == 'STT_FUNC' and s['st_value'] == begin and s['st_size'] == end - begin]
            entries = blocks_at[begin]
            owners = list({key for entry in entries for key in entry_owners[entry]})
            if end <= begin or len(symbols) != 1 or len(entries) != 1 or len(owners) != 1:
                raise ValueError('ABI relocation does not identify one printed function extent')
            members = module.aux_data['functionBlocks'].data[owners[0]]
            outside = [b for b in members if b.address is None or
                       not begin <= b.address < b.address + b.size <= end]
            # DDisasm may assign unreachable inter-function alignment to the
            # preceding function. Permit only a contiguous, edgeless NOP tail;
            # it cannot contain an additional return or observed value use.
            cursor = end
            roots = module.aux_data['functionEntries'].data[owners[0]]
            for block in sorted(outside, key=lambda b: b.address if b.address is not None else -1):
                if (block.address != cursor or block.section != entries[0].section or block in roots or
                        block.size <= 0 or block.size % 4 or list(block.incoming_edges) or
                        bytes(block.contents) != bytes.fromhex('1f2003d5') * (block.size // 4)):
                    raise ValueError('ABI function membership crosses the recorded extent')
                cursor += block.size
            for block in members:
                if bytes(block.contents) != source_bytes(regions, block.address, block.size):
                    raise ValueError('linked ABI function bytes disagree with current IR')
            if owners[0] in contracts:
                raise ValueError('multiple ABI records claim one function')
            contracts[owners[0]] = (function_fingerprint(module, owners[0]),
                                   digest({'record': row, 'linked_elf_sha256': binary_hash}))
    if seen != set(wanted):
        raise ValueError('missing linked ABI records')
    module.aux_data[POINTER_RETURNS] = gtirb.AuxData(contracts, SCHEMA)
    return {'bound_pointer_returns': len(contracts), 'linked_elf_sha256': binary_hash,
            'scope': 'only verified pointer64 functions; all unknown/aggregate types stay unannotated'}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    producer = modes.add_parser('produce')
    producer.add_argument('--binary', type=Path, required=True)
    producer.add_argument('--ir', type=Path, required=True)
    producer.add_argument('--manifest', type=Path, required=True)
    producer.add_argument('--assembly', type=Path, required=True)
    annotator = modes.add_parser('annotate')
    annotator.add_argument('--manifest', type=Path, required=True)
    annotator.add_argument('--input-assembly', type=Path, required=True)
    annotator.add_argument('--output-assembly', type=Path, required=True)
    consumer = modes.add_parser('bind')
    consumer.add_argument('--binary', type=Path, required=True)
    consumer.add_argument('--manifest', type=Path, required=True)
    consumer.add_argument('--source-binary', type=Path, required=True)
    consumer.add_argument('--source-ir', type=Path, required=True)
    consumer.add_argument('--input-ir', type=Path, required=True)
    consumer.add_argument('--output-ir', type=Path, required=True)
    consumer.add_argument('--audit', type=Path, required=True)
    args = parser.parse_args()
    if args.mode == 'produce':
        if args.manifest.exists() or args.assembly.exists():
            raise ValueError('ABI producer output already exists')
        result = produce(args.binary, args.ir)
        args.manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        args.assembly.write_text(assembly(result))
        print(json.dumps({'pointer_records': len(result['records']), 'rejected': len(result['rejected'])}))
    elif args.mode == 'annotate':
        if args.output_assembly.exists():
            raise ValueError('ABI annotated assembly output already exists')
        manifest = json.loads(args.manifest.read_text())
        args.output_assembly.write_text(annotate_assembly(args.input_assembly.read_text(), manifest))
        print(json.dumps({'annotated_functions': len(manifest['records']),
                          'original_assembly_sha256': sha(args.input_assembly)}))
    else:
        if args.output_ir.exists() or args.audit.exists():
            raise ValueError('ABI consumer output already exists')
        manifest = json.loads(args.manifest.read_text())
        if (sha(args.source_binary), sha(args.source_ir)) != (
                manifest['source_elf_sha256'], manifest['source_ir_sha256']):
            raise ValueError('ABI source artifacts changed')
        ir = gtirb.IR.load_protobuf(args.input_ir)
        result = bind(args.binary, manifest, ir)
        args.output_ir.parent.mkdir(parents=True, exist_ok=True)
        ir.save_protobuf(args.output_ir)
        args.audit.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))


if __name__ == '__main__':
    main()
