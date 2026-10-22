#!/usr/bin/env python3
"""Fail-closed ELF64 selected-DSO to ET_REL/ET_EXEC research prototype.

Run in an isolated container exposing only this script, the ELF inputs, the
pinned toolchain, the explicitly selected external ELF dependencies and output.
No source/original object/archive is accepted. Assembly is never text-filtered.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time

import gtirb
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.dwarf.callframe import FDE


CONTRACT = 'teapot-selected-elf64-v3'
AMBIGUOUS_POINTER_WARNING = (
    'WARNING: Allowing ambiguous data pointers without relocation evidence. '
    'These words may be integer data; relayout can corrupt them.')
AMBIGUOUS_POINTER_FOOTER = (
    'Use a PIE input, or link with --emit-relocs and retain its static relocation '
    'tables. --allow-ambiguous-data-pointers explicitly keeps the legacy guesses '
    'at the risk of changing program data.')
FRONTEND_DIAGNOSTIC_FILES = ('frontend-diagnostics.json', 'lift.gtirb',
                             'lift/command.json', 'lift/stderr')
LOOKUP = {'dlopen', 'dlmopen', 'dlsym', 'dlvsym', 'dlclose', 'dlinfo',
          'dl_iterate_phdr', '__libc_dlopen_mode'}
# Public entry points and glibc's internal/fortified aliases all bypass an
# ordinary return. Keep one family for both rejection and the explicit opt-in.
NONLOCAL_JUMPS = {'longjmp', '_longjmp', 'siglongjmp', '__longjmp', '__siglongjmp',
                 '__longjmp_chk', '__libc_longjmp', '__libc_siglongjmp',
                 'setcontext', '__setcontext', 'swapcontext', '__swapcontext'}
UNWIND_UNSUPPORTED = {'__cxa_throw', '__cxa_rethrow', '__cxa_atexit',
                      '_Unwind_Resume'} | NONLOCAL_JUMPS
CRT_WEAK = {'__gmon_start__', '_ITM_registerTMCloneTable',
            '_ITM_deregisterTMCloneTable', '__cxa_finalize'}
RELOCS_X64 = {1, 6, 7, 8}  # 64, GLOB_DAT, JUMP_SLOT, RELATIVE; COPY is resolved separately.
ARCHITECTURES = {
    'EM_X86_64': {'name': 'x64', 'relocations': RELOCS_X64, 'copy': 5,
                 'relative': 8, 'got': 6, 'plt': 7, 'emulation': 'elf_x86_64',
                 'interpreter': '/lib64/ld-linux-x86-64.so.2'},
    'EM_AARCH64': {'name': 'aarch64', 'relocations': {257, 1025, 1026, 1027},
                   'copy': 1024, 'relative': 1027, 'got': 1025, 'plt': 1026,
                   'emulation': 'aarch64linux', 'interpreter': '/lib/ld-linux-aarch64.so.1'},
    'EM_RISCV': {'name': 'riscv64', 'relocations': {2, 3, 5}, 'copy': 4,
                 'relative': 3, 'got': 2, 'plt': 5, 'emulation': 'elf64lriscv',
                 'interpreter': '/lib/ld-linux-riscv64-lp64d.so.1'},
}

# Known x64 glibc/GCC CRT bodies. Only RIP-relative operands and cross-function
# branch displacements vary; their actual targets are checked separately. This
# is deliberately a narrow startup contract, not a function-name heuristic.
CRT_PATTERNS = {
    # Its unconditional tail jump ends the callback. The following function's
    # alignment padding varies with compiler/linker flags and is unreachable
    # from this entry; the jump destination is still validated below.
    'frame_dummy': 'f3 0f 1e fa e9 ?? ?? ?? ??',
    'register_tm_clones': '48 8d 3d ?? ?? ?? ?? 48 8d 35 ?? ?? ?? ?? 48 29 fe 48 89 f0 48 c1 ee 3f 48 c1 f8 03 48 01 c6 48 d1 fe 74 14 48 8b 05 ?? ?? ?? ?? 48 85 c0 74 08 ff e0 66 0f 1f 44 00 00 c3 0f 1f 80 00 00 00 00',
    'deregister_tm_clones': '48 8d 3d ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 48 39 f8 74 15 48 8b 05 ?? ?? ?? ?? 48 85 c0 74 09 ff e0 0f 1f 80 00 00 00 00 c3 0f 1f 80 00 00 00 00',
    '__do_global_dtors_aux': 'f3 0f 1e fa 80 3d ?? ?? ?? ?? 00 75 2b 55 48 83 3d ?? ?? ?? ?? 00 48 89 e5 74 0c 48 8b 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 01 5d c3 0f 1f 00 c3 0f 1f 80 00 00 00 00',
}


class Unsupported(RuntimeError):
    pass


def reject(code, path, detail):
    raise Unsupported('{}: {}: {}'.format(code, path, detail))


@contextmanager
def pure_refusal(path):
    """Keep explicitly invoked pure-policy failures in the structured refusal path."""
    try:
        yield
    except ValueError as error:
        reject('PURE_PROFILE_REFUSAL', path, str(error))


def pure_cache_identity():
    from teapot.riscv_profile import PURE, PURE_ABI
    return dict(riscv_profile=PURE, riscv_abi=dict(PURE_ABI), riscv_codegen_policy='integer-objdump-v1')


def check_pure_final(path, compiler):
    from teapot.riscv_profile import objdump_for
    from teapot.riscv_pure_link import check_pure_code
    with pure_refusal(path):
        return check_pure_code(path, objdump_for(compiler))


def sha(path):
    with Path(path).open('rb') as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


GTIRB_HEADER_SIZE = 8  # "GTIRB", two reserved bytes and the protobuf version (GTIRB's file format)


def save_protobuf_ordered(ir, path):
    """ir.save_protobuf, with each module's symbols in name order.

    gtirb writes a module's symbols in the order of a set hashed by identity,
    which changes from process to process, and the printer prints one block's
    labels in file order. This script runs alone, so it cannot use Teapot's
    teapot.utils.serialization.save_protobuf_ordered; it reorders the written
    file with public gtirb only. Nothing but the order changes.
    """
    from gtirb.proto import IR_pb2

    ir.save_protobuf(path)
    data = Path(path).read_bytes()
    message = IR_pb2.IR()
    message.ParseFromString(data[GTIRB_HEADER_SIZE:])
    for module in message.modules:
        module.symbols.sort(key=lambda symbol: (
            symbol.name, symbol.at_end, symbol.WhichOneof('optional_payload') or '',
            symbol.value, symbol.referent_uuid, symbol.uuid))
    Path(path).write_bytes(data[:GTIRB_HEADER_SIZE] + message.SerializeToString())


def content_key(recipe):
    return hashlib.sha256(json.dumps(recipe, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def native_tool_identity(command):
    path = Path(shutil.which(command) or command).resolve()
    result = {'path': str(path), 'sha256': sha(path), 'libraries': {}}
    process = subprocess.run(['ldd', str(path)], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
    for match in re.finditer(r'(/[^\s()]+)', process.stdout):
        library = Path(match.group(1))
        if library.is_file():
            result['libraries'][str(library.resolve())] = sha(library)
    return result


def python_identity():
    import elftools
    import google.protobuf
    packages = {}
    for module in (gtirb, elftools, google.protobuf):
        directory = Path(module.__file__).resolve().parent
        packages[module.__name__] = content_key({
            str(p.relative_to(directory)): sha(p) for p in sorted(directory.rglob('*'))
            if p.is_file() and p.suffix in ('.py', '.so')})
    return {'version': sys.version, 'executable_sha256': sha(sys.executable), 'packages': packages}


class ArtifactCache:
    """Content-addressed *ordinary* recovered-IR/object cache; never Teapot output.

    Manifests are local trusted metadata, not signatures against a malicious
    writer. Accidental corruption, path escapes and symlinks fail closed. Entries
    are installed atomically, never updated in place, and copies (not hardlinks)
    are returned to preserve the cache against later output edits.
    """
    def __init__(self, root):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def restore(self, stage, recipe, destination):
        key = content_key(recipe)
        entry = self.root / stage / key
        if not entry.exists():
            return False
        try:
            if entry.is_symlink():
                raise ValueError('entry is a symlink')
            manifest = json.loads((entry / 'manifest.json').read_text())
            if manifest['recipe'] != recipe or manifest['key'] != key:
                raise ValueError('recipe/key mismatch')
            artifacts = entry / 'artifacts'
            actual = {}
            for path in artifacts.rglob('*'):
                if path.is_symlink():
                    raise ValueError('artifact is a symlink')
                if path.is_file():
                    actual[str(path.relative_to(artifacts))] = sha(path)
            if actual != manifest['files']:
                raise ValueError('artifact hash/file set mismatch')
            for name in actual:
                if Path(name).is_absolute() or '..' in Path(name).parts:
                    raise ValueError('unsafe relative artifact name')
            for name in actual:
                source, target = artifacts / name, destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        except (ValueError, KeyError, OSError) as error:
            reject('CACHE_INTEGRITY', entry, str(error))
        return True

    def store(self, stage, recipe, directory, names):
        key = content_key(recipe)
        parent = self.root / stage
        parent.mkdir(parents=True, exist_ok=True)
        entry = parent / key
        if entry.exists():
            # This run cannot overwrite an existing entry, even after failure.
            return
        staging = Path(tempfile.mkdtemp(prefix='pending-', dir=parent))
        artifacts = staging / 'artifacts'
        artifacts.mkdir()
        for name in names:
            source, destination = directory / name, artifacts / name
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        files = {str(p.relative_to(artifacts)): sha(p) for p in artifacts.rglob('*') if p.is_file()}
        dump(staging / 'manifest.json', {'key': key, 'recipe': recipe, 'files': files})
        try:
            staging.rename(entry)
        except OSError:
            # Another writer may have committed the same content key. Leave
            # this generated staging entry for inspection rather than deleting
            # anything based on an unexpected filesystem state.
            if not entry.exists():
                raise


def run(out, name, command):
    log = out / name
    log.mkdir()
    dump(log / 'command.json', [str(x) for x in command])
    started = time.time()
    with (log / 'stdout').open('wb') as stdout, (log / 'stderr').open('wb') as stderr:
        result = subprocess.run([str(x) for x in command], stdout=stdout,
                                stderr=stderr)
    dump(log / 'result.json', {'exit': result.returncode,
                              'seconds': time.time() - started})
    if result.returncode:
        raise RuntimeError('{} failed with exit {}; see {}'.format(
            name, result.returncode, log))
    return (log / 'stdout').read_text(errors='replace')


def sym_record(symbol):
    return {'name': symbol.name, 'type': symbol['st_info']['type'],
            'binding': symbol['st_info']['bind'],
            'visibility': symbol['st_other']['visibility'],
            'section': symbol['st_shndx'], 'address': symbol['st_value'],
            'size': symbol['st_size']}


def dynamic_symbol_records(elf):
    """Retain version-qualified identities instead of flattening ELF names."""
    definitions, requirements, by_index = [], [], {}
    section = elf.get_section_by_name('.gnu.version_d')
    if section is not None:
        for version, auxiliaries in section.iter_versions():
            names = [aux.name for aux in auxiliaries]
            if not names:
                raise ValueError('empty ELF version definition')
            row = {'name': names[0], 'parents': names[1:],
                   'flags': version['vd_flags'], 'index': version['vd_ndx']}
            definitions.append(row)
            by_index[row['index']] = {'version': row['name'], 'version_library': None}
    section = elf.get_section_by_name('.gnu.version_r')
    if section is not None:
        for version, auxiliaries in section.iter_versions():
            names = []
            for aux in auxiliaries:
                names.append(aux.name)
                by_index[aux['vna_other'] & 0x7fff] = {
                    'version': aux.name, 'version_library': version.name}
            requirements.append({'library': version.name, 'versions': names})
    table = elf.get_section_by_name('.dynsym')
    versions = elf.get_section_by_name('.gnu.version')
    symbols = []
    for index, symbol in enumerate(table.iter_symbols()):
        if not symbol.name:
            continue
        row = sym_record(symbol)
        if versions is not None:
            ndx = versions.get_symbol(index)['ndx']
            if isinstance(ndx, int) and ndx & 0x7fff > 1:
                version = by_index.get(ndx & 0x7fff)
                if version is None:
                    raise ValueError('unresolved ELF version index {}'.format(ndx))
                row.update(version)
                row['version_default'] = (symbol['st_shndx'] != 'SHN_UNDEF' and not ndx & 0x8000)
        symbols.append(row)
    return symbols, definitions, requirements


def version_node_symbol(item, symbol):
    return (symbol['section'] == 'SHN_ABS' and any(
        symbol['name'] == version['name'] for version in item.get('version_definitions', ())))


def copy_relocation_symbol(elf, section, relocation, symbols, path, role):
    """A loader COPY is an executable data import, not a selected definition."""
    table = elf.get_section(section['sh_link'])
    if role != 'executable' or table['sh_type'] != 'SHT_DYNSYM' or relocation.entry.get('r_addend', 0):
        reject('COPY_RELOCATION', path, 'unsupported COPY source/table/addend')
    raw = sym_record(table.get_symbol(relocation['r_info_sym']))
    matches = [symbol for symbol in symbols if all(symbol[key] == value for key, value in raw.items())]
    # LLD may retain both the versioned and unversioned spelling in dynsym.
    # Only identical complete identities describe one COPY destination.
    if len(matches) > 1 and all(symbol == matches[0] for symbol in matches):
        matches = matches[:1]
    if (len(matches) != 1 or raw['type'] != 'STT_OBJECT' or raw['binding'] != 'STB_GLOBAL'
            or raw['visibility'] != 'STV_DEFAULT' or not isinstance(raw['section'], int)
            or raw['address'] != relocation['r_offset'] or raw['size'] <= 0):
        reject('COPY_RELOCATION', path, 'COPY must name its defined, sized data destination')
    target = elf.get_section(raw['section'])
    if (target['sh_flags'] & 3 != 3 or raw['address'] < target['sh_addr']
            or raw['address'] + raw['size'] > target['sh_addr'] + target['sh_size']):
        reject('COPY_RELOCATION', path, 'COPY destination is not writable allocated data')
    return matches[0]


def validate_copy_forwarding(module, item):
    """Keep DDisasm's external references; a plain copied BSS label is not an import."""
    forwarding = module.aux_data.get('symbolForwarding')
    info = module.aux_data.get('elfSymbolInfo')
    for copy in item.get('copy_relocations', ()):
        symbol = copy['symbol']
        matches = [source for source, target in (forwarding.data.items() if forwarding else ())
                   if isinstance(source.referent, gtirb.DataBlock)
                   and source.referent.address == copy['address'] and not source.at_end
                   and isinstance(target.referent, gtirb.ProxyBlock)
                   and target.name.split('@')[0] == symbol['name']
                   and info and info.data.get(source, ())[:4] ==
                   (symbol['size'], 'OBJECT', 'GLOBAL', 'DEFAULT')]
        if len(matches) != 1:
            reject('COPY_RELOCATION', item['path'], 'missing external COPY forwarding: ' + symbol['name'])


def validate_linked_copies(elf, executable):
    """The final loader must still initialize every admitted COPY destination."""
    copies = executable.get('copy_relocations', ())
    if not copies:
        return
    symbols, _, _ = dynamic_symbol_records(elf)
    actual = []
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        if not section['sh_flags'] & 2 and elf.get_section(section['sh_link'])['sh_type'] == 'SHT_SYMTAB':
            continue
        for relocation in section.iter_relocations():
            if relocation['r_info_type'] == ARCHITECTURES[elf['e_machine']]['copy']:
                actual.append(copy_relocation_symbol(elf, section, relocation, symbols,
                                                     executable['path'], 'executable'))
    needed = {tag.needed for tag in elf.get_section_by_name('.dynamic').iter_tags()
              if tag.entry.d_tag == 'DT_NEEDED'}
    for copy in copies:
        symbol = copy['symbol']
        matches = [candidate for candidate in actual if all(candidate.get(key) == symbol.get(key)
                   for key in ('name', 'version', 'size'))]
        if len(matches) != 1 or copy['provider'] not in needed:
            reject('COPY_RELOCATION', executable['path'], 'final loader COPY lost: ' + symbol['name'])


def selected_version_name(soname, name, version):
    """Stable static-link identity; independent of the referring executable."""
    return '__teapot_selected_version_' + content_key([soname, name, version])


def reconstructed_symbol_name(symbol, item=None):
    if (item and item.get('resolve_selected_versions') and item['role'] == 'selected'
            and symbol.get('version') and symbol.get('version_library') is None):
        return selected_version_name(item['soname'], symbol['name'], symbol['version'])
    if not symbol.get('version'):
        return symbol['name']
    return symbol['name'] + ('@@' if symbol.get('version_default') else '@') + symbol['version']


def resolve_selected_symbol_versions(module, item, selected_sonames):
    """Resolve selected versions to explicit ET_REL identities, not DSOs.

    Keep external (e.g. libc) version requirements unchanged. Each selected
    name/version pair gets a stable linker name at both definitions and uses.
    A default definition also retains its public, unversioned alias. This
    avoids relying on a DSO version script or on the printer's arbitrary choice
    of which same-name version keeps the undecorated assembly label.
    """
    aux = module.aux_data.get('elfSymbolVersions')
    if aux is None:
        if item.get('version_definitions') or item.get('versions'):
            reject('MISSING_VERSION_METADATA', item['path'], 'frontend omitted ELF symbol versions')
        return []
    definitions, needed, entries = aux.data
    selected_needs = {index: (library, name)
                      for library, versions in needed.items() if library in selected_sonames
                      for index, name in versions.items()}
    info = module.aux_data['elfSymbolInfo'].data
    tab_indexes = module.aux_data.get('elfSymbolTabIdxInfo')
    nodes = {name for names, _ in definitions.values() for name in names}
    if any(s.name.startswith('__teapot_selected_version_') for s in module.symbols):
        reject('RESERVED_VERSION_SYMBOL', item['path'], 'input uses the reconstruction namespace')
    changes = []
    defaults = []
    for symbol, (index, hidden) in list(entries.items()):
        if symbol.name in nodes and info.get(symbol, (0, '', '', '', 0))[-1] == 0xfff1:
            continue  # Absolute version-node metadata, not a callable export.
        is_definition = item['role'] == 'selected' and index in definitions
        if is_definition:
            library, version = item['soname'], definitions[index][0][0]
        elif index in selected_needs:
            library, version = selected_needs[index]
        else:
            continue
        original = symbol.name
        alias = selected_version_name(library, original, version)
        changes.append({'name': original, 'version': version, 'library': library,
                        'linker_name': alias, 'definition': is_definition})
        if is_definition and not hidden:
            defaults.append((original, symbol))
        symbol.name = alias
        del entries[symbol]
    for name, symbol in defaults:
        existing = list(module.symbols_named(name))
        if existing:
            if any(s.referent != symbol.referent or s.value != symbol.value for s in existing):
                reject('AMBIGUOUS_DEFAULT_VERSION', item['path'], name)
            continue
        payload = symbol.referent if symbol.referent is not None else symbol.value
        public = gtirb.Symbol(name=name, payload=payload, at_end=symbol.at_end, module=module)
        info[public] = info[symbol]
        if tab_indexes is not None:
            tab_indexes.data[public] = []
    return changes


def validate_crt_callbacks(elf, static, relocations, dynsym, path):
    symbols = {s['name']: s['address'] for s in static if isinstance(s['section'], int)}
    def read(address, size):
        for section in elf.iter_sections():
            if section['sh_flags'] & 2 and section['sh_addr'] <= address and address + size <= section['sh_addr'] + section['sh_size']:
                offset = address - section['sh_addr']
                return section.data()[offset:offset + size]
        reject('UNSUPPORTED_CRT_CALLBACK', path, 'unmapped startup target ' + hex(address))
    def target(address, offset, end):
        return address + end + struct.unpack('<i', read(address + offset, 4))[0]
    def named(address, name):
        if symbols.get(name) != address:
            reject('UNSUPPORTED_CRT_CALLBACK_TARGET', path, '{} must target {}'.format(hex(address), name))
    def got(address, name):
        relocation = relocations.get(address)
        if not relocation or relocation['r_info_type'] != 6 or dynsym.get_symbol(relocation['r_info_sym']).name != name:
            reject('UNSUPPORTED_CRT_CALLBACK_TARGET', path, 'GOT slot {} must target {}'.format(hex(address), name))
    for name, pattern in CRT_PATTERNS.items():
        if name not in symbols:
            reject('UNSUPPORTED_CRT_CALLBACK', path, 'missing helper ' + name)
        tokens = pattern.split()
        expression = b''.join(b'.' if token == '??' else re.escape(bytes.fromhex(token)) for token in tokens)
        if not re.fullmatch(expression, read(symbols[name], len(tokens)), re.DOTALL):
            reject('UNSUPPORTED_CRT_CALLBACK_BODY', path, name)
    address = symbols['frame_dummy']
    named(target(address, 5, 9), 'register_tm_clones')
    for name, offset, hook in (('register_tm_clones', 39, '_ITM_registerTMCloneTable'),
                               ('deregister_tm_clones', 22, '_ITM_deregisterTMCloneTable')):
        address = symbols[name]
        named(target(address, 3, 7), '__TMC_END__')
        named(target(address, 10, 14), '__TMC_END__')
        got(target(address, offset, offset + 4), hook)
    address = symbols['__do_global_dtors_aux']
    named(target(address, 6, 11), 'completed.0')
    named(target(address, 46, 51), 'completed.0')
    got(target(address, 17, 22), '__cxa_finalize')
    named(target(address, 30, 34), '__dso_handle')
    named(target(address, 40, 44), 'deregister_tm_clones')
    plt = target(address, 35, 39)
    if read(plt, 4) == bytes.fromhex('f30f1efa'):
        plt += 4  # One exact CET landing; the canonical jump/GOT proof stays below.
    if read(plt, 2) != b'\xff\x25':
        reject('UNSUPPORTED_CRT_CALLBACK_TARGET', path, 'unrecognized cxa_finalize PLT')
    got(target(plt, 2, 6), '__cxa_finalize')


def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


# Fixed-width RISC-V relocations used in assembler-generated .eh_frame.
# psABI: https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_relocations
# tuple: storage bytes, affected bits, operation. SET6/SUB6 must preserve the
# DW_CFA opcode in the top two bits. Unknown/variable-length forms fail closed.
RISCV_CFI_RELOCATIONS = {
    1: (4, 32, 'set'), 2: (8, 64, 'set'),
    33: (1, 8, 'add'), 34: (2, 16, 'add'), 35: (4, 32, 'add'), 36: (8, 64, 'add'),
    37: (1, 8, 'sub'), 38: (2, 16, 'sub'), 39: (4, 32, 'sub'), 40: (8, 64, 'sub'),
    52: (1, 6, 'sub'), 53: (1, 6, 'set'),
    54: (1, 8, 'set'), 55: (2, 16, 'set'), 56: (4, 32, 'set'), 57: (4, 32, 'pcrel'),
}


def riscv_cfi_value(kind, value, symbol, addend, place):
    """Apply one supported psABI relocation, preserving unaffected field bits."""
    _, bits, operation = RISCV_CFI_RELOCATIONS[kind]
    mask = (1 << bits) - 1
    operand = symbol + addend
    if operation == 'add':
        relocated = (value & mask) + operand
    elif operation == 'sub':
        relocated = (value & mask) - operand
    elif operation == 'pcrel':
        relocated = operand - place
    else:
        relocated = operand
    return (value & ~mask) | (relocated & mask)


def eh_cfi_entries(elf, path):
    """Read CFI without skipping the RV64 ET_REL relocation/validation step.

    pyelftools 0.32 has no RISC-V relocation recipes. Apply the limited CFI
    recipes to a private in-memory section copy before invoking its decoder.
    Original ET_REL bytes/relocations are untouched and still go to the linker.
    ET_REL code addresses remain section-relative, as in other architectures;
    this is not a final executable load-address or unwind-execution proof.
    """
    if elf['e_machine'] != 'EM_RISCV' or elf['e_type'] != 'ET_REL':
        return elf.get_dwarf_info().EH_CFI_entries()
    eh_index = elf.get_section_index('.eh_frame')
    if eh_index is None:
        return []
    eh = elf.get_section(eh_index)
    data = bytearray(eh.data())
    for relocations in elf.iter_sections():
        if not isinstance(relocations, RelocationSection) or relocations['sh_info'] != eh_index:
            continue
        symbols = elf.get_section(relocations['sh_link'])
        for relocation in relocations.iter_relocations():
            kind, offset = relocation['r_info_type'], relocation['r_offset']
            if not relocation.is_RELA() or kind not in RISCV_CFI_RELOCATIONS:
                reject('UNSUPPORTED_CFI_RELOCATION', path, str(kind))
            # GNU ld 2.42 subtracts S before adding A for SUB relocations,
            # unlike the psABI's V-S-A. Assembler-produced CFI uses A=0 here.
            # Do not validate a different unwind table from what that linker
            # will emit for a hand-crafted/nonstandard nonzero SUB addend.
            if RISCV_CFI_RELOCATIONS[kind][2] == 'sub' and relocation['r_addend'] != 0:
                reject('UNSUPPORTED_CFI_RELOCATION', path, 'nonzero SUB addend')
            width, _, _ = RISCV_CFI_RELOCATIONS[kind]
            if offset < 0 or offset + width > len(data):
                reject('INVALID_CFI_RELOCATION', path, 'field outside .eh_frame')
            if relocation['r_info_sym'] >= symbols.num_symbols():
                reject('INVALID_CFI_RELOCATION', path, 'symbol index outside table')
            symbol = symbols.get_symbol(relocation['r_info_sym'])
            section_index = symbol['st_shndx']
            if isinstance(section_index, int) and 0 < section_index < elf.num_sections():
                target = elf.get_section(section_index)
                if symbol['st_value'] > target['sh_size']:
                    reject('INVALID_CFI_RELOCATION', path, 'symbol outside its section')
                address = target['sh_addr'] + symbol['st_value']
            elif section_index == 'SHN_ABS':
                address = symbol['st_value']
            else:
                reject('UNRESOLVED_CFI_RELOCATION', path, symbol.name)
            value = int.from_bytes(data[offset:offset + width], 'little')
            relocated = riscv_cfi_value(kind, value, address, relocation['r_addend'],
                                       eh['sh_addr'] + offset)
            data[offset:offset + width] = relocated.to_bytes(width, 'little')
    dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False)
    dwarf.eh_frame_sec = dwarf.eh_frame_sec._replace(stream=io.BytesIO(data))
    return dwarf.EH_CFI_entries()


class StartupImage:
    """Validate fixed GCC/glibc CRT instruction forms and their actual targets.

    Only address immediates vary in accepted forms. This is not general code
    interpretation: an unfamiliar instruction, register, branch, hook, ABI or
    callback shape is rejected. Selected callback bodies/state are retained.
    """
    def __init__(self, elf, static, relocations, dynsym, path):
        self.elf, self.relocations, self.dynsym, self.path = elf, relocations, dynsym, path
        self.symbols = {s['name']: s['address'] for s in static if isinstance(s['section'], int)}
        self.arch = ARCHITECTURES[elf['e_machine']]

    def check(self, condition, detail):
        if not condition:
            reject('UNSUPPORTED_CRT_CALLBACK_BODY', self.path, detail)

    def address(self, name):
        self.check(name in self.symbols, 'missing helper ' + name)
        return self.symbols[name]

    def read(self, address, size):
        for section in self.elf.iter_sections():
            if section['sh_flags'] & 6 == 6 and section['sh_addr'] <= address and \
                    address + size <= section['sh_addr'] + section['sh_size']:
                offset = address - section['sh_addr']
                return int.from_bytes(section.data()[offset:offset + size], 'little')
        reject('UNSUPPORTED_CRT_CALLBACK_BODY', self.path, 'unmapped code at ' + hex(address))

    def word(self, address, expected=None, mask=0xffffffff, size=4):
        word = self.read(address, size)
        if expected is not None:
            self.check(word & mask == expected,
                       '{}: unexpected CRT instruction {}'.format(hex(address), hex(word)))
        return word

    def named(self, address, name):
        if self.symbols.get(name) != address:
            reject('UNSUPPORTED_CRT_CALLBACK_TARGET', self.path,
                   '{} must name {}'.format(hex(address), name))

    def got(self, address, name, kind=None):
        relocation = self.relocations.get(address)
        if not relocation or relocation['r_info_type'] != (kind or self.arch['got']) or \
                self.dynsym.get_symbol(relocation['r_info_sym']).name != name or \
                relocation.get('r_addend', 0) != 0:
            reject('UNSUPPORTED_CRT_CALLBACK_TARGET', self.path,
                   '{} must be the unadjusted {} relocation'.format(hex(address), name))

    def arm_page(self, pc, register):
        word = self.word(pc, 0x90000000 | register, 0x9f00001f)
        immediate = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2)
        return (pc & ~4095) + signed(immediate, 21) * 4096

    def arm_pair(self, pc, register, load=False):
        page = self.arm_page(pc, register)
        opcode = 0xf9400000 if load else 0x91000000
        word = self.word(pc + 4, opcode | (register << 5) | register, 0xffc003ff)
        return page + ((word >> 10) & 4095) * (8 if load else 1)

    def arm_branch(self, pc, target=None, link=False):
        word = self.word(pc, 0x94000000 if link else 0x14000000, 0xfc000000)
        actual = pc + 4 * signed(word & 0x3ffffff, 26)
        if target is not None:
            self.check(actual == target, 'CRT branch target at ' + hex(pc))
        return actual

    def arm_plt(self, address, name):
        page = self.arm_page(address, 16)
        load = self.word(address + 4, 0xf9400211, 0xffc003ff)
        add = self.word(address + 8, 0x91000210, 0xffc003ff)
        self.word(address + 12, 0xd61f0220)
        slot = page + ((load >> 10) & 4095) * 8
        self.check(slot == page + ((add >> 10) & 4095), 'inconsistent PLT slot')
        self.got(slot, name, self.arch['plt'])

    def arm_init_fini(self, init, fini):
        for section, is_init in ((init, True), (fini, False)):
            if section is None or section['sh_size'] == 0:
                continue
            address, size = section['sh_addr'], section['sh_size']
            first = self.read(address, 4)
            pac = first == 0xd503233f
            nop = first == 0xd503201f  # One ordinary CRT hint, not a prefix-skipping loop.
            expected_size = (5 if is_init else 4) * 4 + (8 if pac else 4 if nop else 0)
            self.check(size == expected_size, 'unrecognized ' + section.name + ' size')
            pc = address + (4 if pac or nop else 0)
            self.word(pc, 0xa9bf7bfd)
            self.word(pc + 4, 0x910003fd)
            if is_init:
                helper = self.address('call_weak_fn')
                self.arm_branch(pc + 8, helper, link=True)
                self.got(self.arm_pair(helper, 0, load=True), '__gmon_start__')
                self.word(helper + 8, 0xb4000040)
                self.arm_plt(self.arm_branch(helper + 12), '__gmon_start__')
                self.word(helper + 16, 0xd65f03c0)
                pc += 4
            self.word(pc + 8, 0xa8c17bfd)
            if pac:
                self.word(pc + 12, 0xd50323bf)
                pc += 4
            self.word(pc + 12, 0xd65f03c0)

    def arm_callbacks(self):
        address = self.address('frame_dummy')
        if self.read(address, 4) == 0xd503245f:  # Optional BTI c emitted by GCC CRT.
            address += 4
        self.arm_branch(address, self.address('register_tm_clones'))
        for name in ('deregister_tm_clones', 'register_tm_clones'):
            address = self.address(name)
            self.named(self.arm_pair(address, 0), '__TMC_END__')
            self.named(self.arm_pair(address + 8, 1), '__TMC_END__')
            if name == 'deregister_tm_clones':
                words = {4: 0xeb00003f, 5: 0x540000c0, 8: 0xb4000061,
                         9: 0xaa0103f0, 10: 0xd61f0200, 11: 0xd65f03c0}
                self.got(self.arm_pair(address + 24, 1, load=True), '_ITM_deregisterTMCloneTable')
            else:
                words = {4: 0xcb000021, 5: 0xd37ffc22, 6: 0x8b810c41, 7: 0x9341fc21,
                         8: 0xb40000c1, 11: 0xb4000062, 12: 0xaa0203f0,
                         13: 0xd61f0200, 14: 0xd65f03c0}
                self.got(self.arm_pair(address + 36, 2, load=True), '_ITM_registerTMCloneTable')
            for offset, word in words.items():
                self.word(address + offset * 4, word)
        address = self.address('__do_global_dtors_aux')
        pac = self.read(address, 4) == 0xd503233f
        address += 4 if pac else 0
        for offset, word in {0: 0xa9be7bfd, 1: 0x910003fd, 2: 0xf9000bf3,
                             8: 0xb4000080, 13: 0x52800020, 15: 0xf9400bf3,
                             16: 0xa8c27bfd}.items():
            self.word(address + offset * 4, word)
        page = self.arm_page(address + 12, 19)
        load = self.word(address + 16, 0x39400260, 0xffc003ff)
        store = self.word(address + 56, 0x39000260, 0xffc003ff)
        self.named(page + ((load >> 10) & 4095), 'completed.0')
        self.named(page + ((store >> 10) & 4095), 'completed.0')
        self.check(self.read(address + 20, 4) in (0x37000140, 0x35000140),
                   'unrecognized completed-state branch')
        self.got(self.arm_pair(address + 24, 0, load=True), '__cxa_finalize')
        self.named(self.arm_pair(address + 36, 0, load=True), '__dso_handle')
        self.arm_plt(self.arm_branch(address + 44, link=True), '__cxa_finalize')
        self.arm_branch(address + 48, self.address('deregister_tm_clones'), link=True)
        if pac:
            self.word(address + 68, 0xd50323bf)
        self.word(address + 68 + (4 if pac else 0), 0xd65f03c0)

    def rv_pair(self, pc, register, operation=0):
        # operation is ADDI=0, LD=3 or LBU=4; operand registers stay fixed.
        upper = self.word(pc, (register << 7) | 0x17, 0xfff)
        opcode = 0x13 if operation == 0 else 0x03
        lower = self.word(pc + 4, (register << 15) | (operation << 12) |
                          (register << 7) | opcode, 0xfffff)
        return pc + signed(upper & 0xfffff000, 32) + signed(lower >> 20, 12)

    def rv_jal(self, pc, target, register=1):
        word = self.word(pc, (register << 7) | 0x6f, 0xfff)
        immediate = ((word >> 31) << 20) | (((word >> 12) & 255) << 12) | \
                    (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1)
        self.check(pc + signed(immediate, 21) == target, 'RISC-V CRT call target')

    def rv_cbranch(self, pc, register, target, nonzero=False):
        word = self.word(pc, (0xe001 if nonzero else 0xc001) | ((register - 8) << 7),
                         0xe383, size=2)
        immediate = (((word >> 12) & 1) << 8) | (((word >> 10) & 3) << 3) | \
                    (((word >> 5) & 3) << 6) | (((word >> 3) & 3) << 1) | (((word >> 2) & 1) << 5)
        self.check(pc + signed(immediate, 9) == target, 'RISC-V CRT conditional target')

    def rv_cjump(self, pc, name):
        word = self.word(pc, 0xa001, 0xe003, size=2)
        immediate = (((word >> 12) & 1) << 11) | (((word >> 11) & 1) << 4) | \
                    (((word >> 9) & 3) << 8) | (((word >> 8) & 1) << 10) | \
                    (((word >> 7) & 1) << 6) | (((word >> 6) & 1) << 7) | \
                    (((word >> 3) & 7) << 1) | (((word >> 2) & 1) << 5)
        self.named(pc + signed(immediate, 12), name)

    def rv_preinit(self, section, static, allow_call_pair=False):
        # glibc's RV executable CRT initializes GP before dependency constructors
        # and again at _start. Retain this array and its real callback; dropping
        # it would change the process-wide GP contract for selected libraries.
        # Some glibc builds emit crt1.o's .preinit_array with alignment 1; the
        # entry the loader reads must still be naturally aligned.
        self.check(section is not None and section['sh_size'] == 8 and
                   section['sh_type'] == 'SHT_PREINIT_ARRAY' and
                   section['sh_entsize'] == 8 and section['sh_flags'] == 3 and
                   section['sh_addr'] % 8 == 0,
                   'RV executable requires the single-entry CRT preinit array')
        self.check(not any(section['sh_addr'] <= address < section['sh_addr'] + 8
                           for address in self.relocations),
                   'RV non-PIE CRT preinit entry must be an unrelocated pointer')
        target = int.from_bytes(section.data(), 'little')
        self.named(target, 'load_gp')
        gp = [symbol['address'] for symbol in static
              if symbol['name'] == '__global_pointer$' and
              symbol['section'] == 'SHN_ABS' and symbol['type'] == 'STT_NOTYPE']
        self.check(len(gp) == 1 and gp[0] == self.rv_pair(target, 3),
                   'load_gp must initialize the linker-defined global pointer')
        self.word(target + 8, 0x8082, size=2)  # ret; no other callback effect.
        entry = self.elf['e_entry']
        if allow_call_pair and self.read(entry, 4) & 0xfff == 0x97:
            # The reconstructed `call` pseudo-instruction remains an exact
            # AUIPC ra / JALR ra,ra pair when final relaxation is disabled.
            # Validate both registers/opcodes and the actual call destination.
            upper = self.word(entry, 0x97, 0xfff)
            lower = self.word(entry + 4, 0x80e7, 0xfffff)
            destination = (entry + signed(upper & 0xfffff000, 32) +
                           signed(lower >> 20, 12)) & ~1
            self.check(destination == target, 'RISC-V CRT call-pair target')
        else:
            self.rv_jal(entry, target)

    def rv_callbacks(self):
        address = self.address('frame_dummy')
        if self.read(address, 2) == 0x1141:
            self.rv_frame_pointer_callbacks()
            return
        if self.read(address, 2) & 3 == 3:
            self.rv_jal(address, self.address('register_tm_clones'), register=0)
        else:
            self.rv_cjump(address, 'register_tm_clones')
        address = self.address('deregister_tm_clones')
        self.named(self.rv_pair(address, 10), '__TMC_END__')
        self.named(self.rv_pair(address + 8, 15), '__TMC_END__')
        self.word(address + 16, 0x00a78863)  # beq a5,a0,ret, +16.
        self.got(self.rv_pair(address + 20, 15, 3), '_ITM_deregisterTMCloneTable')
        self.rv_cbranch(address + 28, 15, address + 32)
        self.word(address + 30, 0x8782, size=2)
        self.word(address + 32, 0x8082, size=2)
        address = self.address('register_tm_clones')
        self.named(self.rv_pair(address, 10), '__TMC_END__')
        self.named(self.rv_pair(address + 8, 11), '__TMC_END__')
        for offset, word in {16: 0x8d89, 22: 0x91fd, 24: 0x95be, 26: 0x8585,
                             40: 0x8782, 42: 0x8082}.items():
            self.word(address + offset, word, size=2)
        self.word(address + 18, 0x4035d793)
        self.rv_cbranch(address + 28, 11, address + 42)
        self.got(self.rv_pair(address + 30, 15, 3), '_ITM_registerTMCloneTable')
        self.rv_cbranch(address + 38, 15, address + 42)
        address = self.address('__do_global_dtors_aux')
        self.named(self.rv_pair(address, 15, 4), 'completed.0')
        self.rv_cbranch(address + 8, 15, address + 54, nonzero=True)
        for offset, word in {10: 0x1141, 12: 0xe406, 32: 0x9782, 38: 0x60a2,
                             40: 0x4785, 50: 0x0141, 52: 0x8082, 54: 0x8082}.items():
            self.word(address + offset, word, size=2)
        self.got(self.rv_pair(address + 14, 15, 3), '__cxa_finalize')
        self.rv_cbranch(address + 22, 15, address + 34)
        self.named(self.rv_pair(address + 24, 10, 3), '__dso_handle')
        self.rv_jal(address + 34, self.address('deregister_tm_clones'))
        upper = self.word(address + 42, 0x717, 0xfff)  # auipc a4
        store = self.word(address + 46, 0x00f70023, 0x01fff07f)  # sb a5,imm(a4)
        immediate = ((store >> 25) << 5) | ((store >> 7) & 31)
        self.named(address + 42 + signed(upper & 0xfffff000, 32) + signed(immediate, 12),
                   'completed.0')

    def rv_frame_pointer_callbacks(self):
        # Ubuntu GCC 13 crtbeginS.o: one exact frame-pointer variant, not
        # arbitrary prologue/epilogue skipping or instruction interpretation.
        address = self.address('frame_dummy')
        for offset, word in {0: 0x1141, 2: 0xe422, 4: 0x0800, 6: 0x6422, 8: 0x0141}.items():
            self.word(address + offset, word, size=2)
        self.rv_cjump(address + 10, 'register_tm_clones')
        address = self.address('deregister_tm_clones')
        for offset, word in {0: 0x1141, 2: 0xe422, 4: 0x0800, 36: 0x6422, 38: 0x0141,
                             40: 0x8782, 42: 0x6422, 44: 0x0141, 46: 0x8082}.items():
            self.word(address + offset, word, size=2)
        self.named(self.rv_pair(address + 6, 10), '__TMC_END__')
        self.named(self.rv_pair(address + 14, 15), '__TMC_END__')
        self.word(address + 22, 0x00a78a63)  # beq a5,a0,epilogue, +20.
        self.got(self.rv_pair(address + 26, 15, 3), '_ITM_deregisterTMCloneTable')
        self.rv_cbranch(address + 34, 15, address + 42)
        address = self.address('register_tm_clones')
        self.named(self.rv_pair(address, 10), '__TMC_END__')
        self.named(self.rv_pair(address + 8, 11), '__TMC_END__')
        for offset, word in {16: 0x8d89, 18: 0x1141, 24: 0x91fd, 26: 0xe422,
                             28: 0x95be, 30: 0x0800, 32: 0x8585, 46: 0x6422,
                             48: 0x0141, 50: 0x8782, 52: 0x6422, 54: 0x0141,
                             56: 0x8082}.items():
            self.word(address + offset, word, size=2)
        self.word(address + 20, 0x4035d793)
        self.rv_cbranch(address + 34, 11, address + 52)
        self.got(self.rv_pair(address + 36, 15, 3), '_ITM_registerTMCloneTable')
        self.rv_cbranch(address + 44, 15, address + 52)
        address = self.address('__do_global_dtors_aux')
        for offset, word in {0: 0x1101, 2: 0xe822, 4: 0xe426, 6: 0xec06, 8: 0x1000,
                             42: 0x9782, 48: 0x4785, 54: 0x60e2, 56: 0x6442,
                             58: 0x64a2, 60: 0x6105, 62: 0x8082}.items():
            self.word(address + offset, word, size=2)
        self.named(self.rv_pair(address + 10, 9), 'completed.0')
        self.word(address + 18, 0x0004c783)  # lbu a5,0(s1)
        self.rv_cbranch(address + 22, 15, address + 54, nonzero=True)
        self.got(self.rv_pair(address + 24, 15, 3), '__cxa_finalize')
        self.rv_cbranch(address + 32, 15, address + 44)
        self.named(self.rv_pair(address + 34, 10, 3), '__dso_handle')
        self.rv_jal(address + 44, self.address('deregister_tm_clones'))
        self.word(address + 50, 0x00f48023)  # sb a5,0(s1), the same completed.0.


def validate_linked_riscv_startup(elf, path):
    """Recheck the actual GP initializer after reconstruction and final link."""
    table = elf.get_section_by_name('.symtab')
    if table is None:
        reject('MISSING_LINKED_GP_METADATA', path, 'symbol table required')
    static = [sym_record(symbol) for symbol in table.iter_symbols() if symbol.name]
    relocations = {relocation['r_offset']: relocation
                   for section in elf.iter_sections() if isinstance(section, RelocationSection)
                   for relocation in section.iter_relocations()}
    image = StartupImage(elf, static, relocations, elf.get_section_by_name('.dynsym'), path)
    image.rv_preinit(elf.get_section_by_name('.preinit_array'), static, allow_call_pair=True)


def arm64_input_data_regions(elf, symbols):
    """Independent input evidence for data in otherwise executable sections.

    Mapping symbols delimit regions within their own ELF section, not across
    the address space. Conflicting mappings at the same address are not proof.
    """
    if elf['e_machine'] != 'EM_AARCH64':
        return []
    sections = list(elf.iter_sections())
    mappings = {}
    regions = []
    for symbol in symbols:
        index = symbol['section']
        if not isinstance(index, int) or not 0 < index < len(sections):
            continue
        section = sections[index]
        begin, end = section['sh_addr'], section['sh_addr'] + section['sh_size']
        address = symbol['address']
        if not section['sh_flags'] & 2 or not begin <= address < end:
            continue
        if symbol['type'] == 'STT_OBJECT' and 0 < symbol['size'] <= end - address:
            regions.append({'start': address, 'end': address + symbol['size'],
                            'source': 'STT_OBJECT', 'name': symbol['name'], 'section': index})
        match = re.fullmatch(r'\$([dx])(?:\..+)?', symbol['name'])
        if match and symbol['type'] == 'STT_NOTYPE' and symbol['binding'] == 'STB_LOCAL':
            mappings.setdefault(index, {}).setdefault(address, set()).add(match[1])
    for index, points in sorted(mappings.items()):
        addresses = sorted(points)
        section_end = sections[index]['sh_addr'] + sections[index]['sh_size']
        for offset, address in enumerate(addresses):
            if points[address] == {'d'}:
                end = addresses[offset + 1] if offset + 1 < len(addresses) else section_end
                regions.append({'start': address, 'end': end, 'source': '$d', 'section': index})
    return sorted(regions, key=lambda r: (r['start'], r['end'], r['source']))


def frontend_data_warning_proof(module, item, address):
    """Accept no undecodable code: input metadata and final IR must agree on data."""
    if item['machine'] != 'EM_AARCH64' or module.isa != gtirb.Module.ISA.ARM64 or address % 4:
        return None
    end = address + 4
    witness = next((r for r in item.get('input_data_regions', ())
                    if r['start'] <= address and end <= r['end']), None)
    if witness is None:
        return None
    blocks = list(module.byte_blocks_on(range(address, end)))
    if not blocks or any(not isinstance(b, gtirb.DataBlock) for b in blocks):
        return None
    covered = address
    for block in sorted(blocks, key=lambda b: b.address):
        if block.address > covered:
            return None
        covered = max(covered, block.address + block.size)
    if covered < end:
        return None
    return {'address': address, 'size': 4, 'input_witness': witness,
            'recovered_data_blocks': sorted((b.address, b.size) for b in blocks)}


def validate_frontend_diagnostics(module, item, diagnostics, allow_ambiguous_data_pointers=False):
    """Distinguish failed candidate decodes of proven data from lost instructions.

    Arm64Loader tries each word in executable sections before code inference.
    Its CIMM message is immediately followed by the addressed type-64 message;
    that exact pair can share the same evidence. Only the exact N52 grouped
    override diagnostic is admitted by the explicit opt-in. It is an unproven
    heuristic, never a frontend_data_warning_proof. All other warnings fail.
    """
    if type(allow_ambiguous_data_pointers) is not bool:
        reject('FRONTEND_POLICY', item['path'], 'explicit boolean policy required')
    lines = diagnostics.splitlines()
    accepted = []
    pattern = r'WARNING: unhandled operand at (\d+), op type:(\d+)'
    grouped = (r'\t([^\t\r\n]+): ([1-9][0-9]*) word\(s\); first at 0x([0-9a-f]+) '
               r'\(([1-9][0-9]*) bytes, value 0x([0-9a-f]+)\)')
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if 'ERROR' in line:
            reject('FRONTEND_DIAGNOSTIC', item['path'], line.strip())
        if line == AMBIGUOUS_POINTER_FOOTER:
            reject('FRONTEND_DIAGNOSTIC', item['path'], 'orphan ambiguity footer')
        if 'WARNING' not in line:
            continue
        message = line[line.index('WARNING'):].strip()
        if line == AMBIGUOUS_POINTER_WARNING:
            if not allow_ambiguous_data_pointers:
                reject('FRONTEND_DIAGNOSTIC', item['path'], message)
            if any(row.get('category') == 'ambiguous-data-pointers' for row in accepted):
                reject('FRONTEND_DIAGNOSTIC', item['path'], 'duplicate ambiguity warning')
            begin = index - 1
            objects = []
            while index < len(lines) and lines[index] != AMBIGUOUS_POINTER_FOOTER:
                match = re.fullmatch(grouped, lines[index])
                if not match or 'WARNING' in lines[index] or 'ERROR' in lines[index]:
                    reject('FRONTEND_DIAGNOSTIC', item['path'],
                           'malformed ambiguity inventory: ' + lines[index])
                name, count, address, size, value = match.groups()
                address, size, value = int(address, 16), int(size), int(value, 16)
                if (size not in (4, 8) or address + size > 1 << 64 or value >= 1 << (size * 8)
                        or any(row['object'] == name for row in objects)):
                    reject('FRONTEND_DIAGNOSTIC', item['path'], 'invalid ambiguity object: ' + name)
                objects.append({'object': name, 'word_count': int(count),
                                'first_address': address, 'size': size, 'first_value': value})
                index += 1
            if not objects or index == len(lines):
                reject('FRONTEND_DIAGNOSTIC', item['path'], 'missing ambiguity inventory/footer')
            index += 1  # the exact footer, not arbitrary explanatory text
            accepted.append({'category': 'ambiguous-data-pointers', 'evidence': 'unproven heuristic',
                             'inventory_kind': 'grouped counts and first examples; not a full per-word inventory',
                             'objects': objects, 'raw_diagnostic': '\n'.join(lines[begin:index])})
            continue
        if (item['role'] == 'selected' and item['entry'] == 0 and
                message == 'WARNING: Failed to set module entry point.'):
            continue
        integral = re.fullmatch(r'WARNING: Found integral symbol pointing into existing block:\s*(\S+)', message)
        if integral and integral[1] in item.get('allow_integral_constant_symbols', []):
            accepted.append({'category': 'integral-constant', 'symbol': integral[1],
                             'diagnostic': message, 'evidence': 'caller named integral authorization',
                             'constant_value_preservation_claimed': False})
            continue
        match = re.fullmatch(pattern, message)
        if message == 'WARNING: unsupported CIMM operand' and index < len(lines):
            following = re.fullmatch(pattern, lines[index].strip())
            if following and following[2] == '64':
                match = following
        if match:
            proof = frontend_data_warning_proof(module, item, int(match[1]))
            if proof is not None:
                accepted.append(dict(proof, diagnostic=message, operand_type=int(match[2])))
                continue
        reject('FRONTEND_DIAGNOSTIC', item['path'], line.strip())
    return accepted


def frontend_argv(args, item, irpath):
    """Every converter/component lift uses the caller's explicit policy."""
    command = [args.ddisasm, item['path'], '--ir', irpath, '-j', str(args.jobs)]
    if args.allow_ambiguous_data_pointers:
        command.append('--allow-ambiguous-data-pointers')
    return command


def frontend_diagnostic_record(module, item, directory, allow_ambiguous_data_pointers):
    """Bind the unmodified stderr and accepted inventory to the lift artifacts."""
    if type(allow_ambiguous_data_pointers) is not bool:
        reject('FRONTEND_POLICY', item['path'], 'explicit boolean policy required')
    try:
        diagnostics = (directory / 'lift/stderr').read_bytes().decode('utf-8')
        command = json.loads((directory / 'lift/command.json').read_text())
    except (OSError, ValueError) as error:
        reject('FRONTEND_DIAGNOSTIC_RECORD', item['path'], str(error))
    flag = '--allow-ambiguous-data-pointers'
    if (not isinstance(command, list) or not all(isinstance(arg, str) for arg in command)
            or len(command) != 6 + int(allow_ambiguous_data_pointers)
            or command[2] != '--ir' or command[4] != '-j'
            or Path(command[1]).name != Path(item['path']).name
            or command.count(flag) != int(allow_ambiguous_data_pointers)
            or '--ignore-errors' in command):
        reject('FRONTEND_POLICY', item['path'], 'lift command disagrees with explicit policy')
    accepted = validate_frontend_diagnostics(module, item, diagnostics, allow_ambiguous_data_pointers)
    return {'format': 'teapot-frontend-diagnostics-v1',
            'allow_ambiguous_data_pointers': allow_ambiguous_data_pointers,
            'input_sha256': item['sha256'], 'input_role': item['role'],
            'lift_ir_sha256': sha(directory / 'lift.gtirb'),
            'command_sha256': sha(directory / 'lift/command.json'),
            'stderr_sha256': sha(directory / 'lift/stderr'), 'raw_diagnostics': diagnostics,
            'accepted': accepted,
            'pointer_inference': 'unproven heuristic' if allow_ambiguous_data_pointers else 'strict'}


def record_frontend_diagnostics(module, item, directory, allow_ambiguous_data_pointers, verify=False):
    record = frontend_diagnostic_record(module, item, directory, allow_ambiguous_data_pointers)
    path = directory / 'frontend-diagnostics.json'
    if verify:
        try:
            existing = json.loads(path.read_text())
        except (OSError, ValueError) as error:
            reject('FRONTEND_DIAGNOSTIC_RECORD', item['path'], str(error))
        if (not isinstance(existing, dict) or type(existing.get('allow_ambiguous_data_pointers')) is not bool
                or existing != json.loads(json.dumps(record))):
            reject('FRONTEND_DIAGNOSTIC_RECORD', item['path'], 'missing/mismatched policy or diagnostic record')
    else:
        dump(path, record)
        # Keep the existing proven-data sidecar narrow: guesses are NOT proofs.
        dump(directory / 'proven-data-decoder-warnings.json',
             [row for row in record['accepted'] if row.get('category') != 'ambiguous-data-pointers'])
    return record


def validate_x64_init_fini(init, fini, relocations, dynsym, path):
    """Admit only the canonical CRT bodies, optionally preceded by one ENDBR64."""
    endbr64 = bytes.fromhex('f30f1efa')
    if init:
        data = init.data()
        offset = 4 if data.startswith(endbr64) else 0
        body = data[offset:]
        prefix, suffix = bytes.fromhex('4883ec08488b05'), bytes.fromhex('4885c07402ffd04883c408c3')
        if not (len(body) == 23 and body[:7] == prefix and body[11:] == suffix):
            reject('CUSTOM_DT_INIT', path, 'not the supported x64 glibc gmon-only CRT sequence')
        got = init['sh_addr'] + offset + 11 + struct.unpack('<i', body[7:11])[0]
        relocation = relocations.get(got)
        if not relocation or dynsym.get_symbol(relocation['r_info_sym']).name != '__gmon_start__':
            reject('CUSTOM_DT_INIT', path, 'init call is not the weak __gmon_start__ hook')
    if fini:
        data = fini.data()
        body = data[4:] if data.startswith(endbr64) else data
        if body != bytes.fromhex('4883ec084883c408c3'):
            reject('CUSTOM_DT_FINI', path, 'not the supported empty x64 glibc CRT sequence')


def inspect(path, role, resolve_selected_versions=False, preserve_selected_lifecycle=False,
            preserve_nonlocal_jumps=False, preserve_weak_imports=False, *, riscv_profile='lp64d',
            allow_integral_constant_symbols=None):
    path = Path(path)
    integral_names = [] if allow_integral_constant_symbols is None else allow_integral_constant_symbols
    if (type(integral_names) is not list or
            not all(type(name) is str and name for name in integral_names) or
            integral_names != sorted(set(integral_names))):
        reject('FRONTEND_POLICY', path, 'integral symbol names require an explicit canonical list')
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        machine = elf['e_machine']
        if elf.elfclass != 64 or not elf.little_endian or machine not in ARCHITECTURES:
            reject('UNSUPPORTED_ARCH', path, 'only little-endian x64/AArch64/RV64 ELF64 is implemented')
        architecture = ARCHITECTURES[machine]
        if riscv_profile not in ('lp64d', 'lp64-pure'):
            reject('UNKNOWN_RISCV_PROFILE', path, str(riscv_profile))
        if riscv_profile == 'lp64-pure':
            from teapot.riscv_profile import INTERPRETERS, validate_elf_header
            try:
                validate_elf_header(elf, role=role)
            except ValueError as error:
                reject('UNSUPPORTED_PURE_PROFILE', path, str(error))
            architecture = dict(architecture, interpreter=INTERPRETERS[riscv_profile])
        rv_executable = machine == 'EM_RISCV' and role == 'executable'
        flags = elf['e_flags']
        if (machine == 'EM_RISCV' and (flags & ~5 or flags & 6 != (0 if riscv_profile == 'lp64-pure' else 4))) or \
                (machine != 'EM_RISCV' and flags != 0):
            reject('UNSUPPORTED_ABI_FLAGS', path, 'requires normal ELF64 ABI, RV64 LP64D with optional RVC')
        expected = 'ET_EXEC' if role == 'executable' else 'ET_DYN'
        if elf['e_type'] != expected:
            reject('UNSUPPORTED_ELF_TYPE', path, '{} requires {}'.format(role, expected))
        dynsym = elf.get_section_by_name('.dynsym')
        dynamic = elf.get_section_by_name('.dynamic')
        if dynsym is None or dynamic is None:
            reject('MISSING_DYNAMIC_METADATA', path, 'dynamic symbol/loader tables required')
        symbols, version_definitions, version_requirements = dynamic_symbol_records(elf)
        symtab = elf.get_section_by_name('.symtab')
        static = [sym_record(s) for s in symtab.iter_symbols() if s.name] if symtab else []
        tags = list(dynamic.iter_tags())
        needed = [t.needed for t in tags if t.entry.d_tag == 'DT_NEEDED']
        sonames = [t.soname for t in tags if t.entry.d_tag == 'DT_SONAME']
        result = {'path': str(path), 'sha256': sha(path), 'role': role,
                  'machine': machine, 'architecture': architecture['name'], 'elf_flags': flags,
                  'needed': needed, 'soname': sonames[0] if sonames else None,
                  'symbols': symbols, 'entry': elf['e_entry'], 'fde_count': 0,
                  'application_fdes': [], 'relocation_types': {},
                  'versions': version_requirements, 'version_definitions': version_definitions,
                  'resolve_selected_versions': resolve_selected_versions,
                  'preserve_selected_lifecycle': preserve_selected_lifecycle,
                  'preserve_nonlocal_jumps': preserve_nonlocal_jumps,
                  'preserve_weak_imports': preserve_weak_imports,
                  'symbolic_lookup': any(t.entry.d_tag == 'DT_SYMBOLIC' or
                      (t.entry.d_tag == 'DT_FLAGS' and t.entry.d_val & 2) for t in tags)}
        if integral_names:
            result['allow_integral_constant_symbols'] = list(integral_names)
        if riscv_profile == 'lp64-pure':
            from teapot.riscv_profile import PURE_ABI
            result.update(riscv_profile=riscv_profile, riscv_abi=dict(PURE_ABI))
        if role == 'external':
            return result
        if role == 'executable':
            interpreters = [s.data().rstrip(b'\0').decode('ascii') for s in elf.iter_segments()
                            if s['p_type'] == 'PT_INTERP']
            if interpreters != [architecture['interpreter']]:
                reject('UNSUPPORTED_INTERPRETER', path, str(interpreters))
        if not symtab:
            reject('STRIPPED_STARTUP_CONTRACT', path,
                   'prototype requires symbol-table evidence for startup/unwind ownership')
        if role == 'executable' and not any(s['name'] == '_start' and s['address'] == elf['e_entry']
                                            and isinstance(s['section'], int) for s in static):
            reject('NONSTANDARD_ENTRY_POINT', path, 'e_entry must match the preserved _start')
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_GNU_STACK' and segment['p_flags'] & 1:
                reject('EXECUTABLE_STACK', path, 'stack-execution contract not supported')
        all_names = {s['name'].split('@')[0] for s in symbols + static}
        if all_names & LOOKUP:
            reject('RUNTIME_SYMBOL_LOOKUP', path, ', '.join(sorted(all_names & LOOKUP)))
        unsupported_unwind = set(UNWIND_UNSUPPORTED)
        if preserve_selected_lifecycle:
            unsupported_unwind.discard('__cxa_atexit')
        if preserve_nonlocal_jumps:
            unsupported_unwind -= NONLOCAL_JUMPS
        if all_names & unsupported_unwind:
            reject('NONLOCAL_UNWIND', path, ', '.join(sorted(all_names & unsupported_unwind)))
        for sec in elf.iter_sections():
            if machine != 'EM_X86_64' and sec.name == '.note.gnu.property' and sec['sh_size']:
                reject('UNSUPPORTED_PROPERTY_CONTRACT', path,
                       'selected Arm/RV GNU properties require an explicit preserved enforcement contract')
            if sec['sh_flags'] & 0x400:
                reject('TLS_SECTION', path, sec.name)
            unsupported_startup = sec.name in {'.gcc_except_table', '.ctors', '.dtors'} or \
                (sec.name == '.preinit_array' and not rv_executable)
            if unsupported_startup and sec['sh_size']:
                reject('UNSUPPORTED_STARTUP_OR_UNWIND_SECTION', path, sec.name)
            if sec.name == '.gnu.version_d' and sec['sh_size'] and not resolve_selected_versions:
                reject('SELECTED_SYMBOL_VERSION_DEFINITION', path, sec.name)
        for symbol in symbols + static:
            if symbol['type'] in ('STT_GNU_IFUNC', 'STT_LOOS'):
                reject('IFUNC_SYMBOL', path, symbol['name'])
            if symbol['type'] == 'STT_TLS':
                reject('TLS_SYMBOL', path, symbol['name'])
            if symbol['binding'] in ('STB_GNU_UNIQUE', 'STB_LOOS'):
                reject('GNU_UNIQUE_BINDING', path, symbol['name'])
            if symbol['binding'] == 'STB_WEAK':
                crt_data_alias = (role == 'executable' and symbol['name'] == 'data_start'
                    and any(s['name'] == '__data_start' and s['address'] == symbol['address']
                            and s['section'] == symbol['section'] for s in static))
                if not crt_data_alias and (symbol['section'] != 'SHN_UNDEF' or
                        (not preserve_weak_imports and symbol['name'].split('@')[0] not in CRT_WEAK)):
                    reject('WEAK_BINDING', path, symbol['name'])
            if symbol['visibility'] not in ('STV_DEFAULT', 'STV_HIDDEN'):
                reject('UNSUPPORTED_VISIBILITY', path, symbol['name'])
        # DT_SYMBOLIC only changes local-vs-global lookup on duplicate
        # definitions. validate_closure rejects that ambiguity, and hidden
        # library definitions are localized before reconstruction.
        unsupported_tags = {'DT_FILTER', 'DT_AUXILIARY', 'DT_AUDIT',
                            'DT_DEPAUDIT', 'DT_TEXTREL', 'DT_RELR', 'DT_RELRSZ',
                            'DT_PREINIT_ARRAY', 'DT_PREINIT_ARRAYSZ'}
        if rv_executable:
            unsupported_tags -= {'DT_PREINIT_ARRAY', 'DT_PREINIT_ARRAYSZ'}
        for tag in tags:
            if tag.entry.d_tag in unsupported_tags:
                reject('UNSUPPORTED_DYNAMIC_TAG', path, tag.entry.d_tag)
            if tag.entry.d_tag == 'DT_FLAGS' and tag.entry.d_val & ~(8 | 2):
                reject('UNSUPPORTED_DYNAMIC_FLAGS', path, hex(tag.entry.d_val))
            # A selected NODELETE DSO is folded into process-lifetime storage;
            # runtime dlopen/dlclose and provider replacement are still refused.
            allowed_flags1 = 1 | (8 if role == 'selected' else 0)
            if tag.entry.d_tag == 'DT_FLAGS_1' and tag.entry.d_val & ~allowed_flags1:
                reject('UNSUPPORTED_DYNAMIC_FLAGS_1', path, hex(tag.entry.d_val))
        relocations = {}
        if machine == 'EM_AARCH64':
            result['aarch64_got_relocations'] = []
        counts = Counter()
        static_counts = Counter()
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            # --emit-relocs retains link-time metadata for a later lift. Those
            # entries refer to .symtab, not the loader's .dynsym, and do not
            # describe runtime relocations (including CRT/preinit fixups).
            if (not (sec['sh_flags'] & 2)
                    and elf.get_section(sec['sh_link'])['sh_type'] == 'SHT_SYMTAB'):
                static_counts.update(rel['r_info_type'] for rel in sec.iter_relocations())
                continue
            for relocation in sec.iter_relocations():
                rtype = relocation['r_info_type']
                counts[rtype] += 1
                if rtype == architecture['copy']:
                    symbol = copy_relocation_symbol(elf, sec, relocation, symbols, path, role)
                    result.setdefault('copy_relocations', []).append({
                        'address': relocation['r_offset'], 'symbol': symbol})
                elif rtype not in architecture['relocations']:
                    reject('UNSUPPORTED_RELOCATION', path, str(rtype))
                relocations[relocation['r_offset']] = dict(relocation.entry)
                if machine == 'EM_AARCH64' and any(
                        got is not None and got['sh_addr'] <= relocation['r_offset']
                        and relocation['r_offset'] + 8 <= got['sh_addr'] + got['sh_size']
                        for got in (elf.get_section_by_name('.got'), elf.get_section_by_name('.got.plt'))):
                    symbol = dynsym.get_symbol(relocation['r_info_sym'])
                    result['aarch64_got_relocations'].append((
                        relocation['r_offset'], rtype, symbol.name, relocation.entry.get('r_addend', 0),
                        symbol['st_shndx'] == 'SHN_UNDEF'))
        result['relocation_types'] = dict(counts)
        result['static_relocation_types'] = dict(static_counts)
        address_names = {}
        for symbol in static:
            if isinstance(symbol['section'], int):
                address_names.setdefault(symbol['address'], set()).add(symbol['name'])
        # Default ELF startup is accepted only with validated architecture-
        # specific CRT bodies/targets, not because a function has a CRT name.
        init = elf.get_section_by_name('.init')
        fini = elf.get_section_by_name('.fini')
        custom_lifecycle = role == 'selected' and preserve_selected_lifecycle
        result['lifecycle'] = {}
        for section, tag_name in ((init, 'DT_INIT'), (fini, 'DT_FINI')):
            addresses = [t.entry.d_val for t in tags if t.entry.d_tag == tag_name]
            if addresses:
                if custom_lifecycle:
                    if len(addresses) != 1 or not any(
                            s['sh_flags'] & 4 and s['sh_addr'] <= addresses[0] < s['sh_addr'] + s['sh_size']
                            for s in elf.iter_sections()):
                        reject('INVALID_' + tag_name, path, 'callback must name executable code')
                elif len(addresses) != 1 or section is None or addresses[0] != section['sh_addr']:
                    reject('REDIRECTED_' + tag_name, path, 'dynamic tag does not name its validated section')
                result['lifecycle'][tag_name] = addresses[0]
        array_tags = [('.init_array', 'DT_INIT_ARRAY', 'DT_INIT_ARRAYSZ'),
                      ('.fini_array', 'DT_FINI_ARRAY', 'DT_FINI_ARRAYSZ')]
        if rv_executable:
            array_tags.append(('.preinit_array', 'DT_PREINIT_ARRAY', 'DT_PREINIT_ARRAYSZ'))
        for name, address_tag, size_tag in array_tags:
            section = elf.get_section_by_name(name)
            addresses = [t.entry.d_val for t in tags if t.entry.d_tag == address_tag]
            sizes = [t.entry.d_val for t in tags if t.entry.d_tag == size_tag]
            if section is not None and section['sh_size']:
                if addresses != [section['sh_addr']] or sizes != [section['sh_size']]:
                    reject('MISMATCHED_' + address_tag, path, 'dynamic address/size must describe the retained array')
            elif addresses or (sizes and sizes != [0]):
                reject('MISMATCHED_' + address_tag, path, 'dynamic array has no retained section')
        if custom_lifecycle:
            for section_name in ('.init_array', '.fini_array'):
                section = elf.get_section_by_name(section_name)
                if section is None:
                    continue
                if section['sh_size'] % 8:
                    reject('INVALID_CALLBACK_ARRAY', path, section_name)
                for slot in range(section['sh_addr'], section['sh_addr'] + section['sh_size'], 8):
                    relocation = relocations.get(slot)
                    if not relocation:
                        reject('UNRELOCATED_CALLBACK', path, hex(slot))
                    if relocation['r_info_type'] == architecture['relative']:
                        target = relocation.get('r_addend')
                        if relocation['r_info_sym'] or target is None or not any(
                                s['sh_flags'] & 4 and s['sh_addr'] <= target < s['sh_addr'] + s['sh_size']
                                for s in elf.iter_sections()):
                            reject('INVALID_CALLBACK', path, hex(slot))
                    elif not relocation['r_info_sym']:
                        reject('INVALID_CALLBACK', path, hex(slot))
        elif machine == 'EM_AARCH64':
            StartupImage(elf, static, relocations, dynsym, path).arm_init_fini(init, fini)
        elif machine == 'EM_RISCV':
            if any(section is not None and section['sh_size'] for section in (init, fini)):
                reject('CUSTOM_DT_INIT_OR_FINI', path, 'RV64 startup contract has no init/fini code section')
            if rv_executable:
                StartupImage(elf, static, relocations, dynsym, path).rv_preinit(
                    elf.get_section_by_name('.preinit_array'), static, allow_call_pair=True)
                # Unrelaxed original executables use the same exact AUIPC/JALR
                # CRT call already validated after reconstruction. Its register
                # operands and actual load_gp target must still match.
                result['preinit_contract'] = 'retained single CRT load_gp; validated _start initialization'
        elif role in ('selected', 'executable'):
            validate_x64_init_fini(init, fini, relocations, dynsym, path)
        if role == 'selected' and not custom_lifecycle:
            callbacks_present = False
            for section_name, allowed in (('.init_array', 'frame_dummy'),
                                          ('.fini_array', '__do_global_dtors_aux')):
                section = elf.get_section_by_name(section_name)
                if not section or not section['sh_size']:
                    continue
                callbacks_present = True
                if section['sh_size'] != 8:
                    reject('CUSTOM_CONSTRUCTOR_OR_DESTRUCTOR', path, section_name)
                relocation = relocations.get(section['sh_addr'])
                target = relocation.get('r_addend') if relocation and \
                    relocation['r_info_type'] == architecture['relative'] and relocation['r_info_sym'] == 0 else None
                if target is None or allowed not in address_names.get(target, set()):
                    reject('CUSTOM_CONSTRUCTOR_OR_DESTRUCTOR', path, section_name)
            if callbacks_present:
                if machine == 'EM_X86_64':
                    validate_crt_callbacks(elf, static, relocations, dynsym, path)
                elif machine == 'EM_AARCH64':
                    StartupImage(elf, static, relocations, dynsym, path).arm_callbacks()
                else:
                    StartupImage(elf, static, relocations, dynsym, path).rv_callbacks()
        if role == 'selected':
            tm = elf.get_section_by_name('.tm_clone_table')
            if tm and tm['sh_size']:
                reject('TRANSACTION_CLONE_REGISTRATION', path, 'nonempty .tm_clone_table')
        eh = elf.get_section_by_name('.eh_frame')
        if eh and eh['sh_size']:
            try:
                # Inputs are linked ET_EXEC/ET_DYN images. Retained static
                # relocations have already been applied; applying them again
                # (using absolute ELF offsets as section offsets) corrupts CFI.
                for entry in elf.get_dwarf_info(relocate_dwarf_sections=False).EH_CFI_entries():
                    if not isinstance(entry, FDE):
                        continue
                    result['fde_count'] += 1
                    start, size = entry['initial_location'], entry['address_range']
                    sections = [s.name for s in elf.iter_sections()
                                if s['sh_addr'] <= start < s['sh_addr'] + s['sh_size'] and s['sh_flags'] & 2]
                    names = sorted(address_names.get(start, set()))
                    if role == 'selected' and ((not custom_lifecycle and set(names) & {'_init', '_fini'}) or any(n.startswith('.plt') for n in sections)):
                        continue
                    if role == 'executable' and any(n.startswith('.plt') for n in sections):
                        continue
                    # Assembly routines may carry several FDEs without a
                    # symbol at every start. Addresses, not optional names,
                    # identify their ownership and the recovered CFI check.
                    if size <= 0 or not any(s['sh_flags'] & 4 and
                            s['sh_addr'] <= start and start + size <= s['sh_addr'] + s['sh_size']
                            for s in elf.iter_sections()):
                        reject('INVALID_UNWIND_RANGE', path, hex(start))
                    result['application_fdes'].append({'start': start, 'size': size, 'names': names})
            except Unsupported:
                raise
            except Exception as error:
                reject('UNWIND_DECODE', path, str(error))
        result['static_symbols'] = static
        result['input_data_regions'] = arm64_input_data_regions(elf, static)
        return result


def validate_closure(executable, selected, external):
    for item in selected + external:
        if item['machine'] != executable['machine']:
            reject('MIXED_ARCHITECTURES', item['path'], executable['machine'] + ' required')
        if executable['machine'] == 'EM_RISCV' and (
                item.get('riscv_profile', 'lp64d') != executable.get('riscv_profile', 'lp64d') or
                item['elf_flags'] & 6 != executable['elf_flags'] & 6):
            reject('MIXED_RISCV_ABI_PROFILE', item['path'], 'all providers must use the same calling ABI/profile')
    providers = {}
    for item in selected + external:
        if not item['soname']:
            reject('MISSING_SONAME', item['path'], 'explicit dependency SONAME required')
        if item['soname'] in providers:
            reject('DUPLICATE_SONAME', item['path'], item['soname'])
        providers[item['soname']] = item
    for item in [executable] + selected + external:
        for needed in item['needed']:
            if needed not in providers:
                reject('INCOMPLETE_DEPENDENCY_CLOSURE', item['path'], needed)
    # A COPY source must be a uniquely resolved, retained external object.
    # It cannot be folded into a selected object, nor guessed from an unrelated DSO.
    copies = executable.get('copy_relocations', ())
    reachable = set()
    pending = list(executable['needed']) if copies else []
    for name in pending:
        if name not in reachable:
            reachable.add(name)
            pending.extend(providers[name]['needed'])
    for copy in copies:
        symbol = copy['symbol']
        matches = [(item, candidate) for name, item in providers.items() if name in reachable
                   for candidate in item['symbols']
                   if candidate['name'] == symbol['name'] and candidate['section'] != 'SHN_UNDEF'
                   and candidate['visibility'] == 'STV_DEFAULT'
                   and candidate['binding'] in ('STB_GLOBAL', 'STB_WEAK')
                   and (candidate.get('version') == symbol.get('version') if symbol.get('version')
                        else not candidate.get('version') or candidate.get('version_default'))]
        if (len(matches) != 1 or matches[0][0]['role'] != 'external'
                or matches[0][1]['type'] != 'STT_OBJECT' or matches[0][1]['size'] != symbol['size']
                or not isinstance(matches[0][1]['section'], int)
                or symbol.get('version_library') not in (None, matches[0][0]['soname'])):
            reject('COPY_RELOCATION', executable['path'], 'COPY provider is not an exact external object: ' + symbol['name'])
        copy['provider'] = matches[0][0]['soname']
    # The executable is first in the loader scope. Admit only its strong,
    # unversioned dynsym definition preempting one ordinary selected DSO.
    # Other duplicate shapes, including DT_SYMBOLIC self-binding, still refuse.
    definitions = {}
    for item in selected:
        item['executable_interpositions'] = []
    for item in [executable] + selected + external:
        for symbol in item['symbols']:
            if item is executable and any(symbol == copy['symbol'] for copy in copies):
                continue  # loader-owned external import, not an ordinary input definition
            if version_node_symbol(item, symbol):
                continue
            if symbol['section'] == 'SHN_UNDEF' or symbol['binding'] == 'STB_LOCAL':
                continue
            if symbol['visibility'] == 'STV_HIDDEN':
                continue
            definitions.setdefault(symbol['name'], []).append((item, symbol))
    for name, entries in definitions.items():
        items = [item for item, _ in entries]
        paths = {item['path'] for item in items}
        selected_definitions = [i for i in items if i['role'] != 'external']
        if len(paths) > 1 and selected_definitions:
            main = [(item, symbol) for item, symbol in entries if item is executable]
            dso = [(item, symbol) for item, symbol in entries if item['role'] == 'selected']
            ordinary = lambda s: (s['binding'] == 'STB_GLOBAL' and
                s['visibility'] == 'STV_DEFAULT' and isinstance(s['section'], int) and
                s['type'] in ('STT_FUNC', 'STT_OBJECT') and not s.get('version'))
            if (len(entries) == 2 and len(main) == len(dso) == 1 and
                    ordinary(main[0][1]) and ordinary(dso[0][1]) and
                    main[0][1]['type'] == dso[0][1]['type'] and
                    not dso[0][0].get('symbolic_lookup')):
                dso[0][0]['executable_interpositions'].append(name)
            else:
                reject('AMBIGUOUS_GLOBAL_BINDING', selected_definitions[0]['path'],
                       '{} also defined in {}'.format(name, ', '.join(sorted(paths))))
        if name in CRT_WEAK - {'__cxa_finalize'}:
            reject('CALLABLE_CRT_HOOK', items[0]['path'], name)
    selected_sonames = {item['soname'] for item in selected}
    for item in [executable] + selected:
        for version in item['versions']:
            if version['library'] in selected_sonames:
                if not item.get('resolve_selected_versions'):
                    reject('SELECTED_SYMBOL_VERSION_REFERENCE', item['path'], version['library'])
                provider = providers[version['library']]
                available = {definition['name'] for definition in provider['version_definitions']}
                missing = set(version['versions']) - available
                if missing:
                    reject('MISSING_SELECTED_SYMBOL_VERSION', item['path'],
                           '{}: {}'.format(version['library'], ', '.join(sorted(missing))))
        for symbol in item['symbols']:
            if symbol['section'] != 'SHN_UNDEF' or symbol.get('version_library') not in selected_sonames:
                continue
            provider = providers[symbol['version_library']]
            if not any(candidate['section'] != 'SHN_UNDEF' and
                       candidate['name'] == symbol['name'] and
                       candidate.get('version') == symbol.get('version')
                       for candidate in provider['symbols']):
                reject('MISSING_SELECTED_SYMBOL_VERSION', item['path'],
                       reconstructed_symbol_name(symbol))
    for item in external:
        if selected_sonames.intersection(item['needed']):
            reject('EXTERNAL_DEPENDS_ON_SELECTED', item['path'], str(item['needed']))
    # Dependency-compatible deterministic array order for the narrowly validated
    # CRT callback subset. Its registration hooks are absent and no selected
    # module registers C++ destructors, so sibling callbacks are order-independent.
    # This is NOT a general emulation of the loader's sibling initialization order.
    ordering, visiting, visited = [], set(), set()
    def visit(item):
        name = item['soname']
        if name in visiting:
            reject('SELECTED_DEPENDENCY_CYCLE', item['path'], name)
        if name in visited:
            return
        visiting.add(name)
        for dependency in item['needed']:
            if dependency in selected_sonames:
                visit(providers[dependency])
        visiting.remove(name)
        visited.add(name)
        ordering.append(name)
    dependencies = executable['needed']
    if executable.get('preserve_selected_lifecycle'):
        dependencies = list(reversed(dependencies))
    for dependency in dependencies:
        if dependency in selected_sonames:
            visit(providers[dependency])
    if len(visited) != len(selected):
        reject('UNREACHABLE_SELECTED_LIBRARY', executable['path'], str(selected_sonames - visited))
    return ordering


def preserve_selected_lifecycle(module, item, priority):
    """Keep callback code/data, exposing fini arrays to one static dispatcher.

    Library constructors originally register atexit handlers before libc
    registers the loader finalizer. Folding constructors into the executable
    reverses that timing. The dispatcher is therefore registered after the
    selected constructors and before executable constructors; it invokes the
    original executable/library fini arrays, including per-DSO cxa_finalize.
    """
    selected = item['role'] == 'selected'
    namespace = '__teapot_lifecycle_' + content_key([item['role'], item['soname']])
    if any(s.name.startswith('__teapot_lifecycle_') for s in module.symbols):
        reject('RESERVED_LIFECYCLE_SYMBOL', item['path'], 'input uses reconstruction namespace')
    properties = module.aux_data.get('sectionProperties', module.aux_data.get('elfSectionProperties'))
    if properties is None:
        reject('MISSING_SECTION_PROPERTIES', item['path'], 'cannot preserve callback section types')
    info = module.aux_data['elfSymbolInfo'].data
    result = {'role': item['role'], 'soname': item['soname'], 'fini_array': None, 'fini': None}
    for section in list(module.sections):
        if section.name == '.fini_array':
            intervals = list(section.byte_intervals)
            if len(intervals) != 1:
                reject('SPLIT_FINI_ARRAY', item['path'], 'one contiguous callback array required')
            interval = intervals[0]
            blocks = sorted((b for b in interval.blocks if isinstance(b, gtirb.DataBlock)),
                            key=lambda b: b.offset)
            end = 0
            for block in blocks:
                if block.offset != end:
                    reject('UNRECOVERED_FINI_ARRAY', item['path'], 'callback bytes have a gap/overlap')
                end += block.size
            if not blocks or end != interval.size or end % 8:
                reject('UNRECOVERED_FINI_ARRAY', item['path'], 'incomplete callback array')
            section.name = '.data.' + namespace + '_fini_array'
            properties.data[section] = (1, 3)  # ordinary pointer data, not automatic ELF callbacks
            bounds = []
            for suffix, block, at_end in (('begin', blocks[0], False), ('end', blocks[-1], True)):
                symbol = gtirb.Symbol(name=namespace + '_fini_' + suffix,
                                      payload=block, at_end=at_end, module=module)
                info[symbol] = (0, 'NOTYPE', 'GLOBAL', 'HIDDEN', 0)
                bounds.append(symbol.name)
            result['fini_array'] = bounds
        elif selected and section.name == '.init_array':
            section.name += '.{:05d}'.format(priority * 2 + 1)
        elif selected and section.name in ('.init', '.fini'):
            section.name = '.text.' + namespace + section.name
    if not selected:
        # Executable DT_FINI is still the byte-validated inert CRT stub. It
        # stays under libc/rtld ownership; only its nontrivial array is moved.
        return result
    for tag, aux_name, array, section_type in (
            ('DT_INIT', 'elfDynamicInit', '.init_array', 14),
            ('DT_FINI', 'elfDynamicFini', '.fini_array', 15)):
        address = item['lifecycle'].get(tag)
        # The pinned Linux/glibc RISC-V ABI uses only callback arrays;
        # ELF_INITFINI=0 means DT_INIT/DT_FINI are not invoked by its loader.
        if address is None or item.get('machine') == 'EM_RISCV':
            continue
        aux = module.aux_data.get(aux_name)
        block = aux.data if aux is not None else None
        if not isinstance(block, gtirb.CodeBlock) or block.address != address:
            reject('UNRECOVERED_' + tag, item['path'], hex(address))
        symbol = gtirb.Symbol(name=namespace + '_' + tag,
                              payload=block, module=module)
        info[symbol] = (0, 'FUNC', 'GLOBAL', 'HIDDEN', 0)
        if tag == 'DT_FINI':
            result['fini'] = symbol.name
            continue
        flags = {gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Readable,
                 gtirb.Section.Flag.Writable, gtirb.Section.Flag.Initialized}
        section = gtirb.Section(name=array + '.{:05d}'.format(priority * 2), flags=flags, module=module)
        properties.data[section] = (section_type, 3)
        interval = gtirb.ByteInterval(contents=bytes(8), section=section)
        pointer = gtirb.DataBlock(size=8, byte_interval=interval)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, symbol)
        module.aux_data['symbolicExpressionSizes'].data[gtirb.Offset(interval, 0)] = 8
        module.aux_data['alignment'].data[pointer] = 8
    module.aux_data.pop('elfDynamicInit', None)
    module.aux_data.pop('elfDynamicFini', None)
    return result


def localize_private_library_definitions(module, item):
    """Only actual DSO exports may bind references from other archive members.

    Frontend-inferred ABI anchors (e.g. a forwarded relocation-range label)
    are private to the recovered input, even if inference marked them GLOBAL.
    Do not export these new labels or let them collide with another module.
    Undefined references keep their original binding, including WEAK.
    """
    exports = {symbol['name'] for symbol in item['symbols']
               if symbol['section'] != 'SHN_UNDEF' and symbol['binding'] != 'STB_LOCAL'
               and symbol['visibility'] == 'STV_DEFAULT'}
    info = module.aux_data['elfSymbolInfo'].data
    for symbol, row in list(info.items()):
        if (symbol.name not in exports and row[2] in ('GLOBAL', 'WEAK') and
                (isinstance(symbol.referent, (gtirb.CodeBlock, gtirb.DataBlock)) or symbol.value is not None)):
            info[symbol] = row[:2] + ('LOCAL',) + row[3:]


def bind_executable_interpositions(module, item):
    """Keep the DSO body local, but bind its loader-owned GOT/PLT uses to main."""
    names = item.get('executable_interpositions', ())
    if not names:
        return
    info = module.aux_data['elfSymbolInfo'].data
    forwarding = module.aux_data.get('symbolForwarding')
    forwarding = forwarding.data if forwarding else {}
    bindings = {}
    for name in names:
        named = list(module.symbols_named(name))
        symbols = [s for s in named
                   if isinstance(s.referent, (gtirb.CodeBlock, gtirb.DataBlock))]
        imports = [s for s in named if isinstance(s.referent, gtirb.ProxyBlock)]
        if len(symbols) != 1 or len(imports) > 1:
            reject('UNRECOVERED_INTERPOSITION', item['path'], name)
        local = symbols[0]
        row = info[local]
        local_name = '.L__component_interposed_' + name
        if list(module.symbols_named(local_name)):
            reject('UNRECOVERED_INTERPOSITION', item['path'], local_name)
        local.name = local_name
        info[local] = row[:2] + ('LOCAL',) + row[3:]
        target = imports[0] if imports else gtirb.Symbol(
            name, payload=gtirb.ProxyBlock(module=module), module=module)
        info[target] = (0, row[1], 'GLOBAL', 'DEFAULT', 0)
        bindings[name] = (local, target)
    for source, target in list(forwarding.items()):
        for local, main in bindings.values():
            if target is local:
                forwarding[source] = main
    # Forwarding handles code references to the GOT/PLT. Rewrite the matching
    # dynamic-relocation slots too; direct local references remain untouched.
    with Path(item['path']).open('rb') as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            table = elf.get_section(section['sh_link'])
            if table['sh_type'] != 'SHT_DYNSYM':
                continue
            for relocation in section.iter_relocations():
                name = table.get_symbol(relocation['r_info_sym']).name
                if name not in bindings:
                    continue
                address = relocation['r_offset']
                intervals = list(module.byte_intervals_on(address))
                if len(intervals) != 1:
                    reject('UNRECOVERED_INTERPOSITION', item['path'], hex(address))
                interval = intervals[0]
                offset = address - interval.address
                expression = interval.symbolic_expressions.get(offset)
                local, target = bindings[name]
                if (not isinstance(expression, gtirb.SymAddrConst) or
                        expression.symbol not in (local, target)):
                    reject('UNRECOVERED_INTERPOSITION', item['path'], hex(address))
                interval.symbolic_expressions[offset] = gtirb.SymAddrConst(
                    expression.offset, target, expression.attributes)


def external_load_order(executable, selected, external):
    """Retain the original breadth-first ELF dependency lookup scope."""
    providers = {item['soname']: item for item in selected + external}
    pending, seen, result = list(executable['needed']), set(), []
    for name in pending:
        if name in seen:
            continue
        seen.add(name)
        provider = providers[name]
        if provider['role'] == 'external':
            result.append(provider)
        pending.extend(provider['needed'])
    return result


def build_lifecycle_dispatcher(args, main_object, objects, initialization_order):
    """A normal ET_REL adapter, linked into the executable before rewriting."""
    descriptors = [json.loads((obj.parent / 'lifecycle.json').read_text()) for obj in objects]
    by_name = {entry['soname']: entry for entry in descriptors}
    ordered = [json.loads((main_object.parent / 'lifecycle.json').read_text())]
    ordered += [by_name[name] for name in reversed(initialization_order)]
    declarations, calls = [], []
    for entry in ordered:
        if entry['fini_array']:
            begin, end = entry['fini_array']
            declarations.append('extern fini_fn %s[], %s[];' % (begin, end))
            calls.append('for (fini_fn *p = %s; p != %s;) (*--p)();' % (end, begin))
        if entry['fini']:
            declarations.append('extern void %s(void);' % entry['fini'])
            calls.append('%s();' % entry['fini'])
    source = args.out / 'lifecycle.c'
    source.write_text('\n'.join([
        'typedef void (*fini_fn)(void);',
        'extern int __cxa_atexit(void (*)(void *), void *, void *);',
        'extern void abort(void);', *declarations,
        'static void finish(void *unused) { (void)unused;', *calls, '}',
        'static void register_finish(void) { if (__cxa_atexit(finish, 0, 0)) abort(); }',
        '__attribute__((used, section(".init_array.65534")))',
        'static fini_fn const register_finish_callback = register_finish;', '']))
    obj = args.out / 'lifecycle.o'
    run(args.out, 'compile-lifecycle', [args.cc, '-c', '-O2', '-fno-pie', '-fno-pic',
                                      '-fno-stack-protector', source, '-o', obj])
    dump(args.out / 'lifecycle.json', {'initialization_order': initialization_order,
                                     'finalization': ordered, 'adapter_sha256': sha(obj)})
    return obj


def preserve_executable_data_blocks(module):
    """Carry recovered in-text data boundaries through the ordinary ELF link.

    A later fresh lift must not invent instructions in bytes already recovered
    as data. A .byte directive alone carries no such information in an ELF;
    local sized OBJECT symbols do. This changes metadata, not bytes or linkage.
    Keep each block separate so alignment between blocks cannot inflate a size.
    """
    info = module.aux_data['elfSymbolInfo'].data
    names = {s.name for s in module.symbols}
    evidence = []
    for section in sorted(module.sections, key=lambda s: (s.address or 0, s.name)):
        if gtirb.Section.Flag.Executable not in section.flags:
            continue
        for block in sorted(section.data_blocks, key=lambda b: (b.address or 0, b.size)):
            if not block.size:
                continue
            if block.address is None or any(module.code_blocks_on(
                    range(block.address, block.address + block.size))):
                reject('AMBIGUOUS_RECOVERED_DATA', module.name,
                       'in-text data has no address or overlaps code')
            name = '__teapot_recovered_data_{:x}'.format(block.address)
            suffix = 0
            while name in names:
                suffix += 1
                name = '__teapot_recovered_data_{:x}_{}'.format(block.address, suffix)
            names.add(name)
            symbol = gtirb.Symbol(name, payload=block, module=module)
            info[symbol] = (block.size, 'OBJECT', 'LOCAL', 'DEFAULT', 0)
            evidence.append({'name': name, 'address': block.address, 'size': block.size,
                             'section': section.name})
    return evidence


def align_executable_preinit_array(module, item):
    """Print the retained RV CRT preinit pointer naturally aligned.

    rv_preinit accepts a crt1.o whose .preinit_array declares alignment 1, and
    the lift then records alignment 1, so a later link could place the 8-byte
    entry the loader reads unaligned. Record its real alignment instead.
    """
    if item['role'] != 'executable' or not item.get('preinit_contract'):
        return 0
    if 'alignment' not in module.aux_data:
        reject('MISSING_ALIGNMENT', item['path'], 'fresh frontend alignment table required')
    table = module.aux_data['alignment'].data
    blocks = [block for section in module.sections if section.name == '.preinit_array'
              for block in section.data_blocks if block.size]
    if len(blocks) != 1 or blocks[0].size != 8:
        reject('UNSUPPORTED_CRT_CALLBACK_BODY', item['path'], 'retained preinit array is not one 8-byte block')
    table[blocks[0]] = max(table.get(blocks[0], 1), 8)
    return 1


def ordinary_object_recipe(item, context, priority=None):
    """Describe reconstruction inputs, not unrelated final executable bytes.

    Every invocation still validates its complete ELF binding closure before
    looking up an object. An ordinary selected-library object is reconstructed
    only from that library's ELF, the tools and startup placement: it contains
    symbolic references, not caller-resolved code or instrumentation plans.
    Retain dependency contents/order and initialization order conservatively.
    This exemption does NOT apply to resolved instrumented-object caches.
    """
    context = dict(context)
    if type(context.get('allow_ambiguous_data_pointers')) is not bool:
        reject('FRONTEND_POLICY', item['path'], 'ordinary cache context needs an explicit boolean policy')
    if item['role'] == 'selected':
        context.pop('executable', None)
    if item.get('riscv_profile') == 'lp64-pure':
        context.update(pure_cache_identity())
    return {'format': 3, 'stage': 'ordinary-et-rel', 'context': context,
            'input_sha256': item['sha256'], 'role': item['role'],
            'executable_interpositions': sorted(item.get('executable_interpositions', ())),
            'module_basename': Path(item['path']).name, 'array_priority': priority,
            'printing_policy': 'complete', 'shared': False}


def recovered_ir_recipe(item, args):
    recipe = {'format': 2, 'stage': 'recovered-ir', 'frontend': args.tool_identities['ddisasm'],
              'input_sha256': item['sha256'], 'module_basename': Path(item['path']).name,
              'frontend_source_provenance': args.source_provenance_data, 'jobs': args.jobs,
              'allow_ambiguous_data_pointers': args.allow_ambiguous_data_pointers}
    if item.get('riscv_profile') == 'lp64-pure':
        recipe.update(pure_cache_identity())
    return recipe


def reconstruct(item, args, out, index=0, priority=None):
    directory = out / ('executable' if item['role'] == 'executable' else 'selected-{:03d}'.format(index))
    directory.mkdir()
    object_recipe = ordinary_object_recipe(item, args.cache_context, priority)
    lift_recipe = recovered_ir_recipe(item, args)
    if args.cache_context['allow_ambiguous_data_pointers'] is not args.allow_ambiguous_data_pointers:
        reject('FRONTEND_POLICY', item['path'], 'request/cache policy mismatch')
    if args.cache and args.cache.restore('objects', object_recipe, directory):
        ir = gtirb.IR.load_protobuf(directory / 'lift.gtirb')
        if len(ir.modules) != 1:
            reject('MULTIMODULE_INPUT', item['path'], 'one module per ELF required')
        record_frontend_diagnostics(ir.modules[0], item, directory,
                                    args.allow_ambiguous_data_pointers, verify=True)
        dump(directory / 'cache.json', {'object': 'hit', 'object_key': content_key(object_recipe),
            'lift_key': content_key(lift_recipe), 'lift': 'included-in-object-hit', 'instrumented': False,
            'allow_ambiguous_data_pointers': args.allow_ambiguous_data_pointers,
            'frontend_diagnostics_sha256': sha(directory / 'frontend-diagnostics.json')})
        return directory / 'reconstructed.o'
    irpath = directory / 'lift.gtirb'
    lift_hit = args.cache is not None and args.cache.restore('ir', lift_recipe, directory)
    if not lift_hit:
        run(directory, 'lift', frontend_argv(args, item, irpath))
    ir = gtirb.IR.load_protobuf(irpath)
    if len(ir.modules) != 1:
        reject('MULTIMODULE_INPUT', item['path'], 'one module per ELF required')
    module = ir.modules[0]
    validate_copy_forwarding(module, item)
    # This standalone converter reconstructs uninstrumented ELF only. It does
    # not own the adaptive RV assembler-option preparation stage; refuse an
    # already-instrumented input rather than silently dropping that contract.
    if ("teapotFaultRiscAssemblyScopes" in module.aux_data or
            any(symbol.name.startswith("__teapot_fault_rv_scope_") for symbol in module.symbols)):
        reject('INSTRUMENTED_RV_FAULT_INPUT', item['path'],
               'use the component rewrite driver or teapot.fault_risc_assembly with matching instrumented IR')
    record_frontend_diagnostics(module, item, directory, args.allow_ambiguous_data_pointers,
                                verify=lift_hit)
    cfi = module.aux_data.get('cfiDirectives')
    starts = set()
    if cfi:
        for offset, directives in cfi.data.items():
            if any(d[0] == '.cfi_startproc' for d in directives):
                starts.add(offset.element_id.address + offset.displacement)
    for fde in item['application_fdes']:
        if fde['start'] not in starts:
            reject('UNRECOVERED_UNWIND_RANGE', item['path'], hex(fde['start']))
    liveness = module.aux_data.get('liveRegisterSets')
    if liveness is None or 'liveRegisterNames' not in module.aux_data:
        reject('MISSING_FRONTEND_LIVENESS', item['path'], 'fresh frontend tables required')
    if args.cache and not lift_hit:
        args.cache.store('ir', lift_recipe, directory,
                         ['lift.gtirb', 'lift', 'frontend-diagnostics.json', 'proven-data-decoder-warnings.json'])
    summary = {'isa': str(module.isa), 'code_blocks': len(list(module.code_blocks)),
               'data_blocks': len(list(module.data_blocks)),
               'live_register_entries': len(liveness.data), 'cfi_starts': len(starts),
               'application_fdes_checked': len(item['application_fdes']),
               'allow_ambiguous_data_pointers': args.allow_ambiguous_data_pointers,
               'frontend_diagnostics_sha256': sha(directory / 'frontend-diagnostics.json')}
    dump(directory / 'ir-summary.json', summary)
    print_ir = irpath
    if item['role'] == 'selected':
        localize_private_library_definitions(module, item)
        bind_executable_interpositions(module, item)
    preinit_aligned = align_executable_preinit_array(module, item)
    data_metadata = preserve_executable_data_blocks(module)
    dump(directory / 'recovered-data-metadata.json', data_metadata)
    version_bindings = (resolve_selected_symbol_versions(module, item, args.selected_sonames)
                        if args.resolve_selected_versions else [])
    dump(directory / 'selected-version-bindings.json', version_bindings)
    if args.preserve_selected_lifecycle:
        lifecycle = preserve_selected_lifecycle(module, item, priority)
        dump(directory / 'lifecycle.json', lifecycle)
    elif item['role'] == 'selected':
        # Keep library CRT callback bodies and their per-DSO __dso_handle.
        # Only the byte-validated, inert DT_INIT/DT_FINI stubs are excluded.
        # Array section priorities respect selected dependency startup order;
        # fini arrays are traversed in reverse by the process startup code.
        for section in module.sections:
            if section.name in ('.init_array', '.fini_array'):
                section.name += '.{:05d}'.format(priority)
        module.aux_data.pop('elfDynamicInit', None)
        module.aux_data.pop('elfDynamicFini', None)
    if (item['role'] == 'selected' or version_bindings or args.preserve_selected_lifecycle or data_metadata
            or preinit_aligned):
        print_ir = directory / 'relocatable.gtirb'
        save_protobuf_ordered(ir, print_ir)
    assembly = directory / 'reconstructed.S'
    print_command = [args.pprinter, '--ir', print_ir, '--asm', assembly,
                     '--policy', 'complete', '--shared', 'no']
    if item['role'] == 'selected' and not args.preserve_selected_lifecycle:
        print_command += ['--skip-section', '.init', '.fini']
    run(directory, 'print', print_command)
    # No replacement/stripping of GOT, PLT, .symver or CFI assembly is allowed.
    obj = directory / 'reconstructed.o'
    run(directory, 'assemble', [args.cc, '-c', '-o', obj, assembly])
    with obj.open('rb') as stream:
        elf = ELFFile(stream)
        if elf['e_type'] != 'ET_REL' or elf['e_machine'] != item['machine']:
            raise RuntimeError('assembler did not create expected ET_REL')
        if item['machine'] == 'EM_RISCV':
            if item.get('riscv_profile') == 'lp64-pure':
                from teapot.riscv_profile import validate_flags
                try:
                    validate_flags(elf['e_flags'], 'lp64-pure')
                except ValueError as error:
                    reject('ASSEMBLED_ABI_MISMATCH', item['path'], str(error))
            elif elf['e_flags'] & 6 != 4 or elf['e_flags'] & ~5:
                reject('ASSEMBLED_ABI_MISMATCH', item['path'], 'RV64 object must retain LP64D ABI')
        table = elf.get_section_by_name('.symtab')
        emitted = {s.name: s for s in table.iter_symbols() if s['st_shndx'] != 'SHN_UNDEF'}
        for symbol in item['symbols']:
            if (symbol['section'] == 'SHN_UNDEF' or symbol['binding'] == 'STB_LOCAL' or
                    version_node_symbol(item, symbol) or
                    symbol['name'] in item.get('executable_interpositions', ())):
                continue
            expected = reconstructed_symbol_name(symbol, item)
            if expected not in emitted:
                reject('MISSING_RECONSTRUCTED_EXPORT', item['path'], expected)
        reconstructed_fdes = sum(isinstance(e, FDE) for e in eh_cfi_entries(elf, obj))
        if reconstructed_fdes < len(item['application_fdes']):
            reject('MISSING_RECONSTRUCTED_UNWIND', item['path'], str(reconstructed_fdes))
        summary.update({'elf_type': elf['e_type'], 'object_sha256': sha(obj),
                        'reconstructed_fdes': reconstructed_fdes,
                        'assembly_sha256': sha(assembly), 'ir_sha256': sha(irpath)})
    dump(directory / 'object-summary.json', summary)
    if args.cache:
        args.cache.store('objects', object_recipe, directory,
                         [p.name for p in directory.iterdir()])
    dump(directory / 'cache.json', {'object': 'miss' if args.cache else 'disabled',
        'object_key': content_key(object_recipe), 'lift_key': content_key(lift_recipe),
        'lift': 'hit' if lift_hit else ('miss' if args.cache else 'disabled'), 'instrumented': False,
        'allow_ambiguous_data_pointers': args.allow_ambiguous_data_pointers,
        'frontend_diagnostics_sha256': sha(directory / 'frontend-diagnostics.json')})
    return obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', required=True, type=Path)
    parser.add_argument('--riscv-profile', choices=('lp64d', 'lp64-pure'), default='lp64d')
    parser.add_argument('--select', action='append', default=[], type=Path)
    parser.add_argument('--external', action='append', default=[], type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ddisasm', required=True)
    parser.add_argument('--pprinter', required=True)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--ar', default='ar')
    parser.add_argument('--linker', default='ld',
                        help='linker command, shlex parsed without a shell')
    parser.add_argument('--cache-dir', type=Path,
                        help='cache ordinary recovered IR/ET_REL, never instrumentation')
    parser.add_argument('--resolve-selected-versions', action='store_true',
                        help='preserve and resolve selected-library ELF symbol versions at final link')
    parser.add_argument('--preserve-selected-lifecycle', action='store_true',
                        help='retain custom selected init/fini code, callback arrays and exit registration')
    parser.add_argument('--preserve-nonlocal-jumps', action='store_true',
                        help='retain ordinary libc setjmp/longjmp calls and saved continuations')
    parser.add_argument('--preserve-weak-imports', action='store_true',
                        help='retain undefined weak bindings and the pinned original external lookup scope')
    parser.add_argument('--allow-ambiguous-data-pointers', action='store_true', default=False,
                        help='explicitly allow unproven heuristic data-pointer guesses; warn and retain diagnostics')
    parser.add_argument('--source-provenance', default='{}',
                        help='JSON source revisions/patch hashes captured by the trusted launcher')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8:
        parser.error('--jobs must be 1..8')
    args.out.mkdir(parents=True, exist_ok=False)
    if 'TEAPOT_CONTAINER_ARGV' in os.environ:
        dump(args.out / 'container.command.json', json.loads(os.environ['TEAPOT_CONTAINER_ARGV']))
    try:
        executable = inspect(args.executable, 'executable', args.resolve_selected_versions,
                             args.preserve_selected_lifecycle, args.preserve_nonlocal_jumps,
                             args.preserve_weak_imports, riscv_profile=args.riscv_profile)
        architecture = ARCHITECTURES[executable['machine']]
        if args.riscv_profile == 'lp64-pure':
            from teapot.riscv_profile import INTERPRETERS, validate_compiler
            architecture = dict(architecture, interpreter=INTERPRETERS[args.riscv_profile])
            with pure_refusal(args.cc):
                dump(args.out / 'riscv-compiler.json', validate_compiler(args.cc))
        selected = [inspect(path, 'selected', args.resolve_selected_versions,
                            args.preserve_selected_lifecycle, args.preserve_nonlocal_jumps,
                            args.preserve_weak_imports, riscv_profile=args.riscv_profile) for path in args.select]
        args.selected_sonames = {item['soname'] for item in selected}
        external = [inspect(path, 'external', riscv_profile=args.riscv_profile) for path in args.external]
        initialization_order = validate_closure(executable, selected, external)
        linked_external = external_load_order(executable, selected, external) if args.preserve_weak_imports else external
        args.source_provenance_data = json.loads(args.source_provenance)
        args.tool_identities = {name: native_tool_identity(getattr(args, name))
                                for name in ('ddisasm', 'pprinter', 'cc', 'ar')}
        args.tool_identities['as'] = native_tool_identity(subprocess.check_output(
            [args.cc, '-print-prog-name=as'], text=True).strip())
        args.tool_identities['cc1'] = native_tool_identity(subprocess.check_output(
            [args.cc, '-print-prog-name=cc1'], text=True).strip())
        args.tool_identities['linker_arguments'] = shlex.split(args.linker)
        args.tool_identities['linker_files'] = {token: sha(token) for token in shlex.split(args.linker)
                                               if Path(token).is_file()}
        args.cache_context = {'contract': CONTRACT, 'converter_sha256': sha(__file__),
            'machine': executable['machine'],
            'architecture': {key: sorted(value) if isinstance(value, set) else value
                             for key, value in architecture.items()},
            'tools': args.tool_identities, 'python': python_identity(),
            'source_provenance': args.source_provenance_data,
            'resolve_selected_versions': args.resolve_selected_versions,
            'preserve_selected_lifecycle': args.preserve_selected_lifecycle,
            'preserve_nonlocal_jumps': args.preserve_nonlocal_jumps,
            'preserve_weak_imports': args.preserve_weak_imports,
            'allow_ambiguous_data_pointers': args.allow_ambiguous_data_pointers,
            'executable': executable['sha256'],
            'selected_order': [(i['soname'], i['sha256']) for i in selected],
            'external_order': [(i['soname'], i['sha256']) for i in external],
            'initialization_order': initialization_order,
            'instrumentation': None, 'runtime_layout': None}
        if args.riscv_profile == 'lp64-pure':
            args.cache_context.update(pure_cache_identity())
        # JSON canonicalization removes tuple/list distinctions on later cache reads.
        args.cache_context = json.loads(json.dumps(args.cache_context))
        args.cache = ArtifactCache(args.cache_dir) if args.cache_dir else None
        manifest = {'contract': CONTRACT, 'script_sha256': sha(__file__),
                    'allow_ambiguous_data_pointers': args.allow_ambiguous_data_pointers,
                    'pointer_inference': 'unproven heuristic' if args.allow_ambiguous_data_pointers else 'strict',
                    'executable': executable, 'selected': selected, 'external': external,
                    'selected_dependency_order': [item['soname'] for item in selected],
                    'selected_initialization_order': initialization_order,
                    'linked_external_order': [item['soname'] for item in linked_external],
                    'tools': args.tool_identities, 'cache_context': args.cache_context,
                    'assumptions': ['single thread', 'no LD_PRELOAD/LD_AUDIT/interposers',
                                    'no alternate runtime symbol lookup',
                                    'validated ' + architecture['name'] + ' glibc process startup',
                                    'no hot-swapped dependency providers'],
                    'instrumentation': 'none; ordinary reconstruction only'}
        dump(args.out / 'manifest.json', manifest)
        main_object = reconstruct(executable, args, args.out)
        objects = [reconstruct(item, args, args.out, index,
                               100 + initialization_order.index(item['soname']))
                   for index, item in enumerate(selected)]
        lifecycle_objects = ([build_lifecycle_dispatcher(args, main_object, objects, initialization_order)]
                             if args.preserve_selected_lifecycle else [])
        archive = args.out / 'selected.a'
        # Distinct member filenames avoid ar silently replacing same-basename
        # members. This archive contains only newly reconstructed ET_REL bytes.
        members = []
        for index, obj in enumerate(objects):
            member = args.out / ('selected-{:03d}.o'.format(index))
            member.write_bytes(obj.read_bytes())
            members.append(member)
        run(args.out, 'archive', [args.ar, 'rcsD', archive] + members)
        run(args.out, 'archive-members', [args.ar, 't', archive])
        output = args.out / 'monolith'
        # The input CRT's .option norelax is not represented by instruction
        # bytes. Without this, the linker may turn load_gp's AUIPC/ADDI pair
        # into mv gp,gp, assuming the very GP value this code must initialize.
        link_policy = ['--no-relax'] if executable['machine'] == 'EM_RISCV' else []
        if args.riscv_profile == 'lp64-pure':
            link_policy += ['-z', 'separate-code']
        run(args.out, 'link', shlex.split(args.linker) + link_policy + [
            '-m', architecture['emulation'], '--dynamic-linker', architecture['interpreter'],
            '--eh-frame-hdr', '--build-id=sha1', '--emit-relocs', '-z', 'noexecstack',
            '-Map=' + str(args.out / 'link.map'), '-o', output, main_object, *lifecycle_objects,
            '--whole-archive', archive, '--no-whole-archive',
            '--no-as-needed' if args.preserve_weak_imports else '--as-needed']
            + [item['path'] for item in linked_external])
        with output.open('rb') as stream:
            elf = ELFFile(stream)
            if elf['e_type'] != 'ET_EXEC' or elf['e_machine'] != executable['machine']:
                raise RuntimeError('output is not the expected architecture/non-PIE ET_EXEC')
            validate_linked_copies(elf, executable)
            if executable['machine'] == 'EM_RISCV':
                validate_linked_riscv_startup(elf, output)
        if args.riscv_profile == 'lp64-pure':
            check_pure_final(output, args.cc)
        with output.open('rb') as stream:
            elf = ELFFile(stream)
            needed = [t.needed for t in elf.get_section_by_name('.dynamic').iter_tags()
                      if t.entry.d_tag == 'DT_NEEDED']
            selected_names = {item['soname'] for item in selected}
            if selected_names.intersection(needed):
                raise RuntimeError('selected library still dynamically needed')
            table = elf.get_section_by_name('.symtab')
            defined = {s.name for s in table.iter_symbols()
                       if isinstance(s['st_shndx'], int)}
            for item in selected:
                for symbol in item['symbols']:
                    if symbol['section'] != 'SHN_UNDEF' and not version_node_symbol(item, symbol):
                        expected = reconstructed_symbol_name(symbol, item)
                        if expected not in defined:
                            raise RuntimeError('missing selected body/data: ' + expected)
            dump(args.out / 'result.json', {'status': 'ordinary_link_ready_not_yet_behavior_verified',
                'allow_ambiguous_data_pointers': args.allow_ambiguous_data_pointers,
                'pointer_inference': 'unproven heuristic' if args.allow_ambiguous_data_pointers else 'strict',
                'elf_type': elf['e_type'], 'needed': needed,
                'monolith_sha256': sha(output), 'archive_sha256': sha(archive),
                'archive_members': [{'name': p.name, 'sha256': sha(p), 'type': 'ET_REL'} for p in members]})
    except Unsupported as error:
        dump(args.out / 'rejection.json', {'status': 'unsupported', 'reason': str(error),
                                         'allow_ambiguous_data_pointers': args.allow_ambiguous_data_pointers})
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
