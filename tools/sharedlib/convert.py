#!/usr/bin/env python3
"""Fail-closed ELF64 selected-DSO to ET_REL/ET_EXEC research prototype.

Run in an isolated container exposing only this script, the ELF inputs, the
pinned toolchain, the explicitly selected external ELF dependencies and output.
No source/original object/archive is accepted. Assembly is never text-filtered.
"""
import argparse
from collections import Counter
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


CONTRACT = 'teapot-selected-elf64-v2'
LOOKUP = {'dlopen', 'dlmopen', 'dlsym', 'dlvsym', 'dlclose', 'dlinfo',
          'dl_iterate_phdr', '__libc_dlopen_mode'}
UNWIND_UNSUPPORTED = {'__cxa_throw', '__cxa_rethrow', '__cxa_atexit',
                      '_Unwind_Resume', 'longjmp', 'siglongjmp', '__longjmp_chk'}
CRT_WEAK = {'__gmon_start__', '_ITM_registerTMCloneTable',
            '_ITM_deregisterTMCloneTable', '__cxa_finalize'}
RELOCS_X64 = {1, 6, 7, 8}  # 64, GLOB_DAT, JUMP_SLOT, RELATIVE; COPY is excluded.
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


def sha(path):
    with Path(path).open('rb') as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


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
            pac = self.read(address, 4) == 0xd503233f
            expected_size = (5 if is_init else 4) * 4 + (8 if pac else 0)
            self.check(size == expected_size, 'unrecognized ' + section.name + ' size')
            pc = address + (4 if pac else 0)
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

    def rv_preinit(self, section, static, allow_call_pair=False):
        # glibc's RV executable CRT initializes GP before dependency constructors
        # and again at _start. Retain this array and its real callback; dropping
        # it would change the process-wide GP contract for selected libraries.
        self.check(section is not None and section['sh_size'] == 8 and
                   section['sh_type'] == 'SHT_PREINIT_ARRAY' and
                   section['sh_entsize'] == 8 and section['sh_flags'] == 3 and
                   section['sh_addralign'] >= 8,
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
        if self.read(address, 2) & 3 == 3:
            self.rv_jal(address, self.address('register_tm_clones'), register=0)
        else:
            word = self.word(address, 0xa001, 0xe003, size=2)
            immediate = (((word >> 12) & 1) << 11) | (((word >> 11) & 1) << 4) | \
                        (((word >> 9) & 3) << 8) | (((word >> 8) & 1) << 10) | \
                        (((word >> 7) & 1) << 6) | (((word >> 6) & 1) << 7) | \
                        (((word >> 3) & 7) << 1) | (((word >> 2) & 1) << 5)
            self.named(address + signed(immediate, 12), 'register_tm_clones')
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


def validate_frontend_diagnostics(module, item, diagnostics):
    """Distinguish failed candidate decodes of proven data from lost instructions.

    Arm64Loader tries each word in executable sections before code inference.
    Its CIMM message is immediately followed by the addressed type-64 message;
    that exact pair can share the same evidence. All other warnings still fail.
    """
    lines = diagnostics.splitlines()
    accepted = []
    pattern = r'WARNING: unhandled operand at (\d+), op type:(\d+)'
    for index, line in enumerate(lines):
        if 'ERROR' in line:
            reject('FRONTEND_DIAGNOSTIC', item['path'], line.strip())
        if 'WARNING' not in line:
            continue
        message = line[line.index('WARNING'):].strip()
        if (item['role'] == 'selected' and item['entry'] == 0 and
                message == 'WARNING: Failed to set module entry point.'):
            continue
        match = re.fullmatch(pattern, message)
        if message == 'WARNING: unsupported CIMM operand' and index + 1 < len(lines):
            following = re.fullmatch(pattern, lines[index + 1].strip())
            if following and following[2] == '64':
                match = following
        if match:
            proof = frontend_data_warning_proof(module, item, int(match[1]))
            if proof is not None:
                accepted.append(dict(proof, diagnostic=message, operand_type=int(match[2])))
                continue
        reject('FRONTEND_DIAGNOSTIC', item['path'], line.strip())
    return accepted


def inspect(path, role):
    path = Path(path)
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        machine = elf['e_machine']
        if elf.elfclass != 64 or not elf.little_endian or machine not in ARCHITECTURES:
            reject('UNSUPPORTED_ARCH', path, 'only little-endian x64/AArch64/RV64 ELF64 is implemented')
        architecture = ARCHITECTURES[machine]
        rv_executable = machine == 'EM_RISCV' and role == 'executable'
        flags = elf['e_flags']
        if (machine == 'EM_RISCV' and (flags & ~5 or flags & 6 != 4)) or \
                (machine != 'EM_RISCV' and flags != 0):
            reject('UNSUPPORTED_ABI_FLAGS', path, 'requires normal ELF64 ABI, RV64 LP64D with optional RVC')
        expected = 'ET_EXEC' if role == 'executable' else 'ET_DYN'
        if elf['e_type'] != expected:
            reject('UNSUPPORTED_ELF_TYPE', path, '{} requires {}'.format(role, expected))
        dynsym = elf.get_section_by_name('.dynsym')
        dynamic = elf.get_section_by_name('.dynamic')
        if dynsym is None or dynamic is None:
            reject('MISSING_DYNAMIC_METADATA', path, 'dynamic symbol/loader tables required')
        symbols = [sym_record(s) for s in dynsym.iter_symbols() if s.name]
        symtab = elf.get_section_by_name('.symtab')
        static = [sym_record(s) for s in symtab.iter_symbols() if s.name] if symtab else []
        tags = list(dynamic.iter_tags())
        needed = [t.needed for t in tags if t.entry.d_tag == 'DT_NEEDED']
        sonames = [t.soname for t in tags if t.entry.d_tag == 'DT_SONAME']
        result = {'path': str(path), 'sha256': sha(path), 'role': role,
                  'machine': machine, 'architecture': architecture['name'], 'elf_flags': flags,
                  'needed': needed, 'soname': sonames[0] if sonames else None,
                  'symbols': symbols, 'entry': elf['e_entry'], 'fde_count': 0,
                  'application_fdes': [], 'relocation_types': {}, 'versions': []}
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
        if all_names & UNWIND_UNSUPPORTED:
            reject('NONLOCAL_UNWIND', path, ', '.join(sorted(all_names & UNWIND_UNSUPPORTED)))
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
            if sec.name == '.gnu.version_d' and sec['sh_size']:
                reject('SELECTED_SYMBOL_VERSION_DEFINITION', path, sec.name)
            if sec.name == '.gnu.version_r':
                for version, auxiliaries in sec.iter_versions():
                    result['versions'].append({'library': version.name,
                                              'versions': [v.name for v in auxiliaries]})
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
                if not crt_data_alias and (symbol['section'] != 'SHN_UNDEF' or symbol['name'].split('@')[0] not in CRT_WEAK):
                    reject('WEAK_BINDING', path, symbol['name'])
            if symbol['visibility'] not in ('STV_DEFAULT', 'STV_HIDDEN'):
                reject('UNSUPPORTED_VISIBILITY', path, symbol['name'])
        unsupported_tags = {'DT_SYMBOLIC', 'DT_FILTER', 'DT_AUXILIARY', 'DT_AUDIT',
                            'DT_DEPAUDIT', 'DT_TEXTREL', 'DT_RELR', 'DT_RELRSZ',
                            'DT_PREINIT_ARRAY', 'DT_PREINIT_ARRAYSZ'}
        if rv_executable:
            unsupported_tags -= {'DT_PREINIT_ARRAY', 'DT_PREINIT_ARRAYSZ'}
        for tag in tags:
            if tag.entry.d_tag in unsupported_tags:
                reject('UNSUPPORTED_DYNAMIC_TAG', path, tag.entry.d_tag)
            if tag.entry.d_tag == 'DT_FLAGS' and tag.entry.d_val & ~8:
                reject('UNSUPPORTED_DYNAMIC_FLAGS', path, hex(tag.entry.d_val))
            if tag.entry.d_tag == 'DT_FLAGS_1' and tag.entry.d_val & ~1:
                reject('UNSUPPORTED_DYNAMIC_FLAGS_1', path, hex(tag.entry.d_val))
        relocations = {}
        counts = Counter()
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            for relocation in sec.iter_relocations():
                rtype = relocation['r_info_type']
                counts[rtype] += 1
                if rtype == architecture['copy']:
                    reject('COPY_RELOCATION', path, hex(relocation['r_offset']))
                if rtype not in architecture['relocations']:
                    reject('UNSUPPORTED_RELOCATION', path, str(rtype))
                relocations[relocation['r_offset']] = dict(relocation.entry)
        result['relocation_types'] = dict(counts)
        address_names = {}
        for symbol in static:
            if isinstance(symbol['section'], int):
                address_names.setdefault(symbol['address'], set()).add(symbol['name'])
        # Default ELF startup is accepted only with validated architecture-
        # specific CRT bodies/targets, not because a function has a CRT name.
        init = elf.get_section_by_name('.init')
        fini = elf.get_section_by_name('.fini')
        for section, tag_name in ((init, 'DT_INIT'), (fini, 'DT_FINI')):
            addresses = [t.entry.d_val for t in tags if t.entry.d_tag == tag_name]
            if addresses and (len(addresses) != 1 or section is None or addresses[0] != section['sh_addr']):
                reject('REDIRECTED_' + tag_name, path, 'dynamic tag does not name its validated section')
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
        if machine == 'EM_AARCH64':
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
            if init:
                data = init.data()
                prefix, suffix = bytes.fromhex('4883ec08488b05'), bytes.fromhex('4885c07402ffd04883c408c3')
                if not (len(data) == 23 and data[:7] == prefix and data[11:] == suffix):
                    reject('CUSTOM_DT_INIT', path, 'not the supported x64 glibc gmon-only CRT sequence')
                got = init['sh_addr'] + 11 + struct.unpack('<i', data[7:11])[0]
                relocation = relocations.get(got)
                if not relocation or dynsym.get_symbol(relocation['r_info_sym']).name != '__gmon_start__':
                    reject('CUSTOM_DT_INIT', path, 'init call is not the weak __gmon_start__ hook')
            if fini and fini.data() != bytes.fromhex('4883ec084883c408c3'):
                reject('CUSTOM_DT_FINI', path, 'not the supported empty x64 glibc CRT sequence')
        if role == 'selected':
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
            tm = elf.get_section_by_name('.tm_clone_table')
            if tm and tm['sh_size']:
                reject('TRANSACTION_CLONE_REGISTRATION', path, 'nonempty .tm_clone_table')
        eh = elf.get_section_by_name('.eh_frame')
        if eh and eh['sh_size']:
            try:
                for entry in elf.get_dwarf_info().EH_CFI_entries():
                    if not isinstance(entry, FDE):
                        continue
                    result['fde_count'] += 1
                    start, size = entry['initial_location'], entry['address_range']
                    sections = [s.name for s in elf.iter_sections()
                                if s['sh_addr'] <= start < s['sh_addr'] + s['sh_size'] and s['sh_flags'] & 2]
                    names = sorted(address_names.get(start, set()))
                    if role == 'selected' and (set(names) & {'_init', '_fini'} or any(n.startswith('.plt') for n in sections)):
                        continue
                    if role == 'executable' and any(n.startswith('.plt') for n in sections):
                        continue
                    if not names:
                        reject('UNNAMED_UNWIND_RANGE', path, hex(start))
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
    # No silently changed ELF search-order/weak/preemption policy. Duplicate
    # definitions among selected inputs or versus retained external providers
    # require a richer resolver and are rejected in this prototype.
    definitions = {}
    for item in [executable] + selected + external:
        for symbol in item['symbols']:
            if symbol['section'] == 'SHN_UNDEF' or symbol['binding'] == 'STB_LOCAL':
                continue
            if symbol['visibility'] == 'STV_HIDDEN':
                continue
            definitions.setdefault(symbol['name'], []).append(item)
    for name, items in definitions.items():
        paths = {item['path'] for item in items}
        selected_definitions = [i for i in items if i['role'] != 'external']
        if len(paths) > 1 and selected_definitions:
            reject('AMBIGUOUS_GLOBAL_BINDING', selected_definitions[0]['path'],
                   '{} also defined in {}'.format(name, ', '.join(sorted(paths))))
        if name in CRT_WEAK - {'__cxa_finalize'}:
            reject('CALLABLE_CRT_HOOK', items[0]['path'], name)
    selected_sonames = {item['soname'] for item in selected}
    for item in [executable] + selected:
        for version in item['versions']:
            if version['library'] in selected_sonames:
                reject('SELECTED_SYMBOL_VERSION_REFERENCE', item['path'], version['library'])
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
    for dependency in executable['needed']:
        if dependency in selected_sonames:
            visit(providers[dependency])
    if len(visited) != len(selected):
        reject('UNREACHABLE_SELECTED_LIBRARY', executable['path'], str(selected_sonames - visited))
    return ordering


def reconstruct(item, args, out, index=0, priority=None):
    directory = out / ('executable' if item['role'] == 'executable' else 'selected-{:03d}'.format(index))
    directory.mkdir()
    object_recipe = {'format': 1, 'stage': 'ordinary-et-rel', 'context': args.cache_context,
                     'input_sha256': item['sha256'], 'role': item['role'],
                     'module_basename': Path(item['path']).name, 'array_priority': priority,
                     'printing_policy': 'complete', 'shared': False}
    lift_recipe = {'format': 1, 'stage': 'recovered-ir', 'frontend': args.tool_identities['ddisasm'],
                   'input_sha256': item['sha256'], 'module_basename': Path(item['path']).name,
                   'frontend_source_provenance': args.source_provenance_data,
                   'jobs': args.jobs}
    if args.cache and args.cache.restore('objects', object_recipe, directory):
        dump(directory / 'cache.json', {'object': 'hit', 'object_key': content_key(object_recipe),
                                       'lift': 'included-in-object-hit', 'instrumented': False})
        return directory / 'reconstructed.o'
    irpath = directory / 'lift.gtirb'
    lift_hit = args.cache is not None and args.cache.restore('ir', lift_recipe, directory)
    if not lift_hit:
        run(directory, 'lift', [args.ddisasm, item['path'], '--ir', irpath, '-j', str(args.jobs)])
    diagnostics = (directory / 'lift/stderr').read_text()
    ir = gtirb.IR.load_protobuf(irpath)
    if len(ir.modules) != 1:
        reject('MULTIMODULE_INPUT', item['path'], 'one module per ELF required')
    module = ir.modules[0]
    data_warnings = validate_frontend_diagnostics(module, item, diagnostics)
    dump(directory / 'proven-data-decoder-warnings.json', data_warnings)
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
        args.cache.store('ir', lift_recipe, directory, ['lift.gtirb', 'lift'])
    summary = {'isa': str(module.isa), 'code_blocks': len(list(module.code_blocks)),
               'data_blocks': len(list(module.data_blocks)),
               'live_register_entries': len(liveness.data), 'cfi_starts': len(starts),
               'application_fdes_checked': len(item['application_fdes'])}
    dump(directory / 'ir-summary.json', summary)
    print_ir = irpath
    if item['role'] == 'selected':
        # Keep library CRT callback bodies and their per-DSO __dso_handle.
        # Only the byte-validated, inert DT_INIT/DT_FINI stubs are excluded.
        # Array section priorities respect selected dependency startup order;
        # fini arrays are traversed in reverse by the process startup code.
        for section in module.sections:
            if section.name in ('.init_array', '.fini_array'):
                section.name += '.{:05d}'.format(priority)
        module.aux_data.pop('elfDynamicInit', None)
        module.aux_data.pop('elfDynamicFini', None)
        print_ir = directory / 'relocatable.gtirb'
        ir.save_protobuf(print_ir)
    assembly = directory / 'reconstructed.S'
    print_command = [args.pprinter, '--ir', print_ir, '--asm', assembly,
                     '--policy', 'complete', '--shared', 'no']
    if item['role'] == 'selected':
        print_command += ['--skip-section', '.init', '.fini']
    run(directory, 'print', print_command)
    # No replacement/stripping of GOT, PLT, .symver or CFI assembly is allowed.
    obj = directory / 'reconstructed.o'
    run(directory, 'assemble', [args.cc, '-c', '-o', obj, assembly])
    with obj.open('rb') as stream:
        elf = ELFFile(stream)
        if elf['e_type'] != 'ET_REL' or elf['e_machine'] != item['machine']:
            raise RuntimeError('assembler did not create expected ET_REL')
        if item['machine'] == 'EM_RISCV' and (elf['e_flags'] & 6 != 4 or elf['e_flags'] & ~5):
            reject('ASSEMBLED_ABI_MISMATCH', item['path'], 'RV64 object must retain LP64D ABI')
        table = elf.get_section_by_name('.symtab')
        emitted = {s.name: s for s in table.iter_symbols() if s['st_shndx'] != 'SHN_UNDEF'}
        for symbol in item['symbols']:
            if symbol['section'] == 'SHN_UNDEF' or symbol['binding'] == 'STB_LOCAL':
                continue
            if symbol['name'] not in emitted:
                reject('MISSING_RECONSTRUCTED_EXPORT', item['path'], symbol['name'])
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
        'lift': 'hit' if lift_hit else ('miss' if args.cache else 'disabled'), 'instrumented': False})
    return obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', required=True, type=Path)
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
        executable = inspect(args.executable, 'executable')
        architecture = ARCHITECTURES[executable['machine']]
        selected = [inspect(path, 'selected') for path in args.select]
        external = [inspect(path, 'external') for path in args.external]
        initialization_order = validate_closure(executable, selected, external)
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
            'executable': executable['sha256'],
            'selected_order': [(i['soname'], i['sha256']) for i in selected],
            'external_order': [(i['soname'], i['sha256']) for i in external],
            'initialization_order': initialization_order,
            'instrumentation': None, 'runtime_layout': None}
        # JSON canonicalization removes tuple/list distinctions on later cache reads.
        args.cache_context = json.loads(json.dumps(args.cache_context))
        args.cache = ArtifactCache(args.cache_dir) if args.cache_dir else None
        manifest = {'contract': CONTRACT, 'script_sha256': sha(__file__),
                    'executable': executable, 'selected': selected, 'external': external,
                    'selected_dependency_order': [item['soname'] for item in selected],
                    'selected_initialization_order': initialization_order,
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
        run(args.out, 'link', shlex.split(args.linker) + link_policy + [
            '-m', architecture['emulation'], '--dynamic-linker', architecture['interpreter'],
            '--eh-frame-hdr', '--build-id=sha1', '-z', 'noexecstack',
            '-Map=' + str(args.out / 'link.map'), '-o', output, main_object,
            '--whole-archive', archive, '--no-whole-archive', '--as-needed']
            + [item['path'] for item in external])
        with output.open('rb') as stream:
            elf = ELFFile(stream)
            if elf['e_type'] != 'ET_EXEC' or elf['e_machine'] != executable['machine']:
                raise RuntimeError('output is not the expected architecture/non-PIE ET_EXEC')
            if executable['machine'] == 'EM_RISCV':
                validate_linked_riscv_startup(elf, output)
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
                    if symbol['section'] != 'SHN_UNDEF' and symbol['name'] not in defined:
                        raise RuntimeError('missing selected body/data: ' + symbol['name'])
            dump(args.out / 'result.json', {'status': 'ordinary_link_ready_not_yet_behavior_verified',
                'elf_type': elf['e_type'], 'needed': needed,
                'monolith_sha256': sha(output), 'archive_sha256': sha(archive),
                'archive_members': [{'name': p.name, 'sha256': sha(p), 'type': 'ET_REL'} for p in members]})
    except Unsupported as error:
        dump(args.out / 'rejection.json', {'status': 'unsupported', 'reason': str(error)})
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
