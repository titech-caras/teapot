"""Container-side ELF-only contract tests, including mutated startup metadata."""
import contextlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile


spec = importlib.util.spec_from_file_location('converter', '/converter.py')
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)
OUT = Path('/out')
INPUT = Path('/inputs')
EXTERNAL = [Path('/external') / n for n in ('libz.so.1', 'libc.so.6', 'ld-linux-x86-64.so.2')]


def mutate(name, base, kind, target, value=None):
    data = bytearray(base.read_bytes())
    with base.open('rb') as stream:
        elf = ELFFile(stream)
        if kind == 'entry':
            struct.pack_into('<Q', data, 24, elf['e_entry'] + 1)
        elif kind == 'machine':
            struct.pack_into('<H', data, 18, 183)
        elif kind == 'elf-type':
            struct.pack_into('<H', data, 16, 3)
        elif kind == 'tag':
            dynamic = elf.get_section_by_name('.dynamic')
            for index, tag in enumerate(dynamic.iter_tags()):
                if tag.entry.d_tag == target:
                    offset = dynamic['sh_offset'] + index * 16
                    struct.pack_into('<Q', data, offset + 8, value if value is not None else tag.entry.d_val + 8)
                    break
            else:
                raise AssertionError('tag not found: ' + target)
        elif kind == 'tag-type':
            dynamic = elf.get_section_by_name('.dynamic')
            for index, tag in enumerate(dynamic.iter_tags()):
                if tag.entry.d_tag == target:
                    struct.pack_into('<Q', data, dynamic['sh_offset'] + index * 16, value)
                    break
        elif kind == 'body':
            symbols = elf.get_section_by_name('.symtab')
            symbol = next(s for s in symbols.iter_symbols() if s.name == target)
            section = elf.get_section(symbol['st_shndx'])
            offset = section['sh_offset'] + symbol['st_value'] - section['sh_addr']
            data[offset] = 0x90
        elif kind == 'rename':
            symbols = elf.get_section_by_name('.symtab')
            symbol = next(s for s in symbols.iter_symbols() if s.name == target)
            strings = elf.get_section(symbols['sh_link'])
            offset = strings['sh_offset'] + symbol['st_name']
            data[offset] = ord('X')
        elif kind == 'dynamic-rename':
            symbols = elf.get_section_by_name('.dynsym')
            symbol = next(s for s in symbols.iter_symbols() if s.name == target)
            strings = elf.get_section(symbols['sh_link'])
            offset = strings['sh_offset'] + symbol['st_name']
            assert len(value) <= len(target)
            data[offset:offset+len(target)] = value.encode() + bytes(len(target)-len(value))
        else:
            raise AssertionError(kind)
    path = OUT / 'mutated' / name
    path.write_bytes(data)
    return path


def reject_case(name, expected, executable, selected):
    directory = OUT / name
    argv = ['converter', '--executable', str(executable), '--out', str(directory),
        '--ddisasm', '/tools/ddisasm', '--pprinter', '/tools/gtirb-pprinter']
    for path in selected:
        argv += ['--select', str(path)]
    for path in EXTERNAL:
        argv += ['--external', str(path)]
    previous = sys.argv
    sys.argv = argv
    try:
        code = converter.main()
    finally:
        sys.argv = previous
    rejection = json.loads((directory / 'rejection.json').read_text())
    assert code == 2 and rejection['reason'].startswith(expected + ':'), (name, code, rejection)
    assert not (directory / 'monolith').exists(), name
    assert not (directory / 'executable').exists(), 'rejected only after lifting: ' + name
    return {'test': name, 'expected': expected, 'exit': code, **rejection}


if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'mutated').mkdir()
    cases = json.loads(Path('/cases.json').read_text())
    results = []
    for name, expected in cases.items():
        results.append(reject_case(name, expected, INPUT / 'main',
                                  [INPUT / (name + '.so'), INPUT / 'libbeta.so']))
    results.append(reject_case('copy-relocation', 'COPY_RELOCATION', INPUT / 'copy-main',
                               [INPUT / 'libalpha.so', INPUT / 'libbeta.so']))
    base = INPUT / 'libalpha.so'
    for name, kind, target, value, reason in (
        ('array-address', 'tag', 'DT_INIT_ARRAY', None, 'MISMATCHED_DT_INIT_ARRAY'),
        ('array-size', 'tag', 'DT_INIT_ARRAYSZ', 16, 'MISMATCHED_DT_INIT_ARRAY'),
        ('fini-array-address', 'tag', 'DT_FINI_ARRAY', None, 'MISMATCHED_DT_FINI_ARRAY'),
        ('fini-array-size', 'tag', 'DT_FINI_ARRAYSZ', 16, 'MISMATCHED_DT_FINI_ARRAY'),
        ('preinit-tag', 'tag-type', 'DT_INIT_ARRAY', 32, 'UNSUPPORTED_DYNAMIC_TAG'),
        ('renamed-callback', 'rename', 'frame_dummy', None, 'CUSTOM_CONSTRUCTOR_OR_DESTRUCTOR'),
        ('mutated-callback-body', 'body', 'frame_dummy', None, 'UNSUPPORTED_CRT_CALLBACK_BODY'),
        ('mutated-dtor-body', 'body', '__do_global_dtors_aux', None, 'UNSUPPORTED_CRT_CALLBACK_BODY'),
        ('mutated-init-body', 'body', '_init', None, 'CUSTOM_DT_INIT'),
    ):
        path = mutate(name + '.so', base, kind, target, value)
        results.append(reject_case(name, reason, INPUT / 'main', [path, INPUT / 'libbeta.so']))
    executable = mutate('entry-main', INPUT / 'main', 'entry', None)
    results.append(reject_case('entry-point', 'NONSTANDARD_ENTRY_POINT', executable,
                               [INPUT / 'libalpha.so', INPUT / 'libbeta.so']))
    for name, kind, reason in (('non-x64', 'machine', 'UNSUPPORTED_ARCH'),
                               ('pie', 'elf-type', 'UNSUPPORTED_ELF_TYPE')):
        executable = mutate(name + '-main', INPUT / 'main', kind, None)
        results.append(reject_case(name, reason, executable,
                                   [INPUT / 'libalpha.so', INPUT / 'libbeta.so']))
    duplicate = mutate('duplicate-global.so', base, 'dynamic-rename', 'alpha_counter', 'beta_bias')
    results.append(reject_case('duplicate-global', 'AMBIGUOUS_GLOBAL_BINDING', INPUT / 'main',
                               [duplicate, INPUT / 'libbeta.so']))
    stripped = OUT / 'mutated/stripped.so'
    subprocess.run(['objcopy', '--strip-all', str(base), str(stripped)], check=True)
    results.append(reject_case('stripped', 'STRIPPED_STARTUP_CONTRACT', INPUT / 'main',
                               [stripped, INPUT / 'libbeta.so']))
    (OUT / 'summary.json').write_text(json.dumps({'passed': len(results), 'cases': results}, indent=2) + '\n')
    print('Negative contract tests passed: {}'.format(len(results)), flush=True)
