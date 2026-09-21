#!/usr/bin/env python3
"""Pin final-link GP validation against retained valid and relaxed ELF files."""
import argparse
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

import convert


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--valid', type=Path, action='append', required=True)
    parser.add_argument('--relaxed', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    results = []
    for path, expected in [(path, True) for path in args.valid] + [(args.relaxed, False)]:
        before = convert.sha(path)
        with path.open('rb') as stream:
            try:
                convert.validate_linked_riscv_startup(ELFFile(stream), path)
            except convert.Unsupported as error:
                assert not expected, str(error)
                assert 'UNSUPPORTED_CRT_CALLBACK_BODY:' in str(error), str(error)
                results.append({'path': str(path), 'sha256': before, 'rejection': str(error)})
            else:
                assert expected, 'relaxed GP initializer was accepted'
                results.append({'path': str(path), 'sha256': before, 'accepted': True})
        assert convert.sha(path) == before
        if expected:
            data = path.read_bytes()
            elf = ELFFile(io.BytesIO(data))
            entry = elf['e_entry']
            section = next(section for section in elf.iter_sections()
                           if section['sh_addr'] <= entry < section['sh_addr'] + section['sh_size'])
            offset = section['sh_offset'] + entry - section['sh_addr']
            if struct.unpack_from('<I', data, offset)[0] & 0xfff == 0x97:
                for name, delta, mask in (('upper-register', 0, 0x80),
                                           ('lower-link-register', 4, 0x80),
                                           ('lower-base-register', 4, 0x8000),
                                           ('wrong-target', 4, 0x200000)):
                    mutant = bytearray(data)
                    word = struct.unpack_from('<I', mutant, offset + delta)[0]
                    struct.pack_into('<I', mutant, offset + delta, word ^ mask)
                    mutant_path = args.out.parent / (path.name + '-' + name + '.elf')
                    mutant_path.write_bytes(mutant)
                    try:
                        convert.validate_linked_riscv_startup(ELFFile(io.BytesIO(mutant)), mutant_path)
                    except convert.Unsupported as error:
                        results.append({'path': str(mutant_path), 'sha256': convert.sha(mutant_path),
                                        'rejection': str(error)})
                    else:
                        raise AssertionError('invalid call pair accepted: ' + name)
    args.out.write_text(json.dumps({'passed': True, 'cases': results}, indent=2) + '\n')
    print('Linked RV startup: {} accepted, relaxed initializer rejected'.format(len(args.valid)))


if __name__ == '__main__':
    main()
