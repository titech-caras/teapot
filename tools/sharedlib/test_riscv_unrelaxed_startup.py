#!/usr/bin/env python3
"""Validate a real unrelaxed RV64 CRT call and reject register/target mutations."""
import argparse
import json
from pathlib import Path

import convert
from test_startup_multiarch import Mutation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    before = convert.sha(args.input)
    image = Mutation(args.input)
    entry = image.elf['e_entry']
    offset = image.offset(entry)
    assert image.symbol('_start')['st_value'] == entry
    assert int.from_bytes(image.data[offset:offset + 4], 'little') & 0xfff == 0x97
    assert int.from_bytes(image.data[offset + 4:offset + 8], 'little') & 0xfffff == 0x80e7
    accepted = convert.inspect(args.input, 'executable')
    assert accepted['preinit_contract'].startswith('retained single CRT load_gp')
    convert.validate_linked_riscv_startup(image.elf, args.input)
    results = []
    for name, displacement, xor in (
        ('upper-register', 0, 0x80), ('upper-opcode', 0, 0x20),
        ('lower-source', 4, 1 << 15), ('lower-destination', 4, 0x80),
        ('call-target', 4, 1 << 21),
    ):
        mutation = Mutation(args.input)
        mutation.code('_start', displacement, xor)
        path = args.out / (name + '.elf')
        path.write_bytes(mutation.data)
        try:
            convert.inspect(path, 'executable')
        except convert.Unsupported as error:
            assert str(error).startswith('UNSUPPORTED_CRT_CALLBACK_BODY:'), str(error)
            results.append({'mutation': name, 'rejection': str(error)})
        else:
            raise AssertionError('accepted malformed CRT call: ' + name)
    assert before == convert.sha(args.input)
    summary = {'positive_checks': 2, 'negative_checks': results, 'input_sha256': before,
               'converter_sha256': convert.sha(convert.__file__), 'input_unchanged': True}
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print('RV64 unrelaxed startup: 2 positive and 5 negative checks passed')


if __name__ == '__main__':
    main()
