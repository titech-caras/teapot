#!/usr/bin/env python3
"""Small fail-closed tests against the real opt-in runtime activation code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT.parent.parent / 'libcheckpoint'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--runtime-build', type=Path, required=True,
                        help='configured AArch64 runtime build providing generated include headers')
    args = parser.parse_args()
    out = args.out.resolve()
    include = args.runtime_build.resolve() / 'include'
    out.mkdir(exist_ok=False)
    files = [Path(__file__), ROOT / 'activation_probe.c', ROOT / 'activation_probe.S',
             RUNTIME / 'src/aarch64_bti.c', RUNTIME / 'asm/aarch64_bti.S', RUNTIME / 'cmake/AArch64Bti.ld']
    hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    variants = [('valid', []), ('bad-second', ['-DBAD_SECOND_WORD']),
                ('overlap-shadow', ['-DOVERLAP_SHADOW'])]
    variants += [(name, ['-DBAD_LANDING=' + value]) for name, value in
                 [('bti-c', '0xd503245f'), ('bti-j', '0xd503249f'), ('bti-jc', '0xd50324df'),
                  ('paciasp', '0xd503233f'), ('pacibsp', '0xd503237f'),
                  ('brk', '0xd4200000'), ('hlt', '0xd4400000')]]
    rows = []
    for name, defines in variants:
        case = out / name
        case.mkdir()
        binary = case / 'probe'
        build = ['aarch64-linux-gnu-gcc', '-no-pie', '-fno-stack-protector', '-DTEAPOT_EXPERIMENTAL_AARCH64_BTI',
                 '-DDIFT_XOR_MASK=0x20000000000ULL',
                 '-I' + str(include), '-I' + str(RUNTIME / 'include'), *defines,
                 str(ROOT / 'activation_probe.c'), str(ROOT / 'activation_probe.S'),
                 str(RUNTIME / 'src/aarch64_bti.c'), str(RUNTIME / 'asm/aarch64_bti.S'),
                 '-Wl,-T,' + str(RUNTIME / 'cmake/AArch64Bti.ld'),
                 '-Wl,--wrap=getauxval', '-Wl,--wrap=mprotect', '-o', str(binary)]
        (case / 'build-command.json').write_text(json.dumps(build) + '\n')
        result = subprocess.run(build, capture_output=True)
        (case / 'build.stdout').write_bytes(result.stdout)
        (case / 'build.stderr').write_bytes(result.stderr)
        result.check_returncode()
        modes = ('normal', 'no-hwcap', 'reject-protection', 'ignore-protection') if name == 'valid' else ('normal',)
        for mode in modes:
            command = ['/usr/bin/qemu-aarch64', '-cpu', 'max', '-L', '/usr/aarch64-linux-gnu', str(binary)]
            env = dict(os.environ, BTI_GATE_TEST=mode)
            result = subprocess.run(command, env=env, capture_output=True, timeout=30)
            prefix = case / mode
            prefix.with_suffix('.stdout').write_bytes(result.stdout)
            prefix.with_suffix('.stderr').write_bytes(result.stderr)
            expected = 0 if name == 'valid' and mode == 'normal' else 78
            diagnostic = b'active:' if expected == 0 else b'refusing activation:'
            good = result.returncode == expected and diagnostic in result.stderr
            row = {'variant': name, 'mode': mode, 'command': command, 'expected': expected,
                   'status': result.returncode, 'passed': good, 'stderr': result.stderr.decode(),
                   'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
            rows.append(row)
            print(name, mode, 'PASS' if good else 'FAIL', flush=True)
    after = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    if hashes != after:
        raise RuntimeError('source changed during gate tests')
    summary = {'passed': sum(r['passed'] for r in rows), 'total': len(rows), 'source_hashes': hashes, 'cases': rows}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return int(summary['passed'] != summary['total'])


if __name__ == '__main__':
    raise SystemExit(main())
