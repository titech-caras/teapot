"""Compare actual status/stdout/stderr/application logs on pinned libhtp seeds."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


WORK = Path(__file__).resolve().parents[3]
ROOT = WORK.parents[1]
SEEDS = ROOT / 'sources/teapot-testcases/resources/seed/libhtp'
HEADER = b'[teapot], Gadget Type, Gadget Address, Mem Access Address, Tag, Instruction Counter, Checkpoint Addresses\n'
REPORT = re.compile(rb'\[teapot\], (-?\d+) (KASPER_MDS|KASPER_CACHE|KASPER_PORT), (0x[0-9a-f]+), (0x[0-9a-f]+), (0x[0-9a-f]+), (\d+), ((?:0x[0-9a-f]+, )+)\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(binary, case, seed, instrumented, no_aslr):
    case.mkdir(parents=True)
    env = dict(os.environ)
    env['LD_LIBRARY_PATH'] = str(WORK / 'inputs/libhtp')
    env['ASAN_OPTIONS'] = 'detect_leaks=0:abort_on_error=1'
    command = (['setarch', 'x86_64', '-R'] if no_aslr else []) + [str(binary), str(seed), str(case / 'application.log')]
    (case / 'command.json').write_text(json.dumps(command) + '\n')
    begin = time.time()
    with (case / 'stdout').open('wb') as stdout, (case / 'stderr').open('wb') as stderr:
        try:
            result = subprocess.run(command, env=env, stdout=stdout, stderr=stderr, timeout=300)
            status = result.returncode
        except subprocess.TimeoutExpired:
            status = 124
    app_stderr, reports, depths, sites, headers = bytearray(), Counter(), Counter(), set(), 0
    for line in (case / 'stderr').read_bytes().splitlines(keepends=True):
        report = REPORT.fullmatch(line)
        if instrumented and line == HEADER:
            headers += 1
        elif instrumented and report:
            kind = report.group(2).decode()
            reports[kind] += 1
            sites.add((kind, report.group(3).decode()))
            depths[len(report.group(7).split(b', ')) - 1] += 1
        else:
            app_stderr.extend(line)
    (case / 'application.stderr').write_bytes(app_stderr)
    data = {'status': status, 'seconds': time.time() - begin, 'sha256': digest(seed),
            'reports': dict(reports), 'depths': dict(depths), 'sites': sorted(sites),
            'runtime_headers': headers}
    (case / 'result.json').write_text(json.dumps(data, indent=2) + '\n')
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--instrumented', action='store_true')
    parser.add_argument('--no-aslr', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    seeds = sorted(p for p in SEEDS.iterdir() if p.is_file())
    assert len(seeds) == 118
    approved = {Path(line.split()[1]).name: line.split()[0] for line in
                (ROOT / 'workers/baseline-libhtp-20260921/inputs.sha256').read_text().splitlines()}
    assert {seed.name: digest(seed) for seed in seeds} == approved, 'approved corpus changed'
    rows, totals = [], Counter()
    for seed in seeds:
        case = args.out / seed.name
        actual = execute(args.binary.resolve(), case, seed, args.instrumented, args.no_aslr)
        differences = []
        if args.baseline:
            baseline = args.baseline / seed.name
            expected = json.loads((baseline / 'result.json').read_text())
            if actual['sha256'] != expected['sha256']:
                differences.append('seed hash')
            if actual['status'] != expected['status']:
                differences.append('status')
            for name in ('stdout', 'application.stderr', 'application.log'):
                got, want = case / name, baseline / name
                if got.exists() != want.exists() or (got.exists() and got.read_bytes() != want.read_bytes()):
                    differences.append(name)
        elif actual['status'] != 0:
            differences.append('baseline nonzero status')
        if args.instrumented and actual['runtime_headers'] != 1:
            differences.append('runtime header count')
        if args.instrumented and any(int(d) != 1 for d in actual['depths']):
            differences.append('nested report')
        totals.update(actual['reports'])
        rows.append({'input': seed.name, 'differences': differences, **actual})
        print('{}: {}'.format(seed.name, 'PASS' if not differences else ','.join(differences)), flush=True)
    result = {'binary': str(args.binary), 'binary_sha256': digest(args.binary),
              'count': len(rows), 'passed': sum(not row['differences'] for row in rows),
              'reports': dict(totals), 'cases': rows}
    (args.out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'cases'}), flush=True)
    return result['passed'] != len(rows)


if __name__ == '__main__':
    raise SystemExit(main())
