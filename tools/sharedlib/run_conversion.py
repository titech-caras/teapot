"""Host launcher for an explicitly isolated binary-input conversion container."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


WORK = Path(__file__).resolve().parents[3]
ROOT = WORK.parents[1]
FRONTEND = ROOT / 'workers/root/baseline-20260921/frontend/install'
PINNED_LLD = ROOT / 'workers/baseline-runtime-20260921/linker/root/usr/lib/llvm-19/bin/lld'


def command(dataset, revision, executable, selected, cache=None):
    inputs = WORK / 'inputs' / dataset
    output = WORK / 'artifacts' / dataset
    output.mkdir(parents=True, exist_ok=True)
    argv = ['docker', 'run', '--rm', '--network', 'none', '--memory', '40g', '--cpus', '8',
            '--user', '1000:1000']
    mounts = [(FRONTEND, FRONTEND.as_posix().replace(str(ROOT), '/eval'), 'ro'),
              (ROOT / 'shared-build/install', '/eval/shared-build/install', 'ro'),
              (inputs, '/inputs', 'ro'),
              (Path(__file__).with_name('convert.py'), '/converter.py', 'ro'),
              (output, '/out', 'rw'),
              (Path('/usr/lib/x86_64-linux-gnu'), '/external', 'ro'),
              (PINNED_LLD, '/pinned-lld', 'ro')]
    for source, target, mode in mounts:
        argv.extend(['-v', '{}:{}:{}'.format(source, target, mode)])
    if cache:
        cache = cache.resolve()
        cache.mkdir(parents=True, exist_ok=True)
        argv += ['-v', '{}:/cache:rw'.format(cache)]
    argv += ['-e', 'LD_LIBRARY_PATH=/eval/workers/root/baseline-20260921/frontend/install/lib:/eval/shared-build/install/lib',
             '-e', 'TMPDIR=/out/tmp', 'teapot-multiarch-eval:1586139-tools-v4',
             'bash', '-lc', 'mkdir -p /out/tmp && exec "$@"', 'converter',
             'python3', '/converter.py', '--executable', '/inputs/' + executable]
    for library in selected:
        argv += ['--select', '/inputs/' + library]
    for library in ('libz.so.1', 'libc.so.6', 'ld-linux-x86-64.so.2'):
        argv += ['--external', '/external/' + library]
    argv += ['--ddisasm', '/eval/workers/root/baseline-20260921/frontend/install/bin/ddisasm',
             '--pprinter', '/eval/workers/root/baseline-20260921/frontend/install/bin/gtirb-pprinter',
             '--linker', '/external/ld-linux-x86-64.so.2 --library-path /external /pinned-lld -flavor gnu',
             '--out', '/out/' + revision]
    if cache:
        argv += ['--cache-dir', '/cache']
    provenance = {}
    for name, repository in (('teapot', WORK / 'teapot'), ('runtime', WORK / 'teapot/libcheckpoint'),
                             ('ddisasm', ROOT / 'sources/ddisasm'), ('pprinter', WORK / 'pprinter'),
                             ('gtirb', ROOT / 'sources/gtirb'), ('libehp', ROOT / 'sources/libehp'),
                             ('lra', ROOT / 'sources/gtirb-live-register-analysis'),
                             ('rewriting', ROOT / 'sources/gtirb-rewriting-2c0308e')):
        provenance[name] = {
            'head': subprocess.check_output(['git', '-C', str(repository), 'rev-parse', 'HEAD'], text=True).strip(),
            'tracked_diff_sha256': hashlib.sha256(subprocess.check_output(
                ['git', '-C', str(repository), 'diff', '--binary', 'HEAD'])).hexdigest()}
    baseline_provenance = ROOT / 'workers/root/baseline-20260921/frontend/provenance'
    provenance['built_frontend_records'] = {
        str(p.relative_to(baseline_provenance)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(baseline_provenance.rglob('*')) if p.is_file()}
    argv += ['--source-provenance', json.dumps(provenance, sort_keys=True)]
    image_index = argv.index('teapot-multiarch-eval:1586139-tools-v4')
    argv[image_index:image_index] = ['-e', 'TEAPOT_CONTAINER_ARGV=' + json.dumps(argv)]
    return argv


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('dataset')
    parser.add_argument('revision')
    parser.add_argument('executable')
    parser.add_argument('selected', nargs='+')
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    argv = command(args.dataset, args.revision, args.executable, args.selected, args.cache)
    raise SystemExit(subprocess.call(argv))
