"""Ground-truth builder. This file/source tree is never mounted in conversion.

All products and command evidence remain under the worker's workspace. Only ELF
copies from the distinct inputs directories are made visible to the converter.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


WORK = Path(__file__).resolve().parents[3]
ROOT = WORK.parents[1]
HERE = Path(__file__).resolve().parent


def run(cwd, name, argv):
    logs = WORK / 'groundtruth' / 'logs'
    logs.mkdir(parents=True, exist_ok=True)
    (logs / (name + '.command.json')).write_text(json.dumps({
        'argv': [str(x) for x in argv], 'cwd': str(cwd),
    }, indent=2) + '\n')
    with (logs / (name + '.stdout')).open('w') as stdout, (logs / (name + '.stderr')).open('w') as stderr:
        subprocess.run([str(x) for x in argv], cwd=cwd, stdout=stdout,
                       stderr=stderr, check=True)


def export(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def fixture(name='fixture'):
    build = WORK / 'groundtruth' / name
    build.mkdir(parents=True, exist_ok=False)
    flags = ['gcc', '-O2', '-g', '-fPIC']
    run(build, 'fixture-beta', flags + ['-shared', HERE / 'fixtures/beta.c',
        '-Wl,-soname,libbeta.so', '-o', 'libbeta.so'])
    run(build, 'fixture-alpha', flags + ['-shared', HERE / 'fixtures/alpha.c',
        '-L.', '-lbeta', '-Wl,-rpath,$ORIGIN', '-Wl,-soname,libalpha.so', '-o', 'libalpha.so'])
    run(build, 'fixture-main', flags + ['-no-pie', HERE / 'fixtures/main.c',
        '-L.', '-lalpha', '-lbeta', '-Wl,-rpath,$ORIGIN', '-o', 'main'])
    for name in ('main', 'libalpha.so', 'libbeta.so'):
        export(build / name, WORK / 'inputs' / build.name / name)


def libhtp():
    build = WORK / 'groundtruth' / 'libhtp'
    shutil.copytree(ROOT / 'sources/teapot-testcases/libhtp', build)
    export(ROOT / 'workers/baseline-libhtp-20260921/teapot_specvariant.h',
           build / 'teapot_specvariant.h')
    if not (build / 'configure').exists():
        run(build, 'libhtp-autogen', ['sh', 'autogen.sh'])
    run(build, 'libhtp-configure', ['./configure', '--enable-shared', '--disable-static',
        'CFLAGS=-O2 -g -fPIC', 'LDFLAGS=-no-pie'])
    run(build, 'libhtp-build', ['make', '-C', 'htp', '-j8', 'libhtp.la'])
    run(build, 'libhtp-test-build', ['make', '-C', 'test', '-j8', 'test_fuzz'])
    export(build / 'test/.libs/test_fuzz', WORK / 'inputs/libhtp/test_fuzz')
    export(build / 'htp/.libs/libhtp.so.2.0.0', WORK / 'inputs/libhtp/libhtp.so.2')


if __name__ == '__main__':
    fixture()
    libhtp()
    hashes = {str(p.relative_to(WORK)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted((WORK / 'inputs').rglob('*')) if p.is_file()}
    (WORK / 'groundtruth/inputs.sha256.json').write_text(json.dumps(hashes, indent=2) + '\n')
