"""Host orchestration for the full, single-runtime x64 validated-monolith path."""
import json
import os
from pathlib import Path
import subprocess


WORK = Path(__file__).resolve().parents[3]
ROOT = WORK.parents[1]
FRONTEND = ROOT / 'workers/root/baseline-20260921/frontend/install'
OUT = WORK / 'artifacts/libhtp/instrumented-v2'


if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=False)
    (OUT / 'tmp').mkdir()
    argv = ['docker', 'run', '--rm', '--network', 'none', '--memory', '40g', '--cpus', '8', '--user', '1000:1000']
    mounts = [(FRONTEND, '/eval/workers/root/baseline-20260921/frontend/install', 'ro'),
        (ROOT / 'shared-build/install', '/eval/shared-build/install', 'ro'),
        (ROOT / 'sources/gtirb-live-register-analysis', '/lra', 'ro'),
        (ROOT / 'sources/gtirb-rewriting-2c0308e/src', '/rewriting', 'ro'),
        (WORK / 'teapot', '/teapot', 'ro'),
        (WORK / 'artifacts/libhtp/v2/monolith', '/monolith', 'ro'),
        (WORK / 'artifacts/libhtp/ordinary-v2', '/ordinary', 'ro'),
        (OUT, '/instrumented', 'rw')]
    for source, target, mode in mounts:
        argv += ['-v', '{}:{}:{}'.format(source, target, mode)]
    argv += ['-e', 'LD_LIBRARY_PATH=/eval/workers/root/baseline-20260921/frontend/install/lib:/eval/shared-build/install/lib',
             '-e', 'PYTHONPATH=/teapot:/lra:/rewriting', '-e', 'TMPDIR=/instrumented/tmp',
             'teapot-multiarch-eval:1586139-tools-v4', 'python3', '/teapot/tools/sharedlib/instrument_monolith.py']
    (OUT / 'container.command.json').write_text(json.dumps(argv, indent=2) + '\n')
    subprocess.run(argv, check=True)
    runtime = ROOT / 'workers/baseline-runtime-20260921/install/x64-host-gcc14/lib'
    hfuzz = ROOT / 'shared-build/honggfuzz/x86_64/lib'
    link = ['gcc-14', '-B' + str(ROOT / 'workers/baseline-runtime-20260921/linker/shim'),
        '-fuse-ld=lld', '-fsanitize=address', '-o', str(OUT / 'monolith.instrumented'),
        str(OUT / 'application.o'), '-no-pie', '-nostartfiles', '-Wl,--no-as-needed',
        '-Wl,--build-id=sha1', '-Wl,-Map=' + str(OUT / 'link.map'),
        str(runtime / 'libcheckpoint.a'), str(runtime / 'libcheckpoint_dift_math_wrappers.a'),
        str(runtime / 'libcheckpoint_dift_zlib_wrappers.a'),
        '-Wl,-u,LIBHFUZZ_module_instrument', '-Wl,-u,LIBHFUZZ_module_memorycmp',
        str(hfuzz / 'libhfuzz.a'), str(hfuzz / 'libhfcommon.a'),
        '-lz', '-lasan', '-ldl', '-pthread', '-lrt', '-lm', '-lc', '-lgcc_s']
    (OUT / 'link.command.json').write_text(json.dumps(link, indent=2) + '\n')
    with (OUT / 'link.stdout').open('wb') as stdout, (OUT / 'link.stderr').open('wb') as stderr:
        subprocess.run(link, stdout=stdout, stderr=stderr, check=True)
    print('Full instrumentation and one-runtime link complete', flush=True)
