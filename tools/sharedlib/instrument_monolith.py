"""Container-side full x64 instrumentation after ordinary behavior validation."""
import hashlib
import json
from pathlib import Path
import subprocess
import time


OUT = Path('/instrumented')
TOOLS = Path('/eval/workers/root/baseline-20260921/frontend/install/bin')


def run(name, argv):
    directory = OUT / name
    directory.mkdir()
    (directory / 'command.json').write_text(json.dumps([str(x) for x in argv], indent=2) + '\n')
    begin = time.time()
    with (directory / 'stdout').open('wb') as stdout, (directory / 'stderr').open('wb') as stderr:
        result = subprocess.run([str(x) for x in argv], stdout=stdout, stderr=stderr)
    (directory / 'result.json').write_text(json.dumps({'exit': result.returncode, 'seconds': time.time()-begin}) + '\n')
    print('{}: {}'.format(name, result.returncode), flush=True)
    result.check_returncode()


if __name__ == '__main__':
    assert json.loads(Path('/ordinary/summary.json').read_text())['passed'] == 118
    OUT.mkdir(exist_ok=True)
    run('lift', [TOOLS / 'ddisasm', '/monolith', '--ir', OUT / 'monolith.gtirb', '-j', '4'])
    run('rewrite', ['python3', '-m', 'teapot.cmdline', OUT / 'monolith.gtirb',
        OUT / 'instrumented.gtirb', '--dift-layout', 'x64-la48-asan-new', '--rewrite-progress'])
    run('print', [TOOLS / 'gtirb-pprinter', '--ir', OUT / 'instrumented.gtirb',
                  '--asm', OUT / 'raw.S'])
    run('section-flags', ['sed', '-f', '/teapot/scripts/fix_asm.sed', OUT / 'raw.S'])
    (OUT / 'fixed.S').write_bytes((OUT / 'section-flags/stdout').read_bytes())
    run('assemble', ['gcc', '-c', '-o', OUT / 'application.o', OUT / 'fixed.S'])
    (OUT / 'hashes.json').write_text(json.dumps({
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in OUT.iterdir() if p.is_file()
    }, indent=2) + '\n')
