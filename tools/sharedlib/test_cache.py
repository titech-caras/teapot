"""Host end-to-end ordinary cache hit, invalidation and integrity checks."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

from run_conversion import WORK, command


OUT = WORK / 'artifacts/cache-tests-v1'
CACHE = WORK / 'cache/ordinary'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label, dataset, revision, selected, cache=CACHE, expected_exit=0):
    argv = command(dataset, revision, 'main', selected, cache)
    started = time.time()
    with (OUT / (label + '.stdout')).open('wb') as stdout, (OUT / (label + '.stderr')).open('wb') as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr)
    record = {'command': argv, 'exit': result.returncode, 'seconds': time.time()-started}
    (OUT / (label + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    assert result.returncode == expected_exit, (label, record)
    return WORK / 'artifacts' / dataset / revision, record


def state(directory):
    return {name: json.loads((directory / name / 'cache.json').read_text())
            for name in ('executable', 'selected-000', 'selected-001')}


if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=False)
    cold = WORK / 'artifacts/fixture-v2/cache-cold'
    assert all(s['object'] == s['lift'] == 'miss' for s in state(cold).values())
    warm, warm_time = run('warm', 'fixture-v2', 'cache-warm-v1', ['libalpha.so', 'libbeta.so'])
    assert all(s['object'] == 'hit' for s in state(warm).values())
    assert sha(cold / 'monolith') == sha(warm / 'monolith')
    reordered, reordered_time = run('binding-order', 'fixture-v2', 'cache-reordered-v1', ['libbeta.so', 'libalpha.so'])
    assert all(s['object'] == 'miss' and s['lift'] == 'hit' for s in state(reordered).values())
    inputs = WORK / 'inputs/cache-input-changed'
    inputs.mkdir(parents=True, exist_ok=False)
    subprocess.run(['objcopy', '--add-section', '.note.cache-probe=' +
        str(Path(__file__).parent / 'fixtures/cache-note.txt'),
        str(WORK / 'inputs/fixture-v2/main'), str(inputs / 'main')], check=True)
    for name in ('libalpha.so', 'libbeta.so'):
        shutil.copy2(WORK / 'inputs/fixture-v2' / name, inputs / name)
    changed, changed_time = run('elf-contents', 'cache-input-changed', 'cache-changed-v1', ['libalpha.so', 'libbeta.so'])
    states = state(changed)
    assert all(s['object'] == 'miss' for s in states.values())
    assert states['executable']['lift'] == 'miss'
    assert states['selected-000']['lift'] == states['selected-001']['lift'] == 'hit'
    tampered = OUT / 'tampered-cache'
    shutil.copytree(CACHE, tampered)
    key = state(cold)['selected-000']['object_key']
    obj = tampered / 'objects' / key / 'artifacts/reconstructed.o'
    data = bytearray(obj.read_bytes())
    data[-1] ^= 1
    obj.write_bytes(data)
    rejected, reject_time = run('corruption', 'fixture-v2', 'cache-corrupt-v1',
        ['libalpha.so', 'libbeta.so'], cache=tampered, expected_exit=2)
    rejection = json.loads((rejected / 'rejection.json').read_text())
    assert rejection['reason'].startswith('CACHE_INTEGRITY:')
    assert not (rejected / 'monolith').exists()
    values = [-99, -7, -1, 0, 1, 2, 3, 7, 10, 17, 99]
    cases = []
    for value in values:
        expected = subprocess.run([str(WORK / 'inputs/fixture-v2/main'), str(value)], capture_output=True)
        for label, directory in (('warm', warm), ('reordered', reordered), ('changed', changed)):
            actual = subprocess.run([str(directory / 'monolith'), str(value)], capture_output=True)
            assert (actual.returncode, actual.stdout, actual.stderr) == (expected.returncode, expected.stdout, expected.stderr)
            cases.append({'variant': label, 'value': value, 'exit': actual.returncode,
                          'stdout': actual.stdout.decode(), 'stderr': actual.stderr.decode()})
    result = {'passed': True, 'cache_kind': 'ordinary recovered GTIRB + ET_REL, not instrumentation',
        'cold': state(cold), 'warm': state(warm), 'binding_order_changed': state(reordered),
        'elf_contents_changed': states, 'corruption': rejection,
        'timing_seconds': {label: record['seconds'] for label, record in
            [('warm', warm_time), ('reordered', reordered_time), ('changed', changed_time), ('corruption', reject_time)]},
        'ordinary_semantic_cases': cases, 'cold_warm_monolith_sha256': sha(warm / 'monolith')}
    (OUT / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Cache tests passed; 33 ordinary comparisons, IR/object hits, dependency/input invalidation and corruption rejection.')
