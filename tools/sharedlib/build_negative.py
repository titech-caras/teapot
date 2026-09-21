"""Build unsupported ELF-feature fixtures; only resulting ELFs are staged."""
import json
from pathlib import Path
import shutil
from build_inputs import WORK, HERE, run


if __name__ == '__main__':
    build = WORK / 'groundtruth/negative'
    inputs = WORK / 'inputs/negative'
    build.mkdir(parents=True, exist_ok=True)
    inputs.mkdir(parents=True, exist_ok=True)
    cases = {}
    for name, define, code in (
        ('tls', 'TLS_CASE', 'TLS_SECTION'),
        ('weak', 'WEAK_CASE', 'WEAK_BINDING'),
        ('protected', 'PROTECTED_CASE', 'UNSUPPORTED_VISIBILITY'),
        ('ifunc', 'IFUNC_CASE', 'IFUNC_SYMBOL'),
        ('lookup', 'LOOKUP_CASE', 'RUNTIME_SYMBOL_LOOKUP'),
        ('constructor', 'CTOR_CASE', 'CUSTOM_CONSTRUCTOR_OR_DESTRUCTOR'),
        ('destructor', 'DTOR_CASE', 'CUSTOM_CONSTRUCTOR_OR_DESTRUCTOR'),
        ('unique', 'UNIQUE_CASE', 'GNU_UNIQUE_BINDING'),
    ):
        run(build, 'negative-' + name, ['gcc', '-O2', '-g', '-fPIC', '-shared',
            '-D' + define, HERE / 'fixtures/negative.c', '-Wl,-soname,libalpha.so', '-o', name + '.so'])
        cases[name] = code
    variants = [
        ('version', ['-Wl,--version-script=' + str(HERE / 'fixtures/negative.map')], 'SELECTED_SYMBOL_VERSION_DEFINITION'),
        ('symbolic', ['-Wl,-Bsymbolic'], 'UNSUPPORTED_DYNAMIC_TAG'),
        ('redirect-init', ['-Wl,-init,feature'], 'REDIRECTED_DT_INIT'),
        ('redirect-fini', ['-Wl,-fini,feature'], 'REDIRECTED_DT_FINI'),
        ('gmon', ['-DHOOK_CASE'], 'CALLABLE_CRT_HOOK'),
    ]
    for name, extra, code in variants:
        run(build, 'negative-' + name, ['gcc', '-O2', '-g', '-fPIC', '-shared',
            HERE / 'fixtures/negative.c', '-Wl,-soname,libalpha.so', '-o', name + '.so'] + extra)
        cases[name] = code
    run(build, 'negative-exception', ['g++', '-O2', '-g', '-fPIC', '-shared',
        HERE / 'fixtures/negative-exception.cc', '-Wl,-soname,libalpha.so', '-o', 'exception.so'])
    cases['exception'] = 'NONLOCAL_UNWIND'
    run(build, 'negative-copy-v2', ['gcc', '-no-pie', '-fno-pic', '-Wl,--no-as-needed', HERE / 'fixtures/copy-main.c',
        '-L' + str(WORK / 'inputs/fixture-v2'), '-lalpha', '-lbeta', '-o', 'copy-main'])
    for name in cases:
        shutil.copy2(build / (name + '.so'), inputs / (name + '.so'))
    shutil.copy2(build / 'copy-main', inputs / 'copy-main')
    for name in ('main', 'libalpha.so', 'libbeta.so'):
        shutil.copy2(WORK / 'inputs/fixture-v2' / name, inputs / name)
    (build / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
