"""Pinned Linux ELF64 contracts for final-linked instrumented components."""

TARGETS = {
    'X64': dict(machine='EM_X86_64', checkpoint='make_checkpoint_x64',
                marker=bytes.fromhex('4887db904887d290')),
    'ARM64': dict(machine='EM_AARCH64', checkpoint='make_checkpoint_aarch64',
                  marker=bytes.fromhex('9f2280d29fa280d2')),
    'RISCV64': dict(machine='EM_RISCV', checkpoint='make_checkpoint_riscv64',
                    marker=bytes.fromhex('1300401113004051')),
}


# Instrumentation modes. Each keeps the ISA contract above and names the DIFT
# layout, ASan tag storage and ASan runtime that the final link must use.
# "default" keeps each ISA's historical component mode.
MODES = {
    'x64': dict(isa='X64', layout='x64-la48-asan-new', tag_storage='shadow', asan='libasan.so.8'),
    'aarch64-vma42': dict(isa='ARM64', layout='aarch64-vma42', tag_storage='shadow', asan='libasan.so.5'),
    'aarch64-vma39': dict(isa='ARM64', layout='aarch64-vma39', tag_storage='shadow', asan='libasan.so.5'),
    'aarch64-vma42-mte': dict(isa='ARM64', layout='aarch64-vma42', tag_storage='mte', asan=None),
    'aarch64-vma48': dict(isa='ARM64', layout='aarch64-vma48', tag_storage='shadow', asan='libasan.so.5'),
    'aarch64-vma48-mte': dict(isa='ARM64', layout='aarch64-vma48', tag_storage='mte', asan=None),
    'riscv64': dict(isa='RISCV64', layout='riscv64-sv39', tag_storage='shadow', asan='libasan.so.8'),
}
DEFAULT_MODE = {'X64': 'x64', 'ARM64': 'aarch64-vma42', 'RISCV64': 'riscv64'}


def mode_for(isa, name=None):
    name = name or DEFAULT_MODE[isa]
    mode = MODES[name]
    if mode['isa'] != isa:
        raise ValueError('mode %s does not apply to %s inputs' % (name, isa))
    return name, mode


def for_machine(machine):
    matches = [(isa, target) for isa, target in TARGETS.items() if target['machine'] == machine]
    if len(matches) != 1:
        raise ValueError('unsupported component ELF architecture: ' + machine)
    return matches[0]


def mode_metadata(isa, name=None):
    name, mode = mode_for(isa, name)
    return dict(isa=isa, mode=name, dift_layout=mode['layout'], tag_storage=mode['tag_storage'])
