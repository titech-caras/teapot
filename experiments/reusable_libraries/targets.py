"""Pinned Linux ELF64 contracts for final-linked instrumented components."""

TARGETS = {
    'X64': dict(machine='EM_X86_64', layout='x64-la48-asan-new', asan='libasan.so.8',
                checkpoint='make_checkpoint_x64', marker=bytes.fromhex('4887db904887d290')),
    'ARM64': dict(machine='EM_AARCH64', layout='aarch64-vma42', asan='libasan.so.5',
                  checkpoint='make_checkpoint_aarch64', marker=bytes.fromhex('9f2280d29fa280d2')),
    'RISCV64': dict(machine='EM_RISCV', layout='riscv64-sv39', asan='libasan.so.8',
                    checkpoint='make_checkpoint_riscv64', marker=bytes.fromhex('1300401113004051')),
}


def for_machine(machine):
    matches = [(isa, target) for isa, target in TARGETS.items() if target['machine'] == machine]
    if len(matches) != 1:
        raise ValueError('unsupported component ELF architecture: ' + machine)
    return matches[0]
