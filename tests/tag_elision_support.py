"""Controlled-fixture proof provider; never imported by production code."""
from pathlib import Path
import re
import subprocess
from types import MethodType, SimpleNamespace

from teapot.passes.transient.lazy_dift import transient_replay_pass


def owned_fixture_proof(self, address, width):
    # The C harness owns anonymous private RW memory, is single-threaded, and
    # does not change its proven range's protections until rollback completes.
    # It withdraws this proof before deliberate shadow protection faults.
    # Bounds are live fixture-owned state, not a startup permission snapshot.
    start = self._load('i64', self._build_gep('i64', 'tag_elision_bounds', 0,
                                            ptr_type='[2 x i64]'), volatile=True)
    end = self._load('i64', self._build_gep('i64', 'tag_elision_bounds', 1,
                                          ptr_type='[2 x i64]'), volatile=True)
    number = self._build_inst(f'ptrtoint ptr {address} to i64')
    last = self._add('i64', number, width-1)
    lower = self._icmp('uge', 'i64', number, start)
    upper = self._icmp('ult', 'i64', last, end)
    nowrap = self._icmp('uge', 'i64', last, number)
    both = self._build_inst(f'and i1 {lower}, {upper}')
    return self._build_inst(f'and i1 {both}, {nowrap}')


def replay_for(arch, *, proof=False):
    replay = transient_replay_pass(arch, SimpleNamespace(abi=arch.abi), None, None,
                                   dift_layout=SimpleNamespace(xor_mask=0))
    if proof:
        replay._shadow_store_noop_proof = MethodType(owned_fixture_proof, replay)
        replay.REPLAY_SYMBOLS = replay.REPLAY_SYMBOLS | {'tag_elision_bounds'}
    replay._reset()
    return replay


def format_ir(replay, name):
    ir = replay._format_llvm_ir('\n'.join(replay.llvm_ir), target_triple=replay.target_triple)
    # Fixtures link several genuine replay bodies into one binary; all bodies
    # use exactly the same runtime globals owned by the C harness.
    ir = re.sub(r'(@(?:scratchpad|dift_reg_tags)) = dso_local local_unnamed_addr global (\[[^\]]+\]) zeroinitializer, align \d+',
                r'\1 = external dso_local global \2', ir)
    ir = ir.replace('define dso_local void @func',
                    '@tag_elision_bounds = external dso_local global [2 x i64]\n'
                    '@tag_elision_fault_stage = external dso_local global i64\n'
                    '@tag_elision_fault_address = external dso_local global ptr\n'
                    f'define dso_local void @{name}')
    return ir


def emit_object(replay, name, root):
    raw = format_ir(replay, name)
    (root/(name+'.ll')).write_text(raw)
    module = replay._parse_and_optimize_llvm(raw)
    assembly = replay.target_machine.emit_assembly(module)
    # Production extractor is deliberately validated before saving a renamed
    # test symbol. It must contain no discarded constant-pool reference/call.
    replay._extract_function_asm(assembly.replace(name+':', 'func:'))
    (root/(name+'.s')).write_text(assembly)
    (root/(name+'.opt.ll')).write_text(str(module))
    path = root/(name+'.o')
    path.write_bytes(replay.target_machine.emit_object(module))
    return path


def build_run(arch, mode, root, source, objects):
    source_path = root/'fixture.c'
    source_path.write_text(source)
    cc = 'gcc' if arch.name == 'x64' else arch.name+'-linux-gnu-gcc'
    flags = ['-march=rv64gc', '-mabi=lp64d', '-Wl,--no-relax'] if arch.name == 'riscv64' else []
    if mode == 'aarch64-mte':
        flags += ['-march=armv8.5-a+memtag']
    build = subprocess.run([cc, '-O2', '-no-pie', *flags, source_path, *objects,
                            '-o', root/'fixture'], capture_output=True, text=True)
    (root/'build.stdout').write_text(build.stdout)
    (root/'build.stderr').write_text(build.stderr)
    (root/'build.exit').write_text(str(build.returncode)+'\n')
    if build.returncode:
        raise AssertionError(build.stderr)
    launcher = [] if arch.name == 'x64' else ['qemu-'+arch.name, '-L', '/usr/'+arch.name+'-linux-gnu']
    if mode == 'aarch64-mte':
        launcher = ['/usr/local/bin/qemu-aarch64-mte', '-cpu', 'max', '-L', '/opt/aarch64-mte-sysroot']
    run = subprocess.run([*launcher, root/'fixture'], capture_output=True, text=True, timeout=45)
    (root/'run.stdout').write_text(run.stdout)
    (root/'run.stderr').write_text(run.stderr)
    (root/'run.exit').write_text(str(run.returncode)+'\n')
    if run.returncode:
        raise AssertionError(run.stdout+run.stderr)
    return run.stdout


def inject_fault(self, stage):
    """Test-only instruction boundary fault, not a production extra load."""
    selected = self._load('i64', '@tag_elision_fault_stage', volatile=True)
    matched = self._icmp('eq', 'i64', selected, stage)
    label = f'inject_{self.tempval_cnt}'
    self._br_cond(matched, '%'+label, '%'+label+'_done')
    self._label(label)
    pointer = self._load('ptr', '@tag_elision_fault_address', volatile=True)
    self._load('i8', pointer, volatile=True)
    self._br('%'+label+'_done')
    self._label(label+'_done')


def install_fault_boundaries(replay):
    """Stages: before/after old load, after every log field/top, after store."""
    old_load = replay._load
    old_store = replay._store
    counter = [1]

    def load(self, type, address, *, dift_mem=False, **kwargs):
        if dift_mem and kwargs.get('volatile'):
            inject_fault(self, counter[0])
            counter[0] += 1
        value = old_load(type, address, dift_mem=dift_mem, **kwargs)
        if dift_mem and kwargs.get('volatile'):
            inject_fault(self, counter[0])
            counter[0] += 1
        return value

    def store(self, type, value, address, *, dift_mem=False, **kwargs):
        old_store(type, value, address, dift_mem=dift_mem, **kwargs)
        if kwargs.get('volatile'):
            inject_fault(self, counter[0])
            counter[0] += 1

    replay._load = MethodType(load, replay)
    replay._store = MethodType(store, replay)
    replay.REPLAY_SYMBOLS = replay.REPLAY_SYMBOLS | {
        'tag_elision_fault_stage', 'tag_elision_fault_address'}
