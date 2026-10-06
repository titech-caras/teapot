"""Reader-ordered transient replay using the normal copy's LLVM tag model.

Policies and propagation share a visitor so insertion order at one application
instruction is explicit: pending replay, policy, address capture, load replay
and queued-tag apply. No pending runtime queue survives a block or rollback.
"""
from dataclasses import dataclass
from copy import copy
import re

from gtirb_rewriting import Patch

from teapot.configs.blacklist import is_blacklisted_function
from teapot.configs.runtime import (
    DIFT_REG_TAGS_SIZE,
    MEMORY_HISTORY_DATA_OFFSET,
    MEMORY_HISTORY_ENTRY_SIZE,
    MEMORY_HISTORY_SIZE_OFFSET,
)
from teapot.configs.slots import ScratchpadSlots
from teapot.passes.mixins import InstVisitorPassMixin, VisitorPassMixin
from teapot.passes.text.dift.base import TextDiftLLVMBase
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass


@dataclass(frozen=True)
class ReplayRecipe:
    """One existing builder invocation, with its already allocated captures."""
    arguments: tuple
    keywords: tuple
    capture_start: int
    capture_end: int
    queue_apply: bool


@dataclass(frozen=True)
class ReplayEffect:
    instruction: int
    ir: tuple
    registers: frozenset
    memory: bool
    queue: bool
    recipe: ReplayRecipe = None


class TransientDiftReplayMixin:
    REPLAY_SYMBOLS = TextDiftLLVMBase.REPLAY_SYMBOLS | {
        "memory_history_top", "dift_reg_queued_tags", "dift_reg_queue_pending"}

    def __init__(self, reg_manager, section, decoder, arch, *, dift_layout,
                 insert_memlog=True, memory_policy=None, port_policy=None,
                 immediate=False, shadow_mapping_enforcement=False):
        # The x64 text class deliberately disables history. Here the shared
        # initializer enables it, while retaining the target-specific operand
        # model, address capture and register-preserving replay wrapper.
        TextDiftLLVMBase.__init__(self, reg_manager, section, decoder, arch,
                                 dift_layout=dift_layout, insert_memlog=insert_memlog)
        self.memory_policy = memory_policy
        self.port_policy = port_policy
        self.immediate = immediate
        self.shadow_mapping_enforcement = shadow_mapping_enforcement
        if shadow_mapping_enforcement:
            self.REPLAY_SYMBOLS = self.REPLAY_SYMBOLS | {
                "teapot_shadow_registry", "teapot_shadow_registry_count",
                "teapot_shadow_mapping_ready", "memory_history"}

    def _reset(self):
        super()._reset()
        self.scratchpad_offset = ScratchpadSlots.TRANSIENT_DIFT_CAPTURE // 8
        self.pending_registers = set()
        self.pending_memory = False
        self.pending_queue_apply = False
        self.effects = []
        self._elision_pricing = False

    def _get_tempval(self):
        # Named SSA values let a prefix and suffix become independent LLVM
        # functions without renumbering references or capture-slot indices.
        self.tempval_cnt += 1
        return f'%tag{self.tempval_cnt}'

    def _reader_observes_pending(self, registers, *, memory=False):
        return bool(self.llvm_ir) and (
            registers is None or not self.pending_registers.isdisjoint(registers)
            or (memory and self.pending_memory))

    def _required_prefix(self, registers, *, memory=False, queue=False):
        return max((i + 1 for i, effect in enumerate(self.effects)
                    if registers is None or not effect.registers.isdisjoint(registers)
                    or (memory and effect.memory) or (queue and effect.queue)), default=0)

    def _allocate_replay_scratch(self, assembly, registers, live):
        """Use dead GPRs for RISC LLVM bodies; wrappers own remaining spills.

        x64 already remaps through ALLOCATE_BLOCK_PATCH_REGISTERS. RISC bodies
        have no calls and may rename all general temporaries, including LLVM's
        chosen frame register, but never SP/TP/GP or architectural zero.
        """
        if self.arch.name == 'x64':
            dead = len(set(self.reg_manager.abi._scratch_registers()) - live)
            return assembly, registers, max(0, len(registers.registers) - dead)
        movable = [r for r in registers if r.name not in {'sp', 'tp', 'gp', 'zero', 'x31'}]
        pool = list(self.reg_manager.abi._scratch_registers())
        pool += [r for r in movable if r not in pool]
        allocated = ([r for r in pool if r not in live] +
                     [r for r in pool if r in live])[:len(movable)]
        mapping = dict(zip(movable, allocated))

        def replace(match):
            name = match.group(0)
            reg = self.reg_manager.abi.get_register(name)
            target = mapping.get(reg)
            if target is None:
                return name
            if self.arch.name == 'aarch64':
                return name[0] + target.name[1:]
            return target.name

        pattern = (r'\b[wx](?:[0-9]|[12][0-9]|30)\b' if self.arch.name == 'aarch64' else
                   r'\b(?:ra|[ast][0-9]+|x(?:[0-9]|[12][0-9]|3[01]))\b')
        assembly = re.sub(pattern, replace, assembly)
        registers = [mapping.get(r, r) for r in registers]
        wrapper_count = 2 if self.arch.name == 'aarch64' else int(
            any(r.name == 'sp' for r in registers) or bool(re.search(r'\bf[ast][0-9]+\b', assembly)))
        controls = self._plan_scratch_registers(wrapper_count, live).registers
        # Count the actual mapped GPRs plus wrapper temporaries, not just the
        # ABI scratch pool: LLVM may also have used an argument/callee register
        # that is dead at this boundary, and controls can share a body register.
        clobbered = (set(registers) | set(controls)) - {
            self.reg_manager.abi.get_register(name)
            for name in (('sp',) if self.arch.name == 'aarch64' else ('sp', 'tp', 'gp', 'zero'))}
        return assembly, registers, len(clobbered & live)

    def _select_replay(self, block, function, inst_idx, required):
        """Price immutable eager effects; never build or cache an elided body.

        The same instruction builder created these effects with elision off.
        Consequently every legal boundary/prefix has the preceding scheduler's
        exact operations and register cost, irrespective of the new provider.
        This method does not consume effects or change capture/SSA counters.
        """
        # Captures for instruction i are before i, but ordinarily move a batch
        # no earlier than i+1. The terminal instruction's own effects must still
        # be flushed before it transfers control (the existing block contract).
        first = min(self.effects[required - 1].instruction + 1, inst_idx)
        compiled = {}
        best = None
        for index in range(first, inst_idx + 1):
            offset = sum(i.size for i in self._current_instructions[:index])
            adjusted_block, adjusted_index = self.insertion_register_location(block, index)
            # A moved HI/LO insertion is not this instruction boundary. Keep the
            # reader's existing safe placement fallback, but never slide to it.
            if index != inst_idx and (adjusted_block is not block or adjusted_index != index):
                continue
            count = sum(e.instruction < index or index == inst_idx for e in self.effects)
            if count < required:
                continue
            if count not in compiled:
                body = '\n'.join(line for e in self.effects[:count] for line in e.ir)
                module = self._parse_and_optimize_llvm(self._format_llvm_ir(
                    body, target_triple=self.target_triple))
                assembly = self._extract_function_asm(self.target_machine.emit_assembly(module))
                compiled[count] = assembly, self._get_register_usage(assembly)
            assembly, registers = compiled[count]
            plan = self._scratch_plan(function, block, index)
            assembly, registers, spills = self._allocate_replay_scratch(
                assembly, registers, plan.live_registers)
            cost = spills + (self.reg_manager.abi.flag_register() in plan.live_registers)
            # Minimum spills + flag save; stable ties toward the reader.
            key = (cost, -index)
            if best is None or key < best[0]:
                best = key, index, offset, count, assembly, registers, plan
        return best[1:]

    def _rebuild_replay_body(self, effects):
        """Use the same builder only after the eager placement is frozen.

        Private emission buffers/counters isolate this rebuild from pending
        effects and from any subsequent prefix's pricing. Capture patches were
        made once during the eager build; here their original slots are read,
        without resolving relocations or allocating GTIRB nodes/UUIDs again.
        """
        emitter = copy(self)
        emitter.llvm_ir = []
        emitter.tempval_cnt = 0
        emitter.effects = []
        emitter.pending_registers = set()
        emitter.pending_memory = False
        emitter.pending_queue_apply = False
        emitter._elision_pricing = False
        for effect in effects:
            recipe = effect.recipe
            if recipe is None:
                raise ValueError('enforcing replay has no captured builder recipe')
            emitter.scratchpad_offset = recipe.capture_start
            emitter._queue_apply_requested = recipe.queue_apply
            TextDiftLLVMBase._build_dift_patch(
                emitter, *recipe.arguments, **dict(recipe.keywords), emit_capture=False)
            if emitter.scratchpad_offset != recipe.capture_end:
                raise ValueError('replay rebuild changed the original capture slots')
        return '\n'.join(emitter.llvm_ir)

    def _flush_dift(self, block, function, inst_idx, inst_offset, *, required_prefix=None):
        if not self.effects:
            return
        required = len(self.effects) if required_prefix is None else required_prefix
        index, offset, count, assembly, registers, plan = self._select_replay(
            block, function, inst_idx, required)
        if self.shadow_mapping_enforcement:
            body = self._rebuild_replay_body(self.effects[:count])
            module = self._parse_and_optimize_llvm(self._format_llvm_ir(
                body, target_triple=self.target_triple))
            assembly = self._extract_function_asm(self.target_machine.emit_assembly(module))
            # Never use the cheaper pricing body's clobber/scratch set to emit
            # the actual body. Only its prefix, boundary and live set survive.
            assembly, registers, _ = self._allocate_replay_scratch(
                assembly, self._get_register_usage(assembly), plan.live_registers)
        self._emit_replay(block, function, index, offset, assembly, registers, plan)
        self.effects = self.effects[count:]
        if not self.effects:
            self._reset()
        else:
            self.llvm_ir = [line for effect in self.effects for line in effect.ir]
            self.pending_registers = set().union(*(effect.registers for effect in self.effects))
            self.pending_memory = any(effect.memory for effect in self.effects)
            self.pending_queue_apply = any(effect.queue for effect in self.effects)

    def _emit_replay(self, block, function, index, offset, assembly, registers, plan):
        patch = self._build_optimized_dift_values_patch(assembly, registers, scratch_plan=plan)
        if self.ALLOCATE_BLOCK_PATCH_REGISTERS:
            patch = self.allocate_registers(function, block, index)(patch)
        self.insert_at(block, offset, Patch.from_function(patch))

    def begin_module(self, module, functions, rewriting_ctx):
        for policy in (self.memory_policy, self.port_policy):
            if policy is not None:
                VisitorPassMixin.begin_module(policy, module, functions, rewriting_ctx)
        super().begin_module(module, functions, rewriting_ctx)

    def visit_function(self, function):
        # Blacklisting suppresses propagation, not the existing gadget checks.
        self.propagate = not is_blacklisted_function(function)
        InstVisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block, function=None):
        self._reset()
        self.port_reader = None
        policy = self.port_policy
        if policy is not None:
            instructions = policy._conditional_branch_instructions(block)
            if instructions is not None:
                idx = policy.predicate_instruction_index(instructions)
                if idx is not None and not self.arch.is_instrumentation_helper_instruction(
                        instructions[idx], idx, instructions):
                    offset = sum(i.size for i in instructions[:idx])
                    info = policy.build_patch(block, instructions[idx], offset)
                    if info is not None:
                        self.port_reader = (idx, info)
        # Unlike text DIFT, flush AFTER the final instruction's capture and
        # policy insertions, but BEFORE that instruction executes/transfers.
        InstVisitorPassMixin.visit_code_block(self, block, function)

    def visit_inst(self, inst, inst_idx, inst_offset, block, function=None, live_registers=None):
        memory = self.memory_policy
        info = None
        if memory is not None:
            memory._current_instructions = self._current_instructions
            memory._current_block = block
            info = memory._build_policy_patch(inst, inst_idx, inst_offset, block, function)
        port = self.port_reader if self.port_reader and self.port_reader[0] == inst_idx else None
        rep = self.arch.name == "x64" and self.arch.rep_string_kind(inst) is not None
        memory_reads_pending = info is not None and (
            self._reader_observes_pending(info.tag_registers, memory=info.reads_memory_tags)
            # There is one runtime queue. Consume the previous load's queued
            # tags before another policy can enqueue tags for a different load.
            or (info.queues_tags and self.pending_queue_apply))
        port_reads_pending = port is not None and self._reader_observes_pending(
            port[1][1], memory=self.arch.memory_operand(inst) is not None)
        if memory_reads_pending or port_reads_pending or rep:
            required = len(self.effects) if rep else max(
                self._required_prefix(info.tag_registers, memory=info.reads_memory_tags,
                                      queue=info.queues_tags) if info is not None else 0,
                self._required_prefix(port[1][1], memory=self.arch.memory_operand(inst) is not None)
                if port is not None else 0)
            self._flush_dift(block, function, inst_idx, inst_offset, required_prefix=required)
        if info is not None:
            self.reg_manager.add_live_registers(function, block, inst_idx, info.live_registers)
            patch = memory.allocate_registers(function, block, inst_idx)(info.patch)
            memory.insert_at(block, inst_offset, Patch.from_function(patch))
        if port is not None:
            patch, registers = port[1]
            self.reg_manager.add_live_registers(function, block, inst_idx, registers)
            patch = self.port_policy.allocate_registers(function, block, inst_idx)(patch)
            self.port_policy.insert_at(block, inst_offset, Patch.from_function(patch))
        self._queue_apply_requested = info is not None and info.queues_tags
        self._effect_index = inst_idx
        if not rep and getattr(self, "propagate", True):
            # REP's transient replacement already owns per-element propagation
            # and policies. Never call the normal-copy post-REP tag handler.
            TextDiftLLVMBase.visit_inst(self, inst, inst_idx, inst_offset,
                                       block, function, live_registers)
        if self.immediate or inst_idx == len(self._current_instructions) - 1:
            self._flush_dift(block, function, inst_idx, inst_offset)

    def _build_dift_patch(self, block, inst, inst_offset, regs_read, regs_write, **kwargs):
        start = len(self.llvm_ir)
        capture_start = self.scratchpad_offset
        # Capture allocation and pending state follow the old eager builder.
        # No elided IR is generated until _select_replay has frozen a prefix.
        self._elision_pricing = self.shadow_mapping_enforcement
        try:
            patch = super()._build_dift_patch(block, inst, inst_offset, regs_read, regs_write, **kwargs)
        finally:
            self._elision_pricing = False
        recipe = (ReplayRecipe(
            (block, inst, inst_offset, frozenset(regs_read), frozenset(regs_write)), tuple(kwargs.items()),
            capture_start, self.scratchpad_offset, getattr(self, '_queue_apply_requested', True))
            if self.shadow_mapping_enforcement else None)
        self.pending_registers.update(regs_write)
        self.pending_memory |= kwargs['mem_write'] is not None
        self.effects.append(ReplayEffect(
            getattr(self, '_effect_index', 0), tuple(self.llvm_ir[start:]), frozenset(regs_write),
            kwargs['mem_write'] is not None,
            kwargs['mem_read'] is not None and getattr(self, '_queue_apply_requested', True), recipe))
        return patch

    def _format_llvm_ir(self, body, *, target_triple=None):
        ir = super()._format_llvm_ir(body, target_triple=target_triple)
        globals = f"""
@memory_history_top = external dso_local global ptr
@dift_reg_queued_tags = external dso_local global [{DIFT_REG_TAGS_SIZE} x i8]
@dift_reg_queue_pending = external dso_local global i8
"""
        if self.shadow_mapping_enforcement:
            globals += """
@teapot_shadow_registry = external dso_local global [64 x [3 x i64]]
@teapot_shadow_registry_count = external dso_local global i64
@teapot_shadow_mapping_ready = external dso_local global i64
@memory_history = external dso_local global i8
"""
        return ir.replace("define dso_local void @func", globals + "\ndefine dso_local void @func")

    def _after_instruction_effects(self, mem_read):
        if mem_read is None or not getattr(self, '_queue_apply_requested', True):
            return
        self.pending_queue_apply = True
        pending = self._load("i8", "@dift_reg_queue_pending")
        empty = self._icmp("eq", "i8", pending, 0)
        label = f"queued_{self.tempval_cnt}"
        self._br_cond(empty, f"%{label}_done", f"%{label}_apply")
        self._label(label + "_apply")
        self._store("i8", 0, "@dift_reg_queue_pending")
        for offset in range(0, DIFT_REG_TAGS_SIZE, 8):
            tags = self._build_gep("i8", "dift_reg_tags", offset, ptr_type=self.DIFT_REG_TAGS_TYPE)
            queued = self._build_gep("i8", "dift_reg_queued_tags", offset, ptr_type=self.DIFT_REG_TAGS_TYPE)
            merged = self._or("i64", self._load("i64", tags, align=8),
                              self._load("i64", queued, align=8))
            self._store("i64", merged, tags, align=8)
            self._store("i64", 0, queued, align=8)
        self._br(f"%{label}_done")
        self._label(label + "_done")

    def _shadow_store_noop_proof(self, address, width):
        """Prove a full chunk in the enforcing runtime's normal-RW DIFT registry.

        Only the fingerprinted enforcing contract enables this provider. The
        single-owner program rule excludes unmediated mapping mutations. The
        runtime registry records successful anonymous private RW DIFT mappings,
        not merely startup observations or arbitrary protected storage. Legacy
        contracts emit exactly the preceding eager path.
        """
        if not self.shadow_mapping_enforcement or getattr(self, '_elision_pricing', False):
            return None
        index = self._get_tempval()
        next_index = self._get_tempval()
        label = f"owned_shadow_{self.tempval_cnt}"
        guard, entry, loop, hit, step, done = (label + '_' + name
                                              for name in ('guard','entry','loop','hit','step','done'))
        self._br('%'+guard)
        self._label(guard)
        ready = self._icmp('eq','i64',self._load('i64','@teapot_shadow_mapping_ready',volatile=True),1)
        count = self._load('i64','@teapot_shadow_registry_count',volatile=True)
        nonempty = self._icmp('ugt','i64',count,0)
        bounded = self._icmp('ule','i64',count,64)
        number = self._build_inst(f'ptrtoint ptr {address} to i64')
        last = self._add('i64',number,width-1)
        nowrap = self._icmp('uge','i64',last,number)
        top = self._load('ptr','@memory_history_top',volatile=True)
        top_number = self._build_inst(f'ptrtoint ptr {top} to i64')
        base = self._build_inst('ptrtoint ptr @memory_history to i64')
        offset = self._build_inst(f'sub i64 {top_number}, {base}')
        in_history = self._icmp('uge','i64',top_number,base)
        capacity = self._icmp('ule','i64',offset,(1048576-1)*MEMORY_HISTORY_ENTRY_SIZE)
        # The independently required capacity bound is below 2**32. Check
        # divisibility in that domain; 64-bit constant division can make the
        # RV64 backend emit an out-of-body constant pool, forbidden in replay.
        small_offset = self._build_inst(f'trunc i64 {offset} to i32')
        alignment = self._build_inst(f'urem i32 {small_offset}, {MEMORY_HISTORY_ENTRY_SIZE}')
        aligned = self._icmp('eq','i32',alignment,0)
        valid = ready
        for condition in (nonempty,bounded,nowrap,in_history,capacity,aligned):
            valid = self._build_inst(f'and i1 {valid}, {condition}')
        self._br_cond(valid,'%'+entry,'%'+done)
        self._label(entry)
        self._br('%'+loop)
        self._label(loop)
        self.llvm_ir.append(f'{index} = phi i64 [ 0, %{entry} ], [ {next_index}, %{step} ]')
        fields=[]
        for field in range(3):
            ptr = self._build_inst(f'getelementptr [64 x [3 x i64]], ptr @teapot_shadow_registry, i64 0, i64 {index}, i64 {field}')
            fields.append(self._load('i64',ptr,align=8))
        lower = self._icmp('uge','i64',number,fields[0])
        upper = self._icmp('ult','i64',last,fields[1])
        writable = self._icmp('eq','i64',fields[2],1)
        match = self._build_inst(f'and i1 {lower}, {upper}')
        match = self._build_inst(f'and i1 {match}, {writable}')
        self._br_cond(match,'%'+hit,'%'+step)
        self._label(hit)
        self._br('%'+done)
        self._label(step)
        self.llvm_ir.append(f'{next_index} = add i64 {index}, 1')
        more = self._icmp('ult','i64',next_index,count)
        self._br_cond(more,'%'+loop,'%'+done)
        self._label(done)
        return self._build_inst(f'phi i1 [ false, %{guard} ], [ true, %{hit} ], [ false, %{step} ]')

    def _shadow_store_value(self, tag, width):
        value = tag
        if width != 1:
            type = f"i{width * 8}"
            value = self._build_inst(f"zext i8 {tag} to {type}")
            value = self._build_inst(f"mul {type} {value}, {int.from_bytes(bytes([1]) * width, 'little')}")
        return value

    def _store_shadow_mem_tags(self, tag, mem_addr, offset, size):
        # A replay may be interrupted by the application's fault handler at
        # any instruction. Volatile history publication and tag mutation keep
        # the old bytes recoverable before each store becomes visible.
        while size:
            width = next(n for n in (8, 4, 2, 1) if n <= size)
            byte_addr = mem_addr if offset == 0 else self._add("i64", mem_addr, offset)
            address = self._inttoptr("i64", self._xor("i64", byte_addr, self.dift_layout.xor_mask))
            type = f"i{width * 8}"
            value = None
            done = None
            if self.insert_memlog:
                old = self._load(type, address, dift_mem=True, volatile=True, align=1)
                proof = self._shadow_store_noop_proof(address, width)
                if proof is not None:
                    # Compare the entire actual store value with this write's
                    # already-loaded old value, not the original window value.
                    value = self._shadow_store_value(tag, width)
                    equal = self._icmp("eq", type, old, value)
                    noop = self._build_inst(f"and i1 {proof}, {equal}")
                    label = f"shadow_write_{self.tempval_cnt}"
                    done = label + "_done"
                    self._br_cond(noop, f"%{done}", f"%{label}")
                    self._label(label)
                if width != 8:
                    old = self._build_inst(f"zext {type} {old} to i64")
                top = self._load("ptr", "@memory_history_top", volatile=True)
                data = self._build_inst(f"getelementptr i8, ptr {top}, i64 {MEMORY_HISTORY_DATA_OFFSET}")
                length = self._build_inst(f"getelementptr i8, ptr {top}, i64 {MEMORY_HISTORY_SIZE_OFFSET}")
                self._store("ptr", address, top, volatile=True)
                self._store("i64", old, data, volatile=True)
                self._store("i8", width, length, volatile=True)
                next_top = self._build_inst(f"getelementptr i8, ptr {top}, i64 {MEMORY_HISTORY_ENTRY_SIZE}")
                self._store("ptr", next_top, "@memory_history_top", volatile=True)
            if value is None:
                value = self._shadow_store_value(tag, width)
            self._store(type, value, address, dift_mem=True, volatile=True, align=1)
            if done is not None:
                self._br(f"%{done}")
                self._label(done)
            size -= width
            offset += width


class X64TransientDiftLLVMPass(TransientDiftReplayMixin, X64TextDiftPropagationLLVMPass):
    pass


class AArch64TransientDiftLLVMPass(TransientDiftReplayMixin, AArch64TextDiftPropagationLLVMPass):
    pass


class RISCV64TransientDiftLLVMPass(TransientDiftReplayMixin, RISCV64TextDiftPropagationLLVMPass):
    pass


def transient_replay_pass(arch, *args, **kwargs):
    kind = {"x64": X64TransientDiftLLVMPass, "aarch64": AArch64TransientDiftLLVMPass,
            "riscv64": RISCV64TransientDiftLLVMPass}[arch.name]
    return kind(*args, arch, **kwargs)
