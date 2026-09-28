"""Reader-ordered transient replay using the normal copy's LLVM tag model.

Policies and propagation share a visitor so insertion order at one application
instruction is explicit: pending replay, policy, address capture, load replay
and queued-tag apply. No pending runtime queue survives a block or rollback.
"""
from gtirb_rewriting import Patch

from teapot.configs.blacklist import is_blacklisted_function
from teapot.configs.runtime import MEMORY_HISTORY_ENTRY_SIZE, MEMORY_HISTORY_SIZE_OFFSET
from teapot.configs.slots import ScratchpadSlots
from teapot.passes.mixins import InstVisitorPassMixin, VisitorPassMixin
from teapot.passes.text.dift.base import TextDiftLLVMBase
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass


class TransientDiftReplayMixin:
    REPLAY_SYMBOLS = TextDiftLLVMBase.REPLAY_SYMBOLS | {
        "memory_history_top", "dift_reg_queued_tags", "dift_reg_queue_pending"}

    def __init__(self, reg_manager, section, decoder, arch, *, dift_layout=None,
                 insert_memlog=True, memory_policy=None, port_policy=None,
                 immediate=False):
        # The x64 text class deliberately disables history. Here the shared
        # initializer enables it, while retaining the target-specific operand
        # model, address capture and register-preserving replay wrapper.
        TextDiftLLVMBase.__init__(self, reg_manager, section, decoder, arch,
                                 dift_layout=dift_layout, insert_memlog=insert_memlog)
        self.memory_policy = memory_policy
        self.port_policy = port_policy
        self.immediate = immediate

    def _reset(self):
        super()._reset()
        self.scratchpad_offset = ScratchpadSlots.TRANSIENT_DIFT_CAPTURE // 8
        self.pending_registers = set()
        self.pending_memory = False
        self.pending_queue_apply = False

    def _reader_observes_pending(self, registers, *, memory=False):
        return bool(self.llvm_ir) and (
            registers is None or not self.pending_registers.isdisjoint(registers)
            or (memory and self.pending_memory))

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
            self._flush_dift(block, function, inst_idx, inst_offset)
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
        if not rep and getattr(self, "propagate", True):
            # REP's transient replacement already owns per-element propagation
            # and policies. Never call the normal-copy post-REP tag handler.
            TextDiftLLVMBase.visit_inst(self, inst, inst_idx, inst_offset,
                                       block, function, live_registers)
        if self.immediate or inst_idx == len(self._current_instructions) - 1:
            self._flush_dift(block, function, inst_idx, inst_offset)

    def _build_dift_patch(self, block, inst, inst_offset, regs_read, regs_write, **kwargs):
        patch = super()._build_dift_patch(block, inst, inst_offset, regs_read, regs_write, **kwargs)
        self.pending_registers.update(regs_write)
        self.pending_memory |= kwargs['mem_write'] is not None
        return patch

    def _format_llvm_ir(self, body, *, target_triple=None):
        ir = super()._format_llvm_ir(body, target_triple=target_triple)
        globals = """
@memory_history_top = external dso_local global ptr
@dift_reg_queued_tags = external dso_local global [48 x i8]
@dift_reg_queue_pending = external dso_local global i8
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
        for offset in range(0, 48, 8):
            tags = self._build_gep("i8", "dift_reg_tags", offset, ptr_type=self.DIFT_REG_TAGS_TYPE)
            queued = self._build_gep("i8", "dift_reg_queued_tags", offset, ptr_type=self.DIFT_REG_TAGS_TYPE)
            merged = self._or("i64", self._load("i64", tags, align=8),
                              self._load("i64", queued, align=8))
            self._store("i64", merged, tags, align=8)
            self._store("i64", 0, queued, align=8)
        self._br(f"%{label}_done")
        self._label(label + "_done")

    def _store_shadow_mem_tags(self, tag, mem_addr, offset, size):
        # A replay may be interrupted by the application's fault handler at
        # any instruction. Volatile history publication and tag mutation keep
        # the old bytes recoverable before each store becomes visible.
        while size:
            width = next(n for n in (8, 4, 2, 1) if n <= size)
            byte_addr = mem_addr if offset == 0 else self._add("i64", mem_addr, offset)
            address = self._inttoptr("i64", self._xor("i64", byte_addr, self.dift_layout.xor_mask))
            type = f"i{width * 8}"
            if self.insert_memlog:
                old = self._load(type, address, dift_mem=True, volatile=True, align=1)
                if width != 8:
                    old = self._build_inst(f"zext {type} {old} to i64")
                top = self._load("ptr", "@memory_history_top", volatile=True)
                data = self._build_inst(f"getelementptr i8, ptr {top}, i64 8")
                length = self._build_inst(f"getelementptr i8, ptr {top}, i64 {MEMORY_HISTORY_SIZE_OFFSET}")
                self._store("ptr", address, top, volatile=True)
                self._store("i64", old, data, volatile=True)
                self._store("i8", width, length, volatile=True)
                next_top = self._build_inst(f"getelementptr i8, ptr {top}, i64 {MEMORY_HISTORY_ENTRY_SIZE}")
                self._store("ptr", next_top, "@memory_history_top", volatile=True)
            value = tag
            if width != 1:
                value = self._build_inst(f"zext i8 {tag} to {type}")
                value = self._build_inst(f"mul {type} {value}, {int.from_bytes(bytes([1]) * width, 'little')}")
            self._store(type, value, address, dift_mem=True, volatile=True, align=1)
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
