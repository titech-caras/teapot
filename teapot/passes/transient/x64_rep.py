from dataclasses import replace
import warnings

from capstone import CS_AC_READ, CS_OP_MEM
from gtirb_rewriting import Patch

from teapot.configs.blacklist import is_blacklisted_function
from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import ScratchpadSlots
from teapot.configs.tags import TAG_SECRET, TAG_SECRET_INDIRECT
from teapot.passes.common.dift.x64 import X64DiftOperandHelpers
from teapot.passes.mixins import InstVisitorPassMixin
from teapot.passes.transient.gadget_policy.mem_operand.x64 import X64TransientMemOperandPoliciesPass


class X64TransientRepPass(X64DiftOperandHelpers):
    """Execute one string element per budget unit, with reversible side effects."""

    def __init__(self, *args, enable_dift=True, enable_checkpoints=True,
                 enable_mem_policy=True, enable_asan_check=True, enable_port_policy=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.enable_dift = enable_dift
        self.enable_checkpoints = enable_checkpoints
        self.enable_mem_policy = enable_mem_policy
        self.enable_port_policy = enable_port_policy
        self._warned_rep_addresses = set()
        self.mem_policy = X64TransientMemOperandPoliciesPass(
            self.reg_manager, self.section, self.decoder, self.arch,
            dift_layout=self.dift_layout, enable_asan_check=enable_asan_check)

    def visit_function(self, function):
        # Unlike ordinary DIFT, bounded execution and memory history are
        # mandatory even in functions excluded from normal tag propagation.
        InstVisitorPassMixin.visit_function(self, function)

    def visit_inst(self, inst, inst_idx, inst_offset, block, function=None, live_registers=None):
        effects = self._rep_string_effects(inst)
        if effects is None:
            return
        if not self.enable_checkpoints:
            raise ValueError(f"Transient REP at {inst.address:#x} requires checkpoints for a bounded iteration budget")
        if self.arch.instruction_must_rollback(inst):
            # The restore-point pass inserts the normal EXT_LIB rollback before
            # this instruction. Leave its bytes intact; never expand its loop.
            if inst.address not in self._warned_rep_addresses:
                warnings.warn(
                    f"Noncanonical REPNE {effects.kind.upper()} at {inst.address:#x}: "
                    "rolling back before the instruction", RuntimeWarning)
                self._warned_rep_addresses.add(inst.address)
            return

        # The loop spans both boundaries, and its implicit operands and flags
        # remain live between iterations even if dead after the original REP.
        live = self.reg_manager.live_registers(function, block, inst_idx) | \
            self.reg_manager.live_registers(function, block, inst_idx + 1)
        live.update(self.arch.abi.get_register(name)
                    for name in ("rax", "rcx", "rsi", "rdi", "rflags"))
        self.reg_manager.add_live_registers(function, block, inst_idx, live)
        patch = self.allocate_registers(function, block, inst_idx)(
            self._build_rep_patch(effects, inst, block, function=function))
        self.rewriting_ctx.replace_at(block, inst_offset, inst.size, Patch.from_function(patch))

    def _build_rep_patch(self, effects, inst, block, *, function=None):
        # Capture this per patch: rendering occurs after visiting other functions.
        propagate_tags = self.enable_dift and (function is None or not is_blacklisted_function(function))
        state = ScratchpadSlots.X64_REP_STATE
        label = f".L__transient_rep{SYMBOL_SUFFIX}"
        count = "ecx" if effects.address_size == 4 else "rcx"
        zero_jump = "jecxz" if effects.address_size == 4 else "jrcxz"
        comparison = effects.kind in {"cmps", "scas"}
        # Preserve effective size/segment attributes, not ignored prefixes.
        # Deleting F3 from e.g. 48 F3 A5 would activate the ignored REX.W and
        # incorrectly turn a dword transfer into a qword transfer.
        single = bytes(
            ([{"fs": 0x64, "gs": 0x65}[effects.source_segment]] if effects.source_segment else []) +
            ([0x67] if effects.address_size == 4 else []) +
            ([0x66] if effects.width == 2 else [0x48] if effects.width == 8 else []) +
            [inst.opcode[0]])
        repeat_equal = next(b for b in reversed(inst.bytes) if b in (0xf2, 0xf3)) == 0xf3
        policies = []
        if self.enable_mem_policy:
            for operand in inst.operands:
                if operand.type == CS_OP_MEM and operand.access & CS_AC_READ:
                    policies.append(self.mem_policy._build_patch(
                        inst, self.arch.mem_operand_to_str(block, inst, operand), effects.width,
                        conditional=None, mem_operand=operand,
                        queued_tag_operand=f"scratchpad+{state+56}",
                        label_key=f"rep_read_{len(policies)}"))

        tag_patch = None
        if propagate_tags or (comparison and self.enable_port_policy):
            tag_patch = self._build_rep_tags_patch(
                effects, extra_tag_operand=f"byte ptr scratchpad+{state+56}",
                report_comparison=comparison and self.enable_port_policy,
                propagate_tags=propagate_tags,
                partial_accumulator_tag_operand=f"byte ptr scratchpad+{state+64}")
        scratch_count = max(
            [1, 3 if self.insert_memlog and effects.kind in {"movs", "stos"} else 0,
             tag_patch.constraints.scratch_registers if tag_patch else 0] +
            [policy.constraints.scratch_registers for policy in policies])

        @self.arch.constraints(scratch_registers=scratch_count,
                               reads_registers={"rax", "rcx", "rsi", "rdi"})
        def patch(ctx):
            # Scratch registers are owned by the outer ABI wrapper for the
            # whole loop. Do not nest wrappers sharing the same spill slots.
            capture = self._build_rep_capture_patch(effects)(ctx)
            restore_flags = self._rep_flags_snippet(restore=True)
            asm = ""
            if self.enable_port_policy:
                tag = ctx.scratch_registers[0]
                index = self.arch.dift_register_id(self.arch.abi.get_register("rcx"))
                asm += self._rep_flags_snippet() + "cld\n"
                asm += f"""
                    movzx {tag:32}, byte ptr dift_reg_tags+{index}
                    test {tag:8l}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                    jz {label}_count_checked
                    {self.arch.report_gadget_snippet("KASPER_PORT", tag_reg=tag)}
                {label}_count_checked:
                """
                asm += restore_flags
            asm += f"""
                {zero_jump} {label}_empty
                jmp {label}_start
            {label}_empty:
                .byte {', '.join(hex(b) for b in inst.bytes)}
                jmp {label}_done
            {label}_start:
            """
            if propagate_tags and effects.kind == "lods" and effects.width < 4:
                tmp = ctx.scratch_registers[0]
                asm += f"mov {tmp:8l}, byte ptr dift_reg_tags\n"
                asm += f"mov byte ptr scratchpad+{state+64}, {tmp:8l}\n"
            asm += f"""
            {label}_loop:
                {capture}
            """
            # The application may have DF set, and both the C report wrappers
            # and the C rollback path require it clear. The budget check below
            # can jump straight to restore_checkpoint_ROB_LEN, which enters C
            # without clearing it, so clear DF first. capture has already saved
            # the real flags and restore_flags reinstates them before the string
            # opcode runs.
            asm += "cld\n"
            asm += self.arch.conditional_restore_point_patch(1)(ctx)
            asm += f"mov byte ptr scratchpad+{state+56}, 0\n"
            for policy in policies:
                asm += policy(replace(
                    ctx, scratch_registers=ctx.scratch_registers[:policy.constraints.scratch_registers]))
            if self.insert_memlog and effects.kind in {"movs", "stos"}:
                addr, history, data = ctx.scratch_registers[:3]
                bits = effects.address_size * 8
                asm += f"mov {addr:{bits}}, {'edi' if bits == 32 else 'rdi'}\n"
                asm += self.arch.memlog_snippet(addr, history, data, effects.width)

            asm += restore_flags
            asm += ".byte " + ", ".join(hex(b) for b in single) + "\n"
            asm += f"lea {count}, [{count}-1]\n"
            asm += self._rep_flags_snippet() + "cld\n"
            if tag_patch:
                asm += tag_patch(replace(
                    ctx, scratch_registers=ctx.scratch_registers[:tag_patch.constraints.scratch_registers]))
            asm += restore_flags
            if comparison:
                asm += f"{'jnz' if repeat_equal else 'jz'} {label}_done\n"
            asm += f"""
                {zero_jump} {label}_done
                jmp {label}_loop
            {label}_done:
                nop
            """
            return asm

        return patch
