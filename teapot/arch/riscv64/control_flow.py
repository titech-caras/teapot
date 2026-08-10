import re
from typing import Optional
from uuid import UUID

import gtirb

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.utils.misc import generate_distinct_label_name


class RISCV64ControlFlowPatchesMixin:
    def adjust_insertion_offset(self, block: gtirb.CodeBlock, offset: int, instructions) -> int:
        if offset != 0 or block.byte_interval is None:
            return offset

        if not instructions or instructions[0].mnemonic != "auipc":
            return offset

        symbolic = block.byte_interval.symbolic_expressions.get(block.offset)
        if not isinstance(symbolic, gtirb.SymAddrConst):
            return offset

        attrs = symbolic.attributes
        if (
            gtirb.SymbolicExpression.Attribute.PCREL in attrs and
            gtirb.SymbolicExpression.Attribute.HI in attrs
        ):
            return instructions[0].size
        return offset

    @staticmethod
    def retarget_last_operand(mnemonic: str, op_str: str, target_symbol_name: str) -> str:
        if mnemonic.startswith("c."):
            mnemonic = mnemonic[2:]

        operands = [operand.strip() for operand in op_str.split(",") if operand.strip()]
        if not operands:
            return f"{mnemonic} {target_symbol_name}"

        operands[-1] = target_symbol_name
        return f"{mnemonic} {', '.join(operands)}"

    @classmethod
    def materialize_target(cls, target_reg: str, operand_str: str) -> str:
        operand = operand_str.strip()
        mem = re.match(r"^(-?(?:0x[0-9a-fA-F]+|\d+))\(([^()]+)\)$", operand)
        if mem:
            offset = int(mem.group(1), 0)
            base = mem.group(2).strip()
            return cls.add_constant_from_base(target_reg, base, target_reg, offset)

        return f"mv {target_reg}, {operand}"

    def trampoline_patch(self, block_uuid: UUID, transient_block_uuid: UUID, mnemonic: str, op_str: str,
                         conditional_target_symbol_name: str, non_conditional_target_symbol_name: str,
                         use_long_jumps: bool = False, jump_register: str = None,
                         conditional_jump_register: str = None, non_conditional_jump_register: str = None,
                         conditional_use_long_jump: bool = None, non_conditional_use_long_jump: bool = None,
                         preserve_jump_registers_with_landing: bool = False,
                         checkpoint_spare_registers=()):
        conditional_taken = generate_distinct_label_name(".__trampoline_taken_", block_uuid)
        conditional_branch = self.retarget_last_operand(mnemonic, op_str, conditional_taken)
        conditional_use_long_jump = use_long_jumps if conditional_use_long_jump is None else conditional_use_long_jump
        non_conditional_use_long_jump = (
            use_long_jumps if non_conditional_use_long_jump is None else non_conditional_use_long_jump)
        conditional_needs_allocated_register = conditional_use_long_jump and conditional_jump_register is None
        non_conditional_needs_allocated_register = (
            non_conditional_use_long_jump and non_conditional_jump_register is None)
        needs_allocated_jump_register = (
            jump_register is None and
            (conditional_needs_allocated_register or non_conditional_needs_allocated_register)
        )
        checkpoint_restore = "\n".join(
            f"mv {fixed}, {spare}"
            for fixed, spare in zip(self.CHECKPOINT_FIXED_REGISTERS, checkpoint_spare_registers)
        )

        @self.constraints(scratch_registers=1 if needs_allocated_jump_register else 0)
        def patch(ctx):
            allocated_jump_reg = jump_register
            if needs_allocated_jump_register:
                allocated_jump_reg = ctx.scratch_registers[0]
            conditional_reg = conditional_jump_register or allocated_jump_reg
            non_conditional_reg = non_conditional_jump_register or allocated_jump_reg
            non_conditional_jump = (
                self.jump_symbol_with_first_spill_restore(non_conditional_target_symbol_name, non_conditional_reg)
                if non_conditional_use_long_jump and preserve_jump_registers_with_landing else
                self.jump_symbol(non_conditional_target_symbol_name, non_conditional_reg)
                if non_conditional_use_long_jump else f"j {non_conditional_target_symbol_name}"
            )
            conditional_jump = (
                self.jump_symbol_with_first_spill_restore(conditional_target_symbol_name, conditional_reg)
                if conditional_use_long_jump and preserve_jump_registers_with_landing else
                self.jump_symbol(conditional_target_symbol_name, conditional_reg)
                if conditional_use_long_jump else f"j {conditional_target_symbol_name}"
            )
            return f"""
        {generate_distinct_label_name(".__trampoline_landing_", block_uuid)}:
            {self.load_address("t0", "checkpoint_target_metadata")}
            ld t0, {self.CHECKPOINT_TARGET_SCRATCH_REG_ADDR}(t0)
            {checkpoint_restore}
        {generate_distinct_label_name(".__trampoline_", block_uuid)}:
        {generate_distinct_label_name(".__trampoline_", transient_block_uuid)}:
            {conditional_branch}
            {non_conditional_jump}
        {conditional_taken}:
            {conditional_jump}
        """

        return patch

    def indirect_branch_target_patch(self, target_symbol: gtirb.Symbol, *, use_scratch_registers: bool = False,
                                     use_long_jump: bool = True, jump_register: str = None,
                                     restore_before_jump: bool = True):
        scratch_count = 0
        if use_scratch_registers:
            scratch_count = 1 + (1 if use_long_jump and jump_register is None else 0)

        @self.constraints(scratch_registers=scratch_count)
        def patch(ctx):
            counter_reg = "t0"
            jump_reg = jump_register
            prologue = self.save_regs_to_first_spill(self.FIRST_SPILL_T0_T1)
            done_epilogue = self.restore_regs_from_first_spill(self.FIRST_SPILL_T0_T1)
            checkpoint_epilogue = self.restore_regs_from_first_spill(self.FIRST_SPILL_T0_T1) \
                if restore_before_jump else ""

            if use_scratch_registers:
                counter_reg = ctx.scratch_registers[0]
                if use_long_jump and jump_reg is None:
                    jump_reg = ctx.scratch_registers[1]
                prologue = ""
                done_epilogue = ""
                checkpoint_epilogue = ""

            if use_long_jump and jump_reg is None:
                jump_reg = "t0"

            target_name = target_symbol.name if hasattr(target_symbol, "name") else str(target_symbol)
            target_jump = self.jump_symbol(target_name, jump_reg) if use_long_jump else f"j {target_name}"
            if not use_scratch_registers and not restore_before_jump:
                checkpoint_taken = self.jump_symbol_with_first_spill_restore(
                    target_name, jump_reg, already_saved=True)
            else:
                checkpoint_taken = f"""
                    {checkpoint_epilogue}
                    {target_jump}
                """
            return f"""
                .word 0x{self.MAGIC_WORDS[0]:08x}
                .word 0x{self.MAGIC_WORDS[1]:08x}
                {prologue}
                {self.load_address(counter_reg, "checkpoint_cnt")}
                ld {counter_reg}, 0({counter_reg})
                beqz {counter_reg}, .L__indbr_transform_done{SYMBOL_SUFFIX}
                {checkpoint_taken}
            .L__indbr_transform_done{SYMBOL_SUFFIX}:
                {done_epilogue}
            """

        return patch

    def indirect_transform_uses_live_registers(self) -> bool:
        return True

    def indirect_transform_landing_pad_label(self, block_uuid: UUID):
        return self.landing_pad_entry_label(block_uuid)

    def indirect_transform_fallback_patch(self, target_symbol: gtirb.Symbol, *, landing_target_uuid=None):
        target_symbol_name = self.landing_pad_entry_label(landing_target_uuid)
        return self.indirect_branch_target_patch(
            target_symbol_name, use_long_jump=True, jump_register="t0", restore_before_jump=False)

    def trampoline_target_names(self, fallthrough_target_symbol_name: str, branch_target_symbol_name: str, *,
                                fallthrough_target_uuid: UUID, branch_target_uuid: UUID,
                                landing_pad_targets=None):
        if landing_pad_targets is not None:
            landing_pad_targets.add(fallthrough_target_uuid)
            landing_pad_targets.add(branch_target_uuid)
        return (
            self.landing_pad_entry_label(fallthrough_target_uuid),
            self.landing_pad_entry_label(branch_target_uuid),
            {
                "use_long_jumps": True,
                "jump_register": "t0",
                "preserve_jump_registers_with_landing": True,
            },
        )

    def indirect_branch_operand(self, edge_type, last_inst, block: gtirb.CodeBlock = None) -> Optional[str]:
        if edge_type == gtirb.cfg.Edge.Type.Return or last_inst.mnemonic == "ret":
            return "ra"

        operands = [operand.strip() for operand in last_inst.op_str.split(",") if operand.strip()]
        if last_inst.mnemonic in ("jr", "jalr"):
            if len(operands) == 1:
                return operands[0]
            if len(operands) == 2:
                return operands[1]
            if len(operands) >= 3:
                base, offset = operands[1], operands[2]
                if offset in ("0", "0x0"):
                    return base
                return f"{offset}({base})"

        if operands:
            return operands[-1]
        return None

    def instruction_must_rollback(self, instruction) -> bool:
        return instruction.mnemonic in {
            "ecall", "ebreak", "fence", "fence.i", "sfence.vma",
            "wfi", "sret", "mret", "uret",
        }

    def is_control_transfer_instruction(self, instruction) -> bool:
        mnemonic = instruction.mnemonic
        return (
            mnemonic in {"call", "j", "jal", "jalr", "jr", "ret", "tail"} or
            mnemonic.startswith("b") or
            mnemonic in {"c.j", "c.jal", "c.jalr", "c.jr"} or
            mnemonic.startswith("c.b")
        )

    def indirect_branch_check_patch(self, operand_str: str, transient_start_symbol: gtirb.Symbol,
                                    transient_end_symbol: gtirb.Symbol, text_start_symbol: gtirb.Symbol,
                                    text_end_symbol: gtirb.Symbol, reads_registers=None):
        @self.constraints(scratch_registers=3,
                          reads_registers=reads_registers or set())
        def patch(ctx):
            target_reg, temp_reg, magic_reg = ctx.scratch_registers[:3]
            return f"""
                {self.materialize_target(target_reg, operand_str)}
                {self.load_address(temp_reg, transient_start_symbol.name)}
                bltu {target_reg}, {temp_reg}, 4f
                {self.load_address(temp_reg, transient_end_symbol.name)}
                bltu {target_reg}, {temp_reg}, 1f
            4:
                {self.load_address(temp_reg, text_start_symbol.name)}
                bltu {target_reg}, {temp_reg}, 2f
                {self.load_address(temp_reg, text_end_symbol.name)}
                bgeu {target_reg}, {temp_reg}, 2f
                lw {temp_reg}, 0({target_reg})
                li {magic_reg}, 0x{self.MAGIC_WORDS[0]:08x}
                bne {temp_reg}, {magic_reg}, 2f
                lw {temp_reg}, 4({target_reg})
                li {magic_reg}, 0x{self.MAGIC_WORDS[1]:08x}
                bne {temp_reg}, {magic_reg}, 2f
            1:
                j 3f
            2:
                {self.jump_symbol("restore_checkpoint_MALFORMED_INDIRECT_BR", target_reg)}
            3:
                nop
            """

        return patch
