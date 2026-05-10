from typing import Optional
from uuid import UUID

import gtirb

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import (
    AARCH64_SHADOW_STACK_CONTROL_OFFSET,
    AARCH64_SHADOW_STACK_INDIRECT_CHECK_OFFSET,
    AARCH64_SHADOW_STACK_INDIRECT_TARGET_OFFSET,
)
from teapot.utils.misc import generate_distinct_label_name


class AArch64ControlFlowPatchesMixin:
    @staticmethod
    def retarget_last_operand(mnemonic: str, op_str: str, target_symbol_name: str) -> str:
        operands = [operand.strip() for operand in op_str.split(",") if operand.strip()]
        if not operands:
            return f"{mnemonic} {target_symbol_name}"

        operands[-1] = target_symbol_name
        return f"{mnemonic} {', '.join(operands)}"

    @classmethod
    def invert_conditional_branch(cls, mnemonic: str, op_str: str, target_symbol_name: str) -> Optional[str]:
        mnemonic = mnemonic.lower()
        if mnemonic == "cbz":
            return cls.retarget_last_operand("cbnz", op_str, target_symbol_name)
        if mnemonic == "cbnz":
            return cls.retarget_last_operand("cbz", op_str, target_symbol_name)
        if mnemonic == "tbz":
            return cls.retarget_last_operand("tbnz", op_str, target_symbol_name)
        if mnemonic == "tbnz":
            return cls.retarget_last_operand("tbz", op_str, target_symbol_name)
        if mnemonic.startswith("b."):
            inverse = cls.INVERSE_CONDITIONS.get(mnemonic[2:])
            if inverse is not None:
                return cls.retarget_last_operand(f"b.{inverse}", op_str, target_symbol_name)
        return None

    @classmethod
    def _long_jump(cls, target_symbol_name: str, jump_register: str) -> str:
        return f"""
            {cls.load_address(jump_register, target_symbol_name)}
            br {jump_register}
        """

    @classmethod
    def _materialize_saved_indirect_target(cls, target_reg: str, operand_str: str, *,
                                           preserve_sp: bool = False,
                                           frame_offset: int = AARCH64_SHADOW_STACK_CONTROL_OFFSET) -> str:
        operand = operand_str.strip().lower()
        saved_offsets = {
            "x15": frame_offset,
            "w15": frame_offset,
            "x16": frame_offset + 8,
            "w16": frame_offset + 8,
            "x17": frame_offset + 16,
            "w17": frame_offset + 16,
        }
        if operand in saved_offsets:
            offset = saved_offsets[operand]
            suffix = "" if offset == 0 else f", #{offset}"
            if preserve_sp:
                return f"""
                    mov {target_reg}, sp
                    {cls.shadow_stack_adjust_reg("sub", target_reg)}
                    ldr {target_reg}, [{target_reg}{suffix}]
                """
            return f"ldr {target_reg}, [sp{suffix}]"
        return f"mov {target_reg}, {operand_str}"

    def trampoline_patch(self, block_uuid: UUID, transient_block_uuid: UUID, mnemonic: str, op_str: str,
                         conditional_target_symbol_name: str, non_conditional_target_symbol_name: str,
                         use_long_jumps: bool = False, jump_register: str = None,
                         conditional_jump_register: str = None, non_conditional_jump_register: str = None,
                         conditional_use_long_jump: bool = None, non_conditional_use_long_jump: bool = None):
        fallthrough_label = generate_distinct_label_name(".__trampoline_fallthrough_", block_uuid)
        inverse_branch = self.invert_conditional_branch(mnemonic, op_str, fallthrough_label)
        conditional_use_long_jump = use_long_jumps if conditional_use_long_jump is None else conditional_use_long_jump
        non_conditional_use_long_jump = (
            use_long_jumps if non_conditional_use_long_jump is None else non_conditional_use_long_jump)
        conditional_reg = conditional_jump_register or jump_register or "x16"
        non_conditional_reg = non_conditional_jump_register or jump_register or conditional_reg
        conditional_jump = self._long_jump(conditional_target_symbol_name, conditional_reg) \
            if conditional_use_long_jump else f"b {conditional_target_symbol_name}"
        non_conditional_jump = self._long_jump(non_conditional_target_symbol_name, non_conditional_reg) \
            if non_conditional_use_long_jump else f"b {non_conditional_target_symbol_name}"
        if inverse_branch is None:
            trampoline_body = f"""
                {self.retarget_last_operand(mnemonic, op_str, conditional_target_symbol_name)}
                {non_conditional_jump}
            """
        else:
            trampoline_body = f"""
                {inverse_branch}
                {conditional_jump}
            {fallthrough_label}:
                {non_conditional_jump}
            """
        return self.constraints()(lambda ctx: f"""
        {generate_distinct_label_name(".__trampoline_landing_", block_uuid)}:
            {self.load_address("x16", "checkpoint_target_metadata")}
            ldr x16, [x16, #{self.CHECKPOINT_TARGET_SCRATCH_REG_ADDR}]
        {generate_distinct_label_name(".__trampoline_", block_uuid)}:
        {generate_distinct_label_name(".__trampoline_", transient_block_uuid)}:
            {trampoline_body}
        """)

    def indirect_branch_target_patch(self, target_symbol: gtirb.Symbol):
        @self.constraints()
        def patch(ctx):
            return f"""
                .word 0x{self.MAGIC_WORDS[0]:08x}
                .word 0x{self.MAGIC_WORDS[1]:08x}
                {self.save_regs_to_shadow_stack(
                    ("x16", "x17"), save_flags=True,
                    frame_offset=AARCH64_SHADOW_STACK_INDIRECT_TARGET_OFFSET, preserve_sp=True)}
                {self.load_address("x16", "checkpoint_cnt")}
                ldr x16, [x16]
                cbz x16, .L__indbr_transform_done{SYMBOL_SUFFIX}
                {self.restore_regs_from_shadow_stack(
                    ("x16", "x17"), save_flags=True,
                    frame_offset=AARCH64_SHADOW_STACK_INDIRECT_TARGET_OFFSET, preserve_sp=True)}
                b {target_symbol.name}
            .L__indbr_transform_done{SYMBOL_SUFFIX}:
                {self.restore_regs_from_shadow_stack(
                    ("x16", "x17"), save_flags=True,
                    frame_offset=AARCH64_SHADOW_STACK_INDIRECT_TARGET_OFFSET, preserve_sp=True)}
            """

        return patch

    def indirect_branch_operand(self, edge_type, last_inst, block: gtirb.CodeBlock = None) -> Optional[str]:
        if edge_type == gtirb.cfg.Edge.Type.Return:
            return last_inst.op_str.strip() or "x30"
        return last_inst.op_str.strip() or None

    def instruction_must_rollback(self, instruction) -> bool:
        return instruction.mnemonic in {"dmb", "dsb", "isb", "svc", "hvc", "smc"}

    def is_control_transfer_instruction(self, instruction) -> bool:
        return instruction.mnemonic in {"b", "bl", "blr", "br", "ret"}

    def indirect_branch_check_patch(self, operand_str: str, transient_start_symbol: gtirb.Symbol,
                                    transient_end_symbol: gtirb.Symbol, text_start_symbol: gtirb.Symbol,
                                    text_end_symbol: gtirb.Symbol, use_scratch_registers: bool = True,
                                    reads_registers=None):
        @self.constraints(scratch_registers=3 if use_scratch_registers else 0,
                          reads_registers=reads_registers or set())
        def patch(ctx):
            if not use_scratch_registers:
                return f"""
                    {self.save_regs_to_shadow_stack(
                        ("x15", "x16", "x17"), save_flags=True,
                        frame_offset=AARCH64_SHADOW_STACK_INDIRECT_CHECK_OFFSET, preserve_sp=True)}
                    {self._materialize_saved_indirect_target(
                        "x15", operand_str, preserve_sp=True,
                        frame_offset=AARCH64_SHADOW_STACK_INDIRECT_CHECK_OFFSET)}
                    {self.load_address("x16", transient_start_symbol.name)}
                    cmp x15, x16
                    b.lo 4f
                    {self.load_address("x16", transient_end_symbol.name)}
                    cmp x15, x16
                    b.lo 1f
                4:
                    {self.load_address("x16", text_start_symbol.name)}
                    cmp x15, x16
                    b.lo 2f
                    {self.load_address("x16", text_end_symbol.name)}
                    cmp x15, x16
                    b.hs 2f
                    ldr w16, [x15]
                    {self.mov_w_imm32("w17", self.MAGIC_WORDS[0])}
                    cmp w16, w17
                    b.ne 2f
                    ldr w16, [x15, #4]
                    {self.mov_w_imm32("w17", self.MAGIC_WORDS[1])}
                    cmp w16, w17
                    b.ne 2f
                1:
                    {self.restore_regs_from_shadow_stack(
                        ("x15", "x16", "x17"), save_flags=True,
                        frame_offset=AARCH64_SHADOW_STACK_INDIRECT_CHECK_OFFSET, preserve_sp=True)}
                    b 3f
                2:
                    {self.restore_regs_from_shadow_stack(
                        ("x15", "x16", "x17"), save_flags=True,
                        frame_offset=AARCH64_SHADOW_STACK_INDIRECT_CHECK_OFFSET, preserve_sp=True)}
                    b restore_checkpoint_MALFORMED_INDIRECT_BR
                3:
                    nop
                """

            target_reg, temp_reg, saved_nzcv_reg = ctx.scratch_registers[:3]
            return f"""
                mrs {saved_nzcv_reg}, nzcv
                mov {target_reg}, {operand_str}
                {self.load_address(temp_reg, transient_start_symbol.name)}
                cmp {target_reg}, {temp_reg}
                b.lo 4f
                {self.load_address(temp_reg, transient_end_symbol.name)}
                cmp {target_reg}, {temp_reg}
                b.lo 1f
            4:
                {self.load_address(temp_reg, text_start_symbol.name)}
                cmp {target_reg}, {temp_reg}
                b.lo 2f
                {self.load_address(temp_reg, text_end_symbol.name)}
                cmp {target_reg}, {temp_reg}
                b.hs 2f
                ldr {self.w_reg(temp_reg)}, [{target_reg}]
                {self.mov_w_imm32(self.w_reg(target_reg), self.MAGIC_WORDS[0])}
                cmp {self.w_reg(temp_reg)}, {self.w_reg(target_reg)}
                b.ne 2f
                ldr {self.w_reg(temp_reg)}, [{target_reg}, #4]
                {self.mov_w_imm32(self.w_reg(target_reg), self.MAGIC_WORDS[1])}
                cmp {self.w_reg(temp_reg)}, {self.w_reg(target_reg)}
                b.ne 2f
            1:
                msr nzcv, {saved_nzcv_reg}
                b 3f
            2:
                b restore_checkpoint_MALFORMED_INDIRECT_BR
            3:
                nop
            """

        return patch
