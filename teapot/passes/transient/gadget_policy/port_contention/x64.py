from typing import Optional

import gtirb
from capstone_gt import CS_AC_READ, CS_OP_MEM, CS_OP_REG
from gtirb_rewriting import InsertionContext, patch_constraints
from gtirb_rewriting.assembly import X86Syntax

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.tags import TAG_SECRET, TAG_SECRET_INDIRECT
from teapot.passes.transient.gadget_policy.port_contention.base import TransientPortContentionPolicyPassBase


class X64TransientPortContentionPolicyPass(TransientPortContentionPolicyPassBase):
    EXPECTED_ARCH = "x64"

    def predicate_instruction_index(self, instructions) -> Optional[int]:
        try:
            idx, _ = next(
                (idx, inst) for idx, inst in enumerate(reversed(instructions))
                if self.arch.instruction_writes_flags(inst))
            return len(instructions) - 1 - idx
        except StopIteration:
            return None

    def build_patch(self, block: gtirb.CodeBlock, inst, inst_offset: int):
        mem_read_operand_str = None
        regs_read = []

        for operand in inst.operands:
            if not operand.access & CS_AC_READ:
                continue

            if operand.type == CS_OP_MEM:
                mem_read_operand_str = self.arch.mem_operand_to_str(block, inst, operand)
            elif operand.type == CS_OP_REG:
                reg = self.arch.register_from_name(
                    self.reg_manager.abi, inst.reg_name(operand.reg))
                if reg is not None:
                    regs_read.append(reg)

        if not regs_read and mem_read_operand_str is None:
            return None

        segmented_operand = (
            mem_read_operand_str is not None
            and self.arch.mem_operand_segment(mem_read_operand_str) is not None)
        scratch_registers = 3 if segmented_operand else (2 if mem_read_operand_str else 1)

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            if segmented_operand:
                r1, r2, segment_reg = ctx.scratch_registers
            elif mem_read_operand_str:
                r1, r2 = ctx.scratch_registers
                segment_reg = None
            else:
                r1, = ctx.scratch_registers
                r2 = None
                segment_reg = None

            asm = self.arch.clear_register_snippet(r1)

            for reg in regs_read:
                asm += self.arch.dift_or_reg_tag_snippet(r1, None, reg)

            if mem_read_operand_str:
                asm += self.arch.effective_address_snippet(
                    r2, mem_read_operand_str, segment_reg)
                asm += self.arch.dift_shadow_addr_snippet(
                    r2, None, self.dift_layout.xor_mask)
                asm += f"or {r1:8l}, [{r2}]\n"

            asm += f"""
                test {r1:8l}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                jz .L__check_ok{SYMBOL_SUFFIX}
                {self.arch.report_gadget_snippet("KASPER_PORT", tag_reg=r1)}
            .L__check_ok{SYMBOL_SUFFIX}:
                nop
            """

            return asm

        return patch, set(regs_read)
