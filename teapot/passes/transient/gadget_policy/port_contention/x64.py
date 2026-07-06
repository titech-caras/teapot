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
                regs_read.append(self.reg_manager.abi.get_register(inst.reg_name(operand.reg)))

        scratch_registers = 2 if mem_read_operand_str else 1

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            if mem_read_operand_str:
                r1, r2 = ctx.scratch_registers
            else:
                r1, = ctx.scratch_registers
                r2 = None

            asm = self.arch.clear_register_snippet(r1)

            for reg in regs_read:
                asm += self.arch.dift_or_reg_tag_snippet(r1, None, reg)

            if mem_read_operand_str:
                asm += f"""
                    lea {r2}, {mem_read_operand_str}
                    {self.arch.dift_shadow_addr_snippet(r2, None, self.dift_layout.xor_mask)}
                    or {r1:8l}, [{r2}]
                """

            asm += f"""
                test {r1:8l}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                jz .L__check_ok{SYMBOL_SUFFIX}
                {self.arch.report_gadget_snippet("KASPER_PORT", tag_reg=r1)}
            .L__check_ok{SYMBOL_SUFFIX}:
                nop
            """

            return asm

        return patch, set(regs_read)
