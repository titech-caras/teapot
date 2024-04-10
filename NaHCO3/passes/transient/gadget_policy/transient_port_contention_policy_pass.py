import capstone_gt.x86
import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn, CS_OP_MEM, CS_AC_WRITE, CS_OP_REG, CS_AC_READ
from capstone_gt.x86 import X86_REG_EFLAGS
from typing import List, Set, Optional
import itertools

from NaHCO3.config import SYMBOL_SUFFIX, TAG_ATTACKER, TAG_SECRET, TAG_SECRET_INDIRECT
from NaHCO3.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from NaHCO3.patch_helpers import (asan_check_snippet, dift_add_reg_tag_snippet, conditional_patch_wrapper,
                                  report_gadget_snippet)
from NaHCO3.utils.misc import distinguish_edges
from NaHCO3.utils.rewriting import mem_access_to_symbolic_str, get_cmov_conditional
from NaHCO3.utils.dift import reg_to_dift_reg_id


class TransientPortContentionPolicyPass(VisitorPassMixin, RegInstAwarePassMixin):
    reg_manager: LiveRegisterManager
    transient_section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.transient_section = transient_section

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_function(self, function: Function):
        self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        if (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                non_fallthrough_edges[0].label.conditional):
            instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
            try:
                idx, inst = next((idx, inst) for idx, inst in enumerate(reversed(instructions))
                                 if X86_REG_EFLAGS in inst.regs_access()[1])
                idx = len(instructions) - 1 - idx
            except StopIteration:
                return

            mem_read_operand_str = None
            regs_read = []

            for operand in inst.operands:
                if not operand.access & CS_AC_READ:
                    continue

                if operand.type == CS_OP_MEM:
                    mem_read_operand_str = mem_access_to_symbolic_str(block, inst, operand)
                elif operand.type == CS_OP_REG:
                    regs_read.append(self.reg_manager.abi.get_register(inst.reg_name(operand.reg)))

            self.rewriting_ctx.insert_at(block, sum(i.size for i in instructions[:idx]), Patch.from_function(
                self.reg_manager.allocate_registers(function, block, idx)(
                    self.__build_patch(mem_read_operand_str, regs_read)
                )
            ))

    def __build_patch(self, mem_read_operand_str: Optional[str], regs_read: List[Register]):
        scratch_registers = 2 if mem_read_operand_str else 1

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            if mem_read_operand_str:
                r1, r2 = ctx.scratch_registers
            else:
                r1, = ctx.scratch_registers
                r2 = None

            asm = f"""
                xor {r1:32}, {r1:32}
            """

            for reg in regs_read:
                asm += dift_add_reg_tag_snippet(r1, reg_add=reg)

            if mem_read_operand_str:
                asm += f"""
                    lea {r2}, {mem_read_operand_str}
                    btc {r2}, 45
                    or {r1:8l}, [{r2}]
                """

            asm += f"""
                test {r1:8l}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                jz .L__check_ok{SYMBOL_SUFFIX} 
                {report_gadget_snippet("KASPER_PORT", tag_reg=r1)}
            .L__check_ok{SYMBOL_SUFFIX}:
                nop
            """

            return asm

        return patch

