import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from capstone_gt import CsInsn, CS_OP_MEM
from typing import List, Set
import itertools

from NaHCO3.config import ASAN_SHADOW_OFFSET
from NaHCO3.passes.mixins import InstVisitorPassMixin
from NaHCO3.utils.misc import distinguish_edges


class TransientAsanPass(InstVisitorPassMixin):
    transient_section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder):
        super().__init__(reg_manager, decoder)
        self.transient_section = transient_section

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)

        self.visit_functions(functions, self.transient_section)

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if inst.mnemonic == "lea" or inst.mnemonic == "nop" or inst.mnemonic == "call":
            return

        mem_operand = next(iter(x for x in inst.operands if x.type == CS_OP_MEM), None)
        if mem_operand is None:
            return

        # TODO: support > 8 bytes access
        # FIXME: capstone read/write info for SSE/AVX is incorrect

        try:
            mem_operand_str = mem_access_to_str(inst, mem_operand.mem,
                                                operand_symbolic_expression(block, inst, mem_operand))
        except NotImplementedError:
            print(f"Warning: unsupported symexp at {inst}")
            mem_operand_str = mem_access_to_str(inst, mem_operand.mem, None)

        self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
            self.reg_manager.allocate_registers(function, block, inst_idx)(
                self.__build_asan_check_patch(inst, mem_operand_str, mem_operand.size)
            )
        ))

    def __build_asan_check_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int):
        # FIXME: this actually clobbers flags!
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=2, clobbers_flags=False)
        def patch(ctx: InsertionContext):
            r1, r2 = ctx.scratch_registers

            detailed_check_snippet = f"""
                
            """ if access_size < 8 else ""

            return f"""
                lea {r1}, {mem_operand_str}
                mov {r2}, {r1}
                sub {r2}, 0x7fff8000
                shr {r2}, 44 # we want to compare it with 0xfff,ffff,ffff
                test {r2}, {r2} # if zero, the target address falls into asan shadow
                jz restore_checkpoint # maybe not directly restore? i don't know
                
                shr {r1}, 3
                mov {r1:8l}, [{r1}+{ASAN_SHADOW_OFFSET}]
                test {r1:8l}, {r1:8l}
                je .L__asan_check_ok
                {detailed_check_snippet}
                jmp restore_checkpoint
            .L__asan_check_ok:
            """

        return patch