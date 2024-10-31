import random

import capstone_gt.x86
import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn, CS_OP_MEM, CS_AC_WRITE
from capstone_gt.x86 import X86OpMem, X86_REG_INVALID
from typing import List, Set, Optional
import itertools

from teapot.config import ASAN_SHADOW_OFFSET, SYMBOL_SUFFIX
from teapot.passes.mixins import InstVisitorPassMixin
from teapot.patch_helpers import asan_check_snippet, memlog_snippet, conditional_patch_wrapper
from teapot.utils.rewriting import (mem_access_to_symbolic_str, get_cmov_conditional,
                                    mem_operand_is_write_capstone_workaround)


class TransientMemlogPass(InstVisitorPassMixin):
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
        if inst.mnemonic in ("lea", "nop", "ret") or inst.mnemonic.startswith("j"):
            return

        mem_operand = next(iter(x for x in inst.operands if x.type == CS_OP_MEM), None)
        if inst.mnemonic == "push" or inst.mnemonic == "call":
            mem_operand_str = "[rsp-8]"
            access_size = 8
        elif mem_operand is not None and mem_operand_is_write_capstone_workaround(inst, mem_operand):
            mem_operand_str = mem_access_to_symbolic_str(block, inst, mem_operand)
            access_size = mem_operand.size
        else:
            return

        self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
            self.reg_manager.allocate_registers(function, block, inst_idx)(
                self.__build_memlog_patch(inst, mem_operand_str, access_size,
                                          conditional=get_cmov_conditional(inst)))))

    @staticmethod
    def __build_memlog_patch(inst: CsInsn, mem_operand_str: str, access_size: int, *,
                                  conditional: Optional[str] = None):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3)
        def patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers

            asm = f"""
                lea {r2}, {mem_operand_str}
                {memlog_snippet(r2, access_size, r1=r1, r2=r3)}
            """

            asm = conditional_patch_wrapper(asm, conditional, label_key="memlog")
            return asm

        return patch
