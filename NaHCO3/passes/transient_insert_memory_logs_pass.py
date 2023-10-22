import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints)
from gtirb_rewriting import InsertionContext
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from gtirb_live_register_analysis import LiveRegisterManager
from capstone_gt import CsInsn, CS_OP_MEM, CS_AC_WRITE
from typing import Iterable, List
import math
import functools

from typing import List, Set

from NaHCO3.passes.mixins import InstVisitorPassMixin


class TransientInsertMemoryLogsPass(InstVisitorPassMixin):
    reg_manager: LiveRegisterManager
    transient_section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder):
        super().__init__(reg_manager, decoder)
        self.transient_section = transient_section

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        super().begin_module(module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if len(inst.operands) > 0:
            if inst.operands[0].type == CS_OP_MEM and inst.operands[0].size > 8:
                # Workaround for capstone: capstone doesn't correctly identify accesses for
                # a lot of SSE/AVX instructions, so we conservatively identify all first
                # SSE/AVX memory operands as being written.
                mem_write_operand = inst.operands[0]
            else:
                mem_write_operand = next(iter(x for x in inst.operands if
                                              x.type == CS_OP_MEM and x.access & CS_AC_WRITE), None)

            if mem_write_operand is not None:
                try:
                    mem_operand_str = mem_access_to_str(inst, mem_write_operand.mem,
                                                        operand_symbolic_expression(block, inst, mem_write_operand))
                except NotImplementedError:
                    print(f"Warning: unsupported symexp at {inst}")
                    mem_operand_str = mem_access_to_str(inst, mem_write_operand.mem, None)

                self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
                    self.reg_manager.allocate_registers(function, block, inst_idx)(
                        self.__build_memory_log_patch(mem_operand_str, mem_write_operand.size))))
            elif inst.mnemonic == "push" or inst.mnemonic == "call":
                # Stack operations
                access_size = inst.operands[0].size
                self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
                    self.reg_manager.allocate_registers(function, block, inst_idx)(
                        self.__build_memory_log_patch(f"[rsp-{access_size}]", access_size))))

    def __build_memory_log_patch(self, mem_operand_str: str, access_size: int):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3)
        def patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers

            store_instructions = ""
            for i in range(0, access_size, 8):
                store_instructions += f"""
                mov {r3}, [{r1}]
                mov [{r2}], {r1}
                mov [{r2} + 8], {r3}
                lea {r2}, [{r2} + 16]
                lea {r1}, [{r1} + 8]
                """

            return f"""
                lea {r1}, {mem_operand_str}
                mov {r2}, [memory_history_top]
                {store_instructions}
                mov memory_history_top, {r2}
            """

        return patch

