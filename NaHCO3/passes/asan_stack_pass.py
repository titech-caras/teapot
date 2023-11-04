import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_capstone.instructions import GtirbInstructionDecoder
from typing import List, Set
import itertools

from NaHCO3.config import BLACKLIST_FUNCTION_NAMES, ASAN_SHADOW_OFFSET
from NaHCO3.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from NaHCO3.utils.misc import distinguish_edges
from NaHCO3.patch_helpers import memlog_snippet


class AsanStackPass(VisitorPassMixin, RegInstAwarePassMixin):
    section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager,
                 section: gtirb.Section, decoder: GtirbInstructionDecoder, insert_memlog: bool):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.section = section
        self.insert_memlog = insert_memlog

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)

        self.visit_functions(functions, self.section)

    def visit_function(self, function: Function):
        if function.get_name() in BLACKLIST_FUNCTION_NAMES + ["main"]:
            return

        self.reg_manager.analyze(function)
        # poison stack
        for block in function.get_entry_blocks():
            self.rewriting_ctx.insert_at(
                block, 0,Patch.from_function(
                    self.reg_manager.allocate_registers(function, block, 0)(
                        self.__build_asan_stack_patch(poison=True))))

        # unpoison stack
        for block in function.get_exit_blocks():
            non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                return

            if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return:
                instructions = list(self.decoder.get_instructions(block))
                self.rewriting_ctx.insert_at(
                    block, sum(inst.size for inst in instructions[:-1]), Patch.from_function(
                        self.reg_manager.allocate_registers(function, block, len(instructions) - 1)(
                            self.__build_asan_stack_patch(poison=False))))

        super().visit_function(function)

    def __build_asan_stack_patch(self, *, poison: bool):
        asan_val = "-1" if poison else "0"
        scratch_registers = 3 if self.insert_memlog else 1

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers)
        def patch(ctx: InsertionContext):
            if self.insert_memlog:
                # Poison the return address
                r1, r2, r3 = ctx.scratch_registers
                my_memlog_snippet = memlog_snippet(r2, 1, r1=r1, r2=r3, no_clobber_addr=True)
            else:
                r2, = ctx.scratch_registers
                my_memlog_snippet = ""

            return f"""
                mov {r2}, rsp
                shr {r2}, 3
                lea {r2}, [{r2}+{ASAN_SHADOW_OFFSET}]
                {my_memlog_snippet}
                mov byte ptr [{r2}], {asan_val}
            """

        return patch
