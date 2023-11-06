import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from capstone_gt import CsInsn, CS_OP_MEM
from gtirb_live_register_analysis import LiveRegisterManager

from NaHCO3.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from NaHCO3.utils.misc import distinguish_edges
from NaHCO3.config import SYMBOL_SUFFIX, SCRATCHPAD_SIZE


class TransientCoveragePass(VisitorPassMixin, RegInstAwarePassMixin):
    transient_section: gtirb.Section
    guard_start_symbol: gtirb.Symbol
    guard_end_symbol: gtirb.Symbol

    idx: int = 0

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder,
                 guard_start_symbol: gtirb.Symbol, guard_end_symbol: gtirb.Symbol):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.transient_section = transient_section
        self.guard_start_symbol = guard_start_symbol
        self.guard_end_symbol = guard_end_symbol

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_function(self, function: Function):
        self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        self.rewriting_ctx.insert_at(block, 0, Patch.from_function(self.__build_coverage_patch(self.idx)))
        self.idx += 1

    def __build_coverage_patch(self, idx: int):
        @patch_constraints(x86_syntax=X86Syntax.INTEL)
        def patch(ctx):
            return f"""
                mov old_rsp, rsp
                lea rsp, scratchpad+{SCRATCHPAD_SIZE - 16}
                mov scratchpad, rdi
                lea rdi, {self.guard_start_symbol.name}
                add rdi, {idx * 4}
                call __sanitizer_cov_trace_pc_guard
                mov rdi, scratchpad
                mov rsp, old_rsp
            """

        return patch
