import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from capstone_gt import CsInsn, CS_OP_MEM
from gtirb_live_register_analysis import LiveRegisterManager

from teapot.preprocess.create_guards import create_guards
from teapot.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from teapot.utils.misc import distinguish_edges
from teapot.config import SYMBOL_SUFFIX, SCRATCHPAD_SIZE, BLACKLIST_FUNCTION_NAMES


class TransientCoveragePass(VisitorPassMixin, RegInstAwarePassMixin):
    transient_section: gtirb.Section
    guard_section: gtirb.Section

    idx: int = 0

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder, guard_section: gtirb.Section):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.transient_section = transient_section
        self.guard_section = guard_section

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def end_module(self, module: gtirb.Module, functions):
        create_guards(self.guard_section, self.idx)

    def visit_function(self, function: Function):
        if function.get_name().replace(SYMBOL_SUFFIX, "") in BLACKLIST_FUNCTION_NAMES:
            return

        self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        self.rewriting_ctx.insert_at(block, 0, Patch.from_function(self.__build_coverage_patch(self.idx)))
        self.idx += 1

    def __build_coverage_patch(self, idx: int):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=1)
        def patch(ctx):
            r1, = ctx.scratch_registers
            return f"""
                mov {r1}, guard_list_top
                mov dword ptr [{r1}], {idx}
                lea {r1}, [{r1} + 4]
                mov guard_list_top, {r1}
            """

        return patch
