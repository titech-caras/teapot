import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.manager import NotEnoughFreeRegistersException
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from typing import List
from uuid import UUID
import functools

from teapot.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from teapot.utils.misc import distinguish_edges, generate_distinct_label_name
from teapot.config import SYMBOL_SUFFIX, BLACKLIST_FUNCTION_NAMES


class TextInitializeLibraryPass(VisitorPassMixin):
    reg_manager: LiveRegisterManager
    text_section: gtirb.Section

    def __init__(self, text_section: gtirb.Section):
        self.text_section = text_section

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        rewriting_ctx.register_insert(AllFunctionsScope(FunctionPosition.ENTRY, BlockPosition.ENTRY, {"main"}),
                                      Patch.from_function(patch_constraints(x86_syntax=X86Syntax.INTEL)(
                                          lambda ctx: """
                                          sub rsp, 8
                                          call libcheckpoint_enable
                                          add rsp, 8
                                          """
                                      )))

        self.visit_functions(functions, self.text_section)

    def visit_function(self, function: Function):
        if function.get_name() == "main":
            for block in function.get_exit_blocks():
                non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
                if len(non_fallthrough_edges) == 0:
                    continue

                if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return:
                    self.rewriting_ctx.insert_at(
                        block, block.size - 1, Patch.from_function(patch_constraints(x86_syntax=X86Syntax.INTEL)(
                            lambda ctx: """
                            sub rsp, 8
                            call libcheckpoint_disable
                            add rsp, 8
                            """)))
