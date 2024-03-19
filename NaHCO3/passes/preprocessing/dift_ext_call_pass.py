import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from gtirb_live_register_analysis import LiveRegisterManager
from capstone_gt import CsInsn, CS_OP_MEM, CS_AC_READ, CS_AC_WRITE
from capstone_gt.x86 import X86_REG_EFLAGS
from typing import List, Set, Optional
from dataclasses import dataclass

from NaHCO3.config import BLACKLIST_FUNCTION_NAMES, DIFT_IGNORE_LIST
from NaHCO3.passes.mixins import VisitorPassMixin
from NaHCO3.utils.misc import distinguish_edges


class DiftExtCallPass(VisitorPassMixin):
    section: gtirb.Section
    symbols_to_rename: Set[gtirb.Symbol]

    def __init__(self, section: gtirb.Section):
        self.section = section
        self.symbols_to_rename = set()

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)

        self.visit_functions(functions, self.section)

    def end_module(self, module: gtirb.Module, functions) -> None:
        for sym in self.symbols_to_rename:
            forwarded_sym: gtirb.Symbol = module.aux_data['symbolForwarding'].data[sym]
            if forwarded_sym.name not in DIFT_IGNORE_LIST:
                forwarded_sym.name += "__dift_wrapper__"

    def visit_function(self, function: Function):
        if function.get_name() in BLACKLIST_FUNCTION_NAMES:
            return

        super().visit_function(function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        if (non_fallthrough_edges[0].label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Branch) and
                (isinstance(non_fallthrough_edges[0].target, gtirb.ProxyBlock) or
                 non_fallthrough_edges[0].target.section.name != self.section.name)):
            target_refs = list(non_fallthrough_edges[0].target.references)
            if len(target_refs) > 0:
                # is an external function call
                self.symbols_to_rename.add(target_refs[0])
