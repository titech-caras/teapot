import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax, Register
from typing import List, Set
import itertools

from NaHCO3.config import BLACKLIST_FUNCTION_NAMES, ASAN_SHADOW_OFFSET
from NaHCO3.passes.mixins import VisitorPassMixin
from NaHCO3.utils.misc import distinguish_edges


class AsanStackPass(VisitorPassMixin):
    text_section: gtirb.Section
    transient_section: gtirb.Section

    def __init__(self, text_section: gtirb.Section, transient_section: gtirb.Section):
        super().__init__()
        self.text_section = text_section
        self.transient_section = transient_section

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)

        rewriting_ctx.register_insert(AllFunctionsScope(FunctionPosition.ENTRY, BlockPosition.ENTRY, {"main"}), CallPatch(
            rewriting_ctx.get_or_insert_extern_symbol("__asan_init", '')
        ))
        rewriting_ctx.register_insert(AllFunctionsScope(FunctionPosition.ENTRY, BlockPosition.ENTRY, {"main"}),
                                      Patch.from_function(self.__asan_trigger_on_null_patch))

        self.visit_functions(functions)

    def visit_function(self, function: Function):
        section_name = next(iter(function.get_entry_blocks())).section.name
        if section_name != self.text_section.name and section_name != self.transient_section.name:
            return

        if function.get_name() in BLACKLIST_FUNCTION_NAMES:
            return

        # poison stack
        for block in function.get_entry_blocks():
            self.rewriting_ctx.insert_at(block, 0, Patch.from_function(self.__poison_stack_patch))

        # unpoison stack
        for block in function.get_exit_blocks():
            non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                return

            if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return:
                self.rewriting_ctx.insert_at(block, block.size - 1, Patch.from_function(self.__unpoison_stack_patch))

        super().visit_function(function)

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def __poison_stack_patch(self, ctx: InsertionContext):
        #r, = ctx.scratch_registers
        r = "r11"
        return f"""
            mov {r}, rsp
            shr {r}, 3
            mov word ptr [{r}+{ASAN_SHADOW_OFFSET}], 0xffff
            sub rsp, 16
        """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def __unpoison_stack_patch(self, ctx: InsertionContext):
        #r, = ctx.scratch_registers
        r = "r11"
        return f"""
            add rsp, 16
            mov {r}, rsp
            shr {r}, 3
            mov word ptr [{r}+{ASAN_SHADOW_OFFSET}], 0x0000
        """

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def __asan_trigger_on_null_patch(self, ctx: InsertionContext):
        return f"mov byte ptr ds:{ASAN_SHADOW_OFFSET}, -1"
