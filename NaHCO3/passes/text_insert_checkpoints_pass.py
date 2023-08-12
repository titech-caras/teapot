import gtirb
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from typing import List
from uuid import UUID
import functools

from NaHCO3.utils.misc import distinguish_edges, generate_distinct_label_name
from NaHCO3.config import CHECKPOINT_LIB_NAME


class TextInsertCheckpointsPass(Pass):
    text_section: gtirb.Section

    def __init__(self, text_section: gtirb.Section):
        self.text_section = text_section
        self.decoder = GtirbInstructionDecoder(text_section.module.isa)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        rewriting_ctx.register_insert(AllFunctionsScope(FunctionPosition.ENTRY, BlockPosition.ENTRY, {"main"}), CallPatch(
            rewriting_ctx.get_or_insert_extern_symbol("libcheckpoint_enable", CHECKPOINT_LIB_NAME)
        ))
        rewriting_ctx.register_insert(AllFunctionsScope(FunctionPosition.EXIT, BlockPosition.EXIT, {"main"}), CallPatch(
            rewriting_ctx.get_or_insert_extern_symbol("libcheckpoint_disable", CHECKPOINT_LIB_NAME)
        ))

        make_checkpoint_symbol = rewriting_ctx.get_or_insert_extern_symbol(
            "make_checkpoint", CHECKPOINT_LIB_NAME)
        for block in self.text_section.code_blocks:
            non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                continue

            if (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                    non_fallthrough_edges[0].label.conditional):
                instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
                conditional_jump_offset = functools.reduce(lambda x, i: x + i.size, instructions[:-1], 0)

                rewriting_ctx.insert_at(block, conditional_jump_offset, Patch.from_function(
                    self.__build_checkpoint_patch(block.uuid, make_checkpoint_symbol)))

    @staticmethod
    def __build_checkpoint_patch(block_uuid: UUID, make_checkpoint_symbol: gtirb.Symbol):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
            lea rsp, [rsp-8]
            push r11
            lea r11, [rip+{generate_distinct_label_name(".__trampoline_", block_uuid)}]
            mov [rsp+8], r11
            pop r11
            call {make_checkpoint_symbol.name}
            lea rsp, [rsp+8]
        """)
