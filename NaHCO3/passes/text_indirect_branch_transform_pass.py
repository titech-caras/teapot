import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from typing import List
import functools

from NaHCO3.config import BLACKLIST_FUNCTION_NAMES
from NaHCO3.passes.mixins import VisitorPassMixin
from NaHCO3.datacls.copied_section_mapping import CopiedSectionMapping
from NaHCO3.utils.misc import distinguish_edges, generate_distinct_label_name


class TextIndirectBranchTransformPass(VisitorPassMixin):
    text_section: gtirb.Section
    text_transient_mapping: CopiedSectionMapping

    def __init__(self, text_section: gtirb.Section, text_transient_mapping: CopiedSectionMapping,
                 decoder: GtirbInstructionDecoder):
        self.text_section = text_section
        self.text_transient_mapping = text_transient_mapping

        self.decoder = decoder

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.visit_functions(functions, self.text_section)

    def visit_function(self, function: Function):
        if function.get_name() in BLACKLIST_FUNCTION_NAMES:
            return

        super().visit_function(function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        incoming_edges = list(block.incoming_edges)
        non_fallthrough_edges, fallthrough_edges = distinguish_edges(incoming_edges)

        if (len(incoming_edges) == 0 or  # Sometimes GTIRB doesn't detect indirect branches
                any(e.label.type in (gtirb.cfg.Edge.Type.Call, gtirb.cfg.Edge.Type.Branch) and
                    not e.label.direct for e in non_fallthrough_edges)):
            # FIXME: Can we handle jump tables better altogether? Maybe there's a better way...
            indbr_transform_target_symbol = gtirb.Symbol(
                name=generate_distinct_label_name(".L__indbr_transform_target_" + function.get_name() + "_",
                                                  block.uuid),
                payload=self.text_transient_mapping.code_blocks_map[block.uuid],
                module=self.module)
            self.rewriting_ctx.insert_at(block, 0, Patch.from_function(
                self.__build_indirect_branch_target_patch(indbr_transform_target_symbol)))

        if (len(fallthrough_edges) > 0 and
                any(e.label.type == gtirb.cfg.Edge.Type.Call for e in fallthrough_edges[0].source.outgoing_edges)):
            ret_transform_target_symbol = gtirb.Symbol(
                name=generate_distinct_label_name(".L__ret_transform_target_" + function.get_name() + "_",
                                                  block.uuid),
                payload=self.text_transient_mapping.code_blocks_map[block.uuid],
                module=self.module)
            self.rewriting_ctx.insert_at(fallthrough_edges[0].source, fallthrough_edges[0].source.size, Patch.from_function(
                self.__build_indirect_branch_target_patch(ret_transform_target_symbol)))

    @staticmethod
    def __build_indirect_branch_target_patch(target_symbol: gtirb.Symbol):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
            .byte 0x48, 0x87, 0xdb, 0x90 # xchg rbx, rbx; nop
            cmp qword ptr checkpoint_cnt, 0
            jne {target_symbol.name}
        """)
