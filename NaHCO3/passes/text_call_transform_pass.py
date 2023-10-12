import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from typing import List
import functools

from NaHCO3.passes.mixins import VisitorPassMixin
from NaHCO3.datacls.copied_section_mapping import CopiedSectionMapping
from NaHCO3.utils.misc import distinguish_edges, generate_distinct_label_name


class TextCallTransformPass(VisitorPassMixin):
    text_section: gtirb.Section
    text_transient_mapping: CopiedSectionMapping

    def __init__(self, text_section: gtirb.Section, text_transient_mapping: CopiedSectionMapping,
                 decoder: GtirbInstructionDecoder):
        self.text_section = text_section
        self.text_transient_mapping = text_transient_mapping

        self.decoder = decoder

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.visit_code_blocks(self.text_section)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Call:
            call_edge: gtirb.Edge = non_fallthrough_edges[0]
            if isinstance(call_edge.target, gtirb.ProxyBlock):
                # TODO: call to external library
                pass
            elif call_edge.target.byte_interval.section.name == ".text":
                if len(fallthrough_edges) == 0:
                    return
                fallthrough_edge: gtirb.Edge = fallthrough_edges[0]

                instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
                call_offset = functools.reduce(lambda x, i: x + i.size, instructions[:-1], 0)

                call_transform_target_symbol = gtirb.Symbol(
                    name=generate_distinct_label_name(".L__call_transform_target", fallthrough_edge.target.uuid),
                    payload=self.text_transient_mapping.code_blocks_map[fallthrough_edge.target.uuid],
                    module=self.module)

                self.rewriting_ctx.insert_at(block, call_offset, Patch.from_function(
                    self.__build_transform_patch(call_transform_target_symbol)))
                self.rewriting_ctx.insert_at(block, call_offset + instructions[-1].size,
                                        Patch.from_function(self.__patch_balance_stack))

    @staticmethod
    def __build_transform_patch(target_symbol: gtirb.Symbol):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
            lea r11, [rip+{target_symbol.name}]
            push r11
        """)

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def __patch_balance_stack(self, ctx):
        return "add rsp, 8"
