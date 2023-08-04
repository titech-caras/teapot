import gtirb
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn

from datacls.copied_section_mapping import CopiedSectionMapping
from utils.misc import distinguish_edges
from config import SYMBOL_SUFFIX


class TransientRetpolinesPass(Pass):
    text_section: gtirb.Section
    transient_section_end_symbol: gtirb.Symbol
    text_transient_mapping: CopiedSectionMapping

    def __init__(self, text_section: gtirb.Section, transient_section_end_symbol: gtirb.Symbol,
                 text_transient_mapping: CopiedSectionMapping):
        self.text_section = text_section
        self.transient_section_end_symbol = transient_section_end_symbol
        self.text_transient_mapping = text_transient_mapping

        self.decoder = GtirbInstructionDecoder(text_section.module.isa)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        for block in self.text_section.code_blocks:
            non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                continue

            transient_block = self.text_transient_mapping.code_blocks_map[block.uuid]

            if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return:
                # last instruction must be `ret`
                rewriting_ctx.replace_at(transient_block, transient_block.size - 1, 1,
                                         Patch.from_function(self.__patch))

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def __patch(self, ctx):
        return f"""
            pop r11
            lea r10, [rip+{self.transient_section_end_symbol.name}]
            cmp r10, r11
            jl .L__retpoline_skip{SYMBOL_SUFFIX}
            pop r11
        .L__retpoline_skip{SYMBOL_SUFFIX}:
            jmp r11            
        """
