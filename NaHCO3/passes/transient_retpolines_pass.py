import gtirb
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder

from NaHCO3.datacls.copied_section_mapping import CopiedSectionMapping
from NaHCO3.utils.misc import distinguish_edges
from NaHCO3.config import SYMBOL_SUFFIX


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
        for function in functions:
            if function.get_name() == "main":
                continue

            for block in function.get_all_blocks():
                if block.section != ".text":
                    continue

                non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
                if len(non_fallthrough_edges) == 0:
                    continue

                transient_block = self.text_transient_mapping.code_blocks_map[block.uuid]

                if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return:
                    # TODO: do not transform if function is `main`
                    # last instruction must be `ret`
                    rewriting_ctx.replace_at(transient_block, transient_block.size - 1, 1,
                                             Patch.from_function(self.__patch))

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def __patch(self, ctx):
        r1, r2 = "r11", "r10"  # TODO: make it work with ctx.scratch_registers
        return f"""
            pop {r1}
            lea {r2}, [rip+{self.transient_section_end_symbol.name}]
            cmp {r2}, {r1}
            jg .L__retpoline_skip{SYMBOL_SUFFIX}
            pop {r1}
        .L__retpoline_skip{SYMBOL_SUFFIX}:
            jmp {r1}            
        """
