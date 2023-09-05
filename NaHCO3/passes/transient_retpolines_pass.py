import gtirb
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder

from NaHCO3.datacls.copied_section_mapping import CopiedSectionMapping
from NaHCO3.utils.misc import distinguish_edges
from NaHCO3.config import SYMBOL_SUFFIX


class TransientRetpolinesPass(Pass):
    transient_section: gtirb.Section
    transient_section_start_symbol: gtirb.Symbol
    transient_section_end_symbol: gtirb.Symbol

    def __init__(self, transient_section: gtirb.Section,
                 transient_section_start_symbol: gtirb.Symbol, transient_section_end_symbol: gtirb.Symbol):
        self.transient_section = transient_section
        self.transient_section_start_symbol = transient_section_start_symbol
        self.transient_section_end_symbol = transient_section_end_symbol

        self.decoder = GtirbInstructionDecoder(transient_section.module.isa)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        for function in functions:
            if next(iter(function.get_entry_blocks())).section.name != self.transient_section.name:
                continue

            if function.get_name() == "main" + SYMBOL_SUFFIX:
                continue

            for block in function.get_all_blocks():
                non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
                if len(non_fallthrough_edges) == 0:
                    continue

                if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return:
                    # last instruction must be `ret`
                    rewriting_ctx.replace_at(block, block.size - 1, 1, Patch.from_function(self.__patch))

    @patch_constraints(x86_syntax=X86Syntax.INTEL)
    def __patch(self, ctx):
        r1, r2, r3 = "r9", "r10", "r11"  # TODO: make it work with ctx.scratch_registers
        return f"""
            pop {r1}
            lea {r2}, [rip+{self.transient_section_start_symbol.name}]
            mov {r3}, {r1}
            sub {r3}, {r2}
            lea {r2}, [rip+{self.transient_section_end_symbol.name}]
            cmp {r2}, {r3}
            ja .L__retpoline_skip{SYMBOL_SUFFIX}
            pop {r1}
        .L__retpoline_skip{SYMBOL_SUFFIX}:
            jmp {r1}            
        """
