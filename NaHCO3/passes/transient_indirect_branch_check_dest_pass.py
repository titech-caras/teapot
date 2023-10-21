import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder

from gtirb_live_register_analysis import LiveRegisterManager
from NaHCO3.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from NaHCO3.datacls.copied_section_mapping import CopiedSectionMapping
from NaHCO3.utils.misc import distinguish_edges
from NaHCO3.config import SYMBOL_SUFFIX


class TransientIndirectBranchCheckDestPass(VisitorPassMixin, RegInstAwarePassMixin):
    transient_section: gtirb.Section

    MAGIC = "0x90909090"  # FIXME: the magic got eaten by gtirb!
    # MAGIC = "0x40461f0f"  # nop dword ptr [rsi+64]; magic of a transformed destination

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder,
                 transient_section_start_symbol: gtirb.Symbol, transient_section_end_symbol: gtirb.Symbol):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.transient_section = transient_section
        self.transient_section_start_symbol = transient_section_start_symbol
        self.transient_section_end_symbol = transient_section_end_symbol

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        if (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return and
                function.get_name() != "main" + SYMBOL_SUFFIX) or \
                (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                 not non_fallthrough_edges[0].label.direct):
            instructions = list(self.decoder.get_instructions(block))
            self.rewriting_ctx.insert_at(block, sum(inst.size for inst in instructions[:-1]), Patch.from_function(
                self.reg_manager.allocate_registers(function, block, len(instructions) - 1)(
                    self.__indirect_branch_check_dist_patch)))

    @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3)
    def __indirect_branch_check_dist_patch(self, ctx):
        r1, r2, r3 = ctx.scratch_registers
        return f"""
            mov {r1}, [rsp]
            lea {r2}, [rip+{self.transient_section_start_symbol.name}]
            mov {r3}, {r1}
            sub {r3}, {r2}
            lea {r2}, [rip+{self.transient_section_end_symbol.name}]
            cmp {r2}, {r3}
            ja .L__indbr_check_skip{SYMBOL_SUFFIX}
            cmp dword ptr [{r1}], {self.MAGIC}
            jne restore_checkpoint_MALFORMED_INDIRECT_BR
        .L__indbr_check_skip{SYMBOL_SUFFIX}:
            nop
        """
