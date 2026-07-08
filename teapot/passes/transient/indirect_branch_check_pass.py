import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Patch, RewritingContext

from teapot.arch.architecture import Architecture
from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.passes.mixins import ArchSpecificPassMixin, RegInstAwarePassMixin, VisitorPassMixin
from teapot.utils.misc import distinguish_edges


class TransientIndirectBranchCheckDestPass(ArchSpecificPassMixin, VisitorPassMixin, RegInstAwarePassMixin):
    transient_section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder,
                 transient_section_start_symbol: gtirb.Symbol, transient_section_end_symbol: gtirb.Symbol,
                 text_section_start_symbol: gtirb.Symbol, text_section_end_symbol: gtirb.Symbol,
                 arch: Architecture):
        self.check_expected_arch(arch)
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.transient_section = transient_section
        self.transient_section_start_symbol = transient_section_start_symbol
        self.transient_section_end_symbol = transient_section_end_symbol
        self.text_section_start_symbol = text_section_start_symbol
        self.text_section_end_symbol = text_section_end_symbol
        self.arch = arch

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_function(self, function: Function):
        if self.reg_manager is not None and self.arch.uses_live_registers:
            self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        edge = non_fallthrough_edges[0]
        if not self._must_check_edge(edge, function):
            return

        instructions = list(self.decoder.get_instructions(block))
        last_inst = instructions[-1]
        operand_str = self.arch.indirect_branch_operand(edge.label.type, last_inst, block)
        operand_registers = set()
        if self.reg_manager is not None:
            operand_registers = self.arch.registers_in_operand_string(self.reg_manager.abi, operand_str)
        if self.reg_manager is not None and self.arch.uses_live_registers:
            self.reg_manager.add_live_registers(function, block, len(instructions) - 1, operand_registers)

        patch = self.arch.indirect_branch_check_patch(
            operand_str, self.transient_section_start_symbol, self.transient_section_end_symbol,
            self.text_section_start_symbol, self.text_section_end_symbol,
            reads_registers={reg.name for reg in operand_registers})
        if self.reg_manager is not None and self.arch.uses_live_registers:
            patch = self.reg_manager.allocate_registers(
                function, block, len(instructions) - 1)(patch)
        self.insert_at(block, sum(inst.size for inst in instructions[:-1]), Patch.from_function(patch))

    @staticmethod
    def _must_check_edge(edge: gtirb.Edge, function: Function) -> bool:
        return (
            edge.label.type == gtirb.cfg.Edge.Type.Return and function.get_name() != "main" + SYMBOL_SUFFIX
        ) or (
            edge.label.type in (gtirb.cfg.Edge.Type.Call, gtirb.cfg.Edge.Type.Branch) and
            not edge.label.direct
        )
