import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext
from gtirb_rewriting.assembly import Register
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn

from typing import List, Set

from .reg_inst_aware_pass_mixin import RegInstAwarePassMixin
from NaHCO3.utils.progress import print_progress_bar


class VisitorPassMixin(Pass):
    module: gtirb.Module
    rewriting_ctx: RewritingContext

    def visit_function(self, function: Function):
        for block in function.get_all_blocks():
            self.visit_code_block(block, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        pass

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        self.module = module
        self.rewriting_ctx = rewriting_ctx

    def visit_functions(self, functions, section: gtirb.Section = None):
        if section is None:
            function_list = list(functions)
        else:
            function_list = [fn for fn in functions if next(iter(fn.get_entry_blocks())).section.name == section.name]

        functions_count = len(function_list)

        for idx, function in enumerate(function_list):
            print_progress_bar(self.__class__.__name__, idx+1, functions_count)
            self.visit_function(function)

        print('')

    def visit_code_blocks(self, section: gtirb.Section):
        code_blocks_count = len(list(section.code_blocks))

        for idx, block in enumerate(section.code_blocks):
            print_progress_bar(self.__class__.__name__, idx+1, code_blocks_count)
            self.visit_code_block(block)

        print('')


class InstVisitorPassMixin(VisitorPassMixin, RegInstAwarePassMixin):
    enable_live_reg_analysis: bool

    def __init__(self, reg_manager: LiveRegisterManager, decoder: GtirbInstructionDecoder,
                 enable_live_reg_analysis: bool = True):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.enable_live_reg_analysis = enable_live_reg_analysis

    def visit_function(self, function: Function):
        if self.enable_live_reg_analysis:
            self.reg_manager.analyze(function)

        super().visit_function(function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
        inst_offset = 0
        for inst_idx, inst in enumerate(instructions):
            live_registers = self.reg_manager.live_registers(function, block, inst_idx) \
                if function is not None and self.enable_live_reg_analysis else None

            self.visit_inst(inst, inst_idx, inst_offset, block, function, live_registers)
            inst_offset += inst.size

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        pass
