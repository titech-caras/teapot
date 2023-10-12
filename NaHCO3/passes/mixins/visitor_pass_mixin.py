import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass
from gtirb_rewriting.assembly import Register
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn

from typing import List, Set

from .reg_inst_aware_pass_mixin import RegInstAwarePassMixin


class VisitorPassMixin(Pass):
    def visit_function(self, function: Function):
        for block in function.get_all_blocks():
            self.visit_code_block(block, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        pass

    def visit_functions(self, functions, section: gtirb.Section = None):
        for function in functions:
            if section is not None and next(iter(function.get_entry_blocks())).section.name != section.name:
                continue

            self.visit_function(function)

    def visit_code_blocks(self, section: gtirb.Section):
        for block in section.code_blocks:
            self.visit_code_block(block)


class InstVisitorPassMixin(VisitorPassMixin, RegInstAwarePassMixin):
    enable_live_reg_analysis: bool

    def __init__(self, reg_manager: LiveRegisterManager, decoder: GtirbInstructionDecoder,
                 enable_live_reg_analysis: bool = True):
        super(RegInstAwarePassMixin, self).__init__(reg_manager, decoder)
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

            inst_offset += inst.size
            self.visit_inst(inst, inst_idx, inst_offset, block, function, live_registers)

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        pass
