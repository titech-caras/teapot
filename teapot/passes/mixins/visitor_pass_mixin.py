import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext
from gtirb_rewriting.assembly import Register
from teapot.liveness import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone import CsInsn

from typing import List, Set

from .reg_inst_aware_pass_mixin import RegInstAwarePassMixin
from teapot.utils.progress import print_progress_bar


class VisitorPassMixin(Pass):
    module: gtirb.Module
    rewriting_ctx: RewritingContext

    def visit_function(self, function: Function):
        for block in function.get_all_blocks():
            section = getattr(self, "_visit_section", None)
            if section is not None and (
                    block.section is None or block.section.name != section.name):
                continue
            self.visit_code_block(block, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        pass

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        self.module = module
        self.rewriting_ctx = rewriting_ctx

    def end_module(self, module: gtirb.Module, functions) -> None:
        del self.rewriting_ctx
        del self.module

    def insert_at(self, block: gtirb.CodeBlock, offset: int, patch):
        arch = getattr(self, "arch", None)
        decoder = getattr(self, "decoder", None)
        if arch is not None and decoder is not None:
            instructions = (self._current_instructions
                            if block is getattr(self, "_current_block", None)
                            else list(decoder.get_instructions(block)))
            offset = arch.adjust_insertion_offset(block, offset, instructions)
        self.rewriting_ctx.insert_at(block, offset, patch)

    def insertion_register_location(self, block: gtirb.CodeBlock, instruction_idx: int):
        instructions = (self._current_instructions
                        if block is getattr(self, "_current_block", None)
                        else list(self.decoder.get_instructions(block)))
        if not 0 <= instruction_idx < len(instructions):
            return block, len(instructions)
        offset = instructions[instruction_idx].address - instructions[0].address
        adjusted_offset = self.arch.adjust_insertion_offset(block, offset, instructions)
        # The rewriter can move a patch into another block, or across a
        # complete HI/LO pair after the architecture's entry adjustment.
        adjusted_block, adjusted_offset = self.rewriting_ctx.resolve_insert_location(
            block, adjusted_offset)
        if adjusted_block is block and adjusted_offset == offset:
            return block, instruction_idx
        if adjusted_block is not block:
            instructions = list(self.decoder.get_instructions(adjusted_block))
        adjusted_idx = next((idx for idx, inst in enumerate(instructions)
                             if inst.address - instructions[0].address == adjusted_offset), len(instructions))
        return adjusted_block, adjusted_idx

    def allocate_registers(self, function: Function, block: gtirb.CodeBlock,
                           instruction_idx: int, allow_fallback: bool = True):
        adjusted_block, adjusted_idx = self.insertion_register_location(block, instruction_idx)
        if adjusted_block is not block or adjusted_idx != instruction_idx:
            # Placement can move after an AUIPC. Keep both the actual boundary
            # state and any operand/capture requirements recorded at the source.
            self.reg_manager.add_live_registers(
                function, adjusted_block, adjusted_idx,
                self.reg_manager.live_registers(function, block, instruction_idx))
        return self.reg_manager.allocate_registers(
            function, adjusted_block, adjusted_idx, allow_fallback)

    def visit_functions(self, functions, section: gtirb.Section = None):
        if section is None:
            function_list = list(functions)
        else:
            function_list = [fn for fn in functions if next(iter(fn.get_entry_blocks())).section.name == section.name]

        functions_count = len(function_list)
        previous_section = getattr(self, "_visit_section", None)
        self._visit_section = section

        try:
            for idx, function in enumerate(function_list):
                print_progress_bar(self.__class__.__name__, idx+1, functions_count)
                self.visit_function(function)
        finally:
            self._visit_section = previous_section

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
        previous_instructions = getattr(self, "_current_instructions", None)
        previous_block = getattr(self, "_current_block", None)
        self._current_instructions = instructions
        self._current_block = block
        inst_offset = 0
        try:
            for inst_idx, inst in enumerate(instructions):
                live_registers = self.reg_manager.live_registers(function, block, inst_idx) \
                    if function is not None and self.enable_live_reg_analysis else None

                self.visit_inst(inst, inst_idx, inst_offset, block, function, live_registers)
                inst_offset += inst.size
        finally:
            self._current_instructions = previous_instructions
            self._current_block = previous_block

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        pass
