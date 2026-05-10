from typing import Set

import gtirb
from capstone_gt import CsInsn
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Patch, RewritingContext
from gtirb_rewriting.assembly import Register

from teapot.arch.architecture import Architecture
from teapot.passes.mixins import ArchSpecificPassMixin, InstVisitorPassMixin


class TransientMemlogPassBase(ArchSpecificPassMixin, InstVisitorPassMixin):
    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder, arch: Architecture):
        self.check_expected_arch(arch)
        super().__init__(reg_manager, decoder)
        self.transient_section = transient_section
        self.arch = arch

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if self.arch.dift_should_skip_instruction(inst):
            return
        if self.arch.is_instrumentation_helper_instruction(
                inst, inst_idx, getattr(self, "_current_instructions", None)):
            return

        mem_operand = self.arch.memory_operand(inst)
        if mem_operand is None or not self.arch.mem_operand_is_write(inst, mem_operand):
            return

        access_size = self.arch.mem_operand_size(inst, mem_operand)
        if access_size == 0:
            return

        regs_read = self.arch.access_registers(self.reg_manager.abi, inst, 0)
        regs_read.update(self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand))
        self.reg_manager.add_live_registers(function, block, inst_idx, regs_read)

        mem_symexpr = self.arch.operand_symbolic_expression(block, inst, mem_operand, inst_offset)
        patch = self._build_patch(inst, mem_operand, access_size, mem_symexpr=mem_symexpr)
        patch = self.reg_manager.allocate_registers(function, block, inst_idx)(patch)
        self.insert_at(block, inst_offset, Patch.from_function(patch))

    def _build_patch(self, inst: CsInsn, mem_operand, access_size: int, *, mem_symexpr=None):
        raise NotImplementedError(type(self).__name__)
