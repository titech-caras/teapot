from typing import Optional, Set

import gtirb
from capstone_gt import CsInsn
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Patch, RewritingContext
from gtirb_rewriting.assembly import Register

from teapot.arch.architecture import Architecture
from teapot.configs.blacklist import is_blacklisted_function
from teapot.datacls.dift_layout import get_dift_layout
from teapot.passes.mixins import ArchSpecificPassMixin, InstVisitorPassMixin


class DiftPropagationBase(ArchSpecificPassMixin, InstVisitorPassMixin):
    section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, section: gtirb.Section, decoder: GtirbInstructionDecoder,
                 arch: Architecture, *, dift_layout=None, insert_memlog: bool = False):
        self.check_expected_arch(arch)
        super().__init__(reg_manager, decoder)
        self.section = section
        self.arch = arch
        self.dift_layout = dift_layout or get_dift_layout(arch.name)
        self.insert_memlog = insert_memlog

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.visit_functions(functions, self.section)

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        super().visit_function(function)

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if self.arch.dift_should_skip_instruction(inst):
            return
        if self.arch.is_instrumentation_helper_instruction(
                inst, inst_idx, getattr(self, "_current_instructions", None)):
            return

        regs_read = self.arch.access_registers(self.reg_manager.abi, inst, 0)
        regs_write = self.arch.access_registers(self.reg_manager.abi, inst, 1)
        regs_read = self._filter_ignored_registers(regs_read)
        regs_write = self._filter_ignored_registers(regs_write)
        mem_operand = self.arch.memory_operand(inst)
        if mem_operand is not None:
            regs_read.update(self._filter_ignored_registers(
                self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand)))
        mem_read = mem_operand if mem_operand is not None and self.arch.mem_operand_is_read(
            inst, mem_operand) else None
        mem_write = mem_operand if mem_operand is not None and self.arch.mem_operand_is_write(
            inst, mem_operand) else None
        mem_write_size = self.arch.mem_operand_size(inst, mem_write) if mem_write is not None else 0
        if mem_write is not None and mem_write_size == 0:
            mem_write = None

        if not regs_write and mem_write is None:
            return

        clear_dest_tags = self.arch.dift_clears_destination_tags(inst)
        if not clear_dest_tags and regs_read == regs_write and mem_read is None and mem_write is None:
            return

        patch = self._build_patch(
            inst,
            regs_read,
            regs_write,
            clear_dest_tags=clear_dest_tags,
            mem_read=mem_read,
            mem_write=mem_write,
            mem_write_size=mem_write_size,
            mem_symexpr=(
                self.arch.operand_symbolic_expression(block, inst, mem_operand, inst_offset)
                if mem_operand is not None else None),
        )
        self.reg_manager.add_live_registers(function, block, inst_idx, regs_read.union(regs_write))
        patch = self.reg_manager.allocate_registers(function, block, inst_idx)(patch)
        self.insert_at(block, inst_offset, Patch.from_function(patch))

    def _filter_ignored_registers(self, regs: Set[Register]) -> Set[Register]:
        ignored = self.arch.dift_ignored_register_names()
        return {reg for reg in regs if reg.name.lower() not in ignored}

    def _build_patch(self, inst: CsInsn, regs_read: Set[Register], regs_write: Set[Register], *,
                     clear_dest_tags: bool, mem_read, mem_write, mem_write_size: int,
                     mem_symexpr: Optional[gtirb.SymbolicExpression] = None):
        raise NotImplementedError(type(self).__name__)
