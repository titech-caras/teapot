from dataclasses import dataclass
from typing import List, Set

import gtirb
from capstone_gt import CS_OP_MEM, CS_OP_REG, CsInsn
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Patch, RewritingContext
from gtirb_rewriting.assembly import Register

from teapot.arch.architecture import Architecture
from teapot.datacls.dift_layout import get_dift_layout
from teapot.passes.mixins import ArchSpecificPassMixin, InstVisitorPassMixin


@dataclass(frozen=True)
class MemOperandPolicyPatch:
    patch: object
    live_registers: Set[Register]


class TransientMemOperandPoliciesPassBase(ArchSpecificPassMixin, InstVisitorPassMixin):
    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder, arch: Architecture, *, dift_layout=None,
                 enable_asan_check: bool = True):
        self.check_expected_arch(arch)
        super().__init__(reg_manager, decoder)
        self.transient_section = transient_section
        self.arch = arch
        self.dift_layout = dift_layout or get_dift_layout(arch.name)
        self.enable_asan_check = enable_asan_check

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        patch_info = self._build_policy_patch(inst, inst_idx, inst_offset, block, function)
        if patch_info is None:
            return

        if patch_info.live_registers:
            self.reg_manager.add_live_registers(
                function, block, inst_idx, patch_info.live_registers)
        patch = self.reg_manager.allocate_registers(
            function, block, inst_idx)(patch_info.patch)
        self.insert_at(block, inst_offset, Patch.from_function(patch))

    def _build_policy_patch(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                            block: gtirb.CodeBlock, function: Function = None):
        raise NotImplementedError(type(self).__name__)

    def _load_destination_registers(self, inst: CsInsn, regs_write: Set[Register],
                                    stop_operand=None, fallback_to_all_writes: bool = False) -> List[Register]:
        if not regs_write:
            return []

        write_names = {reg.name.lower(): reg for reg in regs_write}
        result = []
        seen = set()
        for operand in inst.operands:
            if operand is stop_operand or operand.type == CS_OP_MEM:
                break
            if operand.type != CS_OP_REG:
                continue

            reg = self.arch.register_from_name(self.reg_manager.abi, inst.reg_name(operand.reg))
            if reg is None:
                continue
            write_reg = write_names.get(reg.name.lower())
            if write_reg is None or write_reg.name in seen:
                continue
            result.append(write_reg)
            seen.add(write_reg.name)

        if result or not fallback_to_all_writes:
            return result
        return list(regs_write)
