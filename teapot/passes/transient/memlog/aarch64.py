import gtirb
from capstone_gt import CsInsn
from typing import Optional

from teapot.configs.slots import AARCH64_SHADOW_STACK_MEMLOG_OFFSET
from teapot.passes.transient.memlog.base import TransientMemlogPassBase


class AArch64TransientMemlogPass(TransientMemlogPassBase):
    EXPECTED_ARCH = "aarch64"

    def _build_patch(self, inst: CsInsn, mem_operand, access_size: int, *,
                     mem_symexpr: Optional[gtirb.SymbolicExpression] = None):
        fixed_regs = self.arch.fixed_spill_registers(self.reg_manager.abi, 3)
        frame_offset = AARCH64_SHADOW_STACK_MEMLOG_OFFSET
        saved_reg_offsets = self.arch.fixed_scratch_offsets(fixed_regs, frame_offset)
        source_label = f".L__aarch64_memlog_src_{str(inst.address).replace('-', '_')}_{access_size}_{frame_offset}"

        @self.arch.constraints()
        def patch(ctx):
            addr_reg, top_reg, data_reg = fixed_regs
            return "\n".join((
                f"{source_label}:",
                self.arch.save_regs_to_shadow_stack(
                    fixed_regs, save_flags=False, frame_offset=frame_offset, preserve_sp=True),
                self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi, inst, addr_reg, data_reg, mem_operand,
                    ctx.stack_adjustment,
                    mem_symexpr=mem_symexpr, saved_reg_offsets=saved_reg_offsets,
                    saved_reg_base="shadow_sp"),
                self.arch.memlog_snippet(addr_reg, top_reg, data_reg, access_size, source_label=source_label),
                self.arch.restore_regs_from_shadow_stack(
                    fixed_regs, save_flags=False, frame_offset=frame_offset, preserve_sp=True),
            ))

        return patch
