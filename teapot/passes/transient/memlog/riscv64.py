from capstone_gt import CsInsn

from teapot.configs.slots import SCRATCHPAD_FIRST_SPILL_OFFSET
from teapot.passes.transient.memlog.base import TransientMemlogPassBase


class RISCV64TransientMemlogPass(TransientMemlogPassBase):
    EXPECTED_ARCH = "riscv64"

    def _build_patch(self, inst: CsInsn, mem_operand, access_size: int, *, mem_symexpr=None):
        fixed_regs = self.arch.fixed_spill_registers(self.reg_manager.abi, 3)
        saved_reg_offsets = {
            reg.name: SCRATCHPAD_FIRST_SPILL_OFFSET + idx * 8
            for idx, reg in enumerate(fixed_regs)
        }

        @self.arch.constraints()
        def patch(ctx):
            addr_reg, top_reg, data_reg = fixed_regs
            return "\n".join((
                self.arch.save_regs_to_first_spill(fixed_regs),
                self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi, inst, addr_reg, data_reg, mem_operand, ctx.stack_adjustment,
                    saved_reg_offsets=saved_reg_offsets),
                self.arch.memlog_snippet(addr_reg, top_reg, data_reg, access_size),
                self.arch.restore_regs_from_first_spill(fixed_regs),
            ))

        return patch
