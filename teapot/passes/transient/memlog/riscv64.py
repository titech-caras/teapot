from capstone_gt import CsInsn

from teapot.passes.transient.memlog.base import TransientMemlogPassBase


class RISCV64TransientMemlogPass(TransientMemlogPassBase):
    EXPECTED_ARCH = "riscv64"

    def _build_patch(self, inst: CsInsn, mem_operand, access_size: int, *,
                     mem_symexpr=None, reads_registers=None):
        @self.arch.constraints(scratch_registers=3, reads_registers=reads_registers or set())
        def patch(ctx):
            addr_reg, top_reg, data_reg = ctx.scratch_registers[:3]
            return "\n".join((
                self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi, inst, addr_reg, data_reg, mem_operand, ctx.stack_adjustment),
                self.arch.memlog_snippet(addr_reg, top_reg, data_reg, access_size),
            ))

        return patch
