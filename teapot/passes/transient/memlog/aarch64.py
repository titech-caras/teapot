import gtirb
from capstone_gt import CsInsn
from typing import Optional

from teapot.passes.transient.memlog.base import TransientMemlogPassBase


class AArch64TransientMemlogPass(TransientMemlogPassBase):
    EXPECTED_ARCH = "aarch64"

    def _build_patch(self, inst: CsInsn, mem_operand, access_size: int, *,
                     mem_symexpr: Optional[gtirb.SymbolicExpression] = None,
                     reads_registers=None):
        source_label = f".L__aarch64_memlog_src_{str(inst.address).replace('-', '_')}_{access_size}"

        @self.arch.constraints(scratch_registers=3, reads_registers=reads_registers or set())
        def patch(ctx):
            addr_reg, top_reg, data_reg = ctx.scratch_registers[:3]
            return "\n".join((
                f"{source_label}:",
                self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi, inst, addr_reg, data_reg, mem_operand,
                    ctx.stack_adjustment,
                    mem_symexpr=mem_symexpr),
                self.arch.memlog_snippet(addr_reg, top_reg, data_reg, access_size, source_label=source_label),
            ))

        return patch
