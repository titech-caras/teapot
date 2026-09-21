from typing import Set

from gtirb_rewriting import InsertionContext
from gtirb_rewriting.assembly import Register

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import SCRATCHPAD_FIRST_SPILL_OFFSET
from teapot.passes.common.dift.base import DiftPropagationBase


class RISCV64DiftPropagationPass(DiftPropagationBase):
    EXPECTED_ARCH = "riscv64"

    def _build_patch(self, inst, regs_read: Set[Register], regs_write: Set[Register], *,
                     clear_dest_tags: bool, mem_read, mem_write, mem_write_size: int,
                     mem_symexpr=None, live_registers=None):
        scratch_plan = self._plan_scratch_registers(4 if self.insert_memlog else 3, live_registers)
        saved_reg_offsets = {
            reg.name: SCRATCHPAD_FIRST_SPILL_OFFSET + idx * 8
            for idx, reg in enumerate(scratch_plan.saved_regs)
        }

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            tag_reg, addr_reg, tmp_reg = scratch_plan.registers[:3]
            memlog_data_reg = scratch_plan.registers[3] if self.insert_memlog else None
            done_label = f".L__dift_done{SYMBOL_SUFFIX}"

            asm = self.arch.save_regs_to_first_spill(scratch_plan.saved_regs)
            asm += "\n" + self.arch.clear_register_snippet(tag_reg)
            if not clear_dest_tags:
                for reg in regs_read:
                    asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)

                if mem_read is not None:
                    asm += self.arch.mem_operand_address_snippet(
                        self.reg_manager.abi, inst, addr_reg, tmp_reg, mem_read, ctx.stack_adjustment,
                        mem_symexpr=mem_symexpr, saved_reg_offsets=saved_reg_offsets)
                    asm += self.arch.dift_shadow_addr_snippet(addr_reg, tmp_reg, self.dift_layout.xor_mask)
                    asm += f"""
                        lbu {tmp_reg}, 0({addr_reg})
                        or {tag_reg}, {tag_reg}, {tmp_reg}
                    """

            for reg in regs_write:
                asm += self.arch.dift_store_reg_tag_snippet(tag_reg, tmp_reg, reg)

            if mem_write is not None:
                if mem_read is None or mem_write != mem_read:
                    asm += self.arch.mem_operand_address_snippet(
                        self.reg_manager.abi, inst, addr_reg, tmp_reg, mem_write, ctx.stack_adjustment,
                        mem_symexpr=mem_symexpr, saved_reg_offsets=saved_reg_offsets)
                    asm += self.arch.dift_shadow_addr_snippet(addr_reg, tmp_reg, self.dift_layout.xor_mask)
                for idx in range(mem_write_size):
                    if idx:
                        asm += f"addi {addr_reg}, {addr_reg}, 1\n"
                    if self.insert_memlog and idx % 8 == 0:
                        asm += self.arch.memlog_snippet(
                            addr_reg, tmp_reg, memlog_data_reg, min(8, mem_write_size - idx),
                            no_clobber_addr=True)
                    asm += f"sb {tag_reg}, 0({addr_reg})\n"

            if mem_read is not None:
                asm += self.arch.dift_apply_queued_tag_snippet(tag_reg, addr_reg, tmp_reg, done_label)

            asm += f"""
            {done_label}:
                nop
            """
            asm += self.arch.restore_regs_from_first_spill(scratch_plan.saved_regs)
            return asm

        return patch
