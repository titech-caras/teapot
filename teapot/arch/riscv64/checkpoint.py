from uuid import UUID

from gtirb_rewriting import InsertionContext

from teapot.configs.runtime import (
    CHECKPOINT_TARGET_FIXED_REG_SOURCE_NONE,
    CHECKPOINT_TARGET_FIXED_REG_SOURCE_OFFSETS,
    ROB_LEN,
    SYMBOL_SUFFIX,
)
from teapot.utils.misc import generate_distinct_label_name


class RISCV64CheckpointPatchesMixin:
    CHECKPOINT_FIXED_REGISTERS = ("t0", "t1")
    CHECKPOINT_PATCH_USES_LIVE_REGISTERS = True
    RESTORE_POINT_PATCH_USES_LIVE_REGISTERS = True

    def _checkpoint_source_offset(self, register: str) -> int:
        register_number = int(self.x_register_name(self.abi.get_register(register))[1:])
        return (register_number - 1) * 8

    def checkpoint_patch(self, block_uuid: UUID, spare_registers=()):
        spare_registers = tuple(spare_registers)

        @self.constraints(scratch_registers=0)
        def patch(ctx: InsertionContext):
            fixed_spill = self.save_regs_to_first_spill(
                self.CHECKPOINT_FIXED_REGISTERS[len(spare_registers):],
                offset=len(spare_registers) * 8,
            ) if len(spare_registers) < len(self.CHECKPOINT_FIXED_REGISTERS) else ""
            register_spill = "\n".join(
                f"mv {spare}, {fixed}"
                for fixed, spare in zip(self.CHECKPOINT_FIXED_REGISTERS, spare_registers)
            )
            source_offsets = [
                self._checkpoint_source_offset(spare)
                for spare in spare_registers
            ] + [CHECKPOINT_TARGET_FIXED_REG_SOURCE_NONE] * (
                len(self.CHECKPOINT_FIXED_REGISTERS) - len(spare_registers))
            register_restore = "\n".join(
                f"mv {fixed}, {spare}"
                for fixed, spare in zip(self.CHECKPOINT_FIXED_REGISTERS, spare_registers)
            )
            trampoline_landing = generate_distinct_label_name(".__trampoline_landing_", block_uuid)
            branch_counter = generate_distinct_label_name(".__branch_counter_", block_uuid)
            return_landing = generate_distinct_label_name(".__return_landing_", block_uuid)
            after_checkpoint = f".L__after_checkpoint{SYMBOL_SUFFIX}"
            return f"""
                {register_spill}
                {fixed_spill}
                {self.load_address("t0", trampoline_landing)}
                {self.load_address("t1", "checkpoint_target_metadata")}
                sd t0, 0(t1)
                {self.load_address("t0", return_landing)}
                sd t0, 8(t1)
                {self.load_address("t0", branch_counter)}
                sd t0, 16(t1)
                li t0, {source_offsets[0]}
                sd t0, {CHECKPOINT_TARGET_FIXED_REG_SOURCE_OFFSETS[0]}(t1)
                li t0, {source_offsets[1]}
                sd t0, {CHECKPOINT_TARGET_FIXED_REG_SOURCE_OFFSETS[1]}(t1)
                {self.jump_symbol("make_checkpoint_riscv64", "t0")}
            {return_landing}:
                {self.load_address("t0", "checkpoint_target_metadata")}
                ld t0, {self.CHECKPOINT_TARGET_SCRATCH_REG_ADDR}(t0)
                {register_restore}
            {after_checkpoint}:
                nop
            """

        return patch

    def init_library_patch(self):
        return self.constraints()(lambda ctx: f"""
            addi sp, sp, -32
            sd a0, 0(sp)
            sd a1, 8(sp)
            sd ra, 16(sp)
            {self.call_symbol("libcheckpoint_enable")}
            ld ra, 16(sp)
            ld a1, 8(sp)
            ld a0, 0(sp)
            addi sp, sp, 32
        """)

    def fini_library_patch(self):
        return self.constraints()(lambda ctx: f"""
            addi sp, sp, -16
            sd a0, 0(sp)
            sd ra, 8(sp)
            {self.call_symbol("libcheckpoint_disable")}
            ld ra, 8(sp)
            ld a0, 0(sp)
            addi sp, sp, 16
        """)

    def conditional_restore_point_patch(self, instruction_count: int):
        @self.constraints(scratch_registers=2)
        def patch(ctx: InsertionContext):
            counter_reg, limit_reg = ctx.scratch_registers[:2]
            return f"""
                {self.load_address(limit_reg, "instruction_cnt")}
                ld {counter_reg}, 0({limit_reg})
                li {limit_reg}, {instruction_count}
                add {counter_reg}, {counter_reg}, {limit_reg}
                li {limit_reg}, {ROB_LEN}
                bgeu {counter_reg}, {limit_reg}, 1f
                {self.load_address(limit_reg, "instruction_cnt")}
                sd {counter_reg}, 0({limit_reg})
                j 2f
            1:
                {self.jump_symbol("restore_checkpoint_ROB_LEN", counter_reg)}
            2:
                nop
            """

        return patch

    def unconditional_restore_point_patch(self):
        return self.constraints()(lambda ctx: self.jump_symbol("restore_checkpoint_EXT_LIB", "t0"))
