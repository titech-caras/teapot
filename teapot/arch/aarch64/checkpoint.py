from uuid import UUID

from gtirb_rewriting import InsertionContext

from teapot.configs.runtime import ROB_LEN, SYMBOL_SUFFIX
from teapot.configs.slots import AARCH64_SHADOW_STACK_CONTROL_OFFSET
from teapot.utils.misc import generate_distinct_label_name


class AArch64CheckpointPatchesMixin:
    CHECKPOINT_PATCH_USES_LIVE_REGISTERS = False
    RESTORE_POINT_PATCH_USES_LIVE_REGISTERS = True

    def checkpoint_patch(self, block_uuid: UUID, use_scratch_registers: bool = True):
        @self.constraints(scratch_registers=0)
        def patch(ctx: InsertionContext):
            trampoline_landing = generate_distinct_label_name(".__trampoline_landing_", block_uuid)
            branch_counter = generate_distinct_label_name(".__branch_counter_", block_uuid)
            return_landing = generate_distinct_label_name(".__return_landing_", block_uuid)
            after_checkpoint = f".L__after_checkpoint{SYMBOL_SUFFIX}"
            return f"""
                {self.save_regs_to_shadow_stack(
                    ("x16", "x17"), frame_offset=AARCH64_SHADOW_STACK_CONTROL_OFFSET, preserve_sp=True)}
                {self.load_address("x16", trampoline_landing)}
                {self.load_address("x17", "checkpoint_target_metadata")}
                str x16, [x17]
                {self.load_address("x16", return_landing)}
                str x16, [x17, #8]
                {self.load_address("x16", branch_counter)}
                str x16, [x17, #16]
                b make_checkpoint_aarch64
            {return_landing}:
                {self.load_address("x16", "checkpoint_target_metadata")}
                ldr x16, [x16, #{self.CHECKPOINT_TARGET_SCRATCH_REG_ADDR}]
            {after_checkpoint}:
                nop
            """

        return patch

    def init_library_patch(self):
        return self.constraints()(lambda ctx: """
            stp x0, x1, [sp, #-32]!
            str x30, [sp, #16]
            bl libcheckpoint_enable
            ldr x30, [sp, #16]
            ldp x0, x1, [sp], #32
        """)

    def fini_library_patch(self):
        return self.constraints()(lambda ctx: """
            stp x0, x30, [sp, #-16]!
            bl libcheckpoint_disable
            ldp x0, x30, [sp], #16
        """)

    def conditional_restore_point_patch(self, instruction_count: int):
        @self.constraints(scratch_registers=2, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            counter_reg, addr_reg = ctx.scratch_registers[:2]
            return f"""
                {self.load_address(addr_reg, "instruction_cnt")}
                ldr {counter_reg}, [{addr_reg}]
                add {counter_reg}, {counter_reg}, #{instruction_count}
                cmp {counter_reg}, #{ROB_LEN}
                b.ge 1f
                str {counter_reg}, [{addr_reg}]
                b 2f
            1:
                b restore_checkpoint_ROB_LEN
            2:
                nop
            """

        return patch

    def unconditional_restore_point_patch(self):
        return self.constraints()(lambda ctx: "b restore_checkpoint_EXT_LIB")
