from uuid import UUID

from teapot.configs.slots import (
    RISCV64_LANDING_RESTORE_FLAG_OFFSET,
    RISCV64_LANDING_TEMP_OFFSET,
    RISCV64_ORIGINAL_TP_OFFSET,
)
from teapot.utils.misc import generate_distinct_label_name


class RISCV64LandingPadPatchesMixin:
    @staticmethod
    def landing_pad_entry_label(block_uuid: UUID, *, normal_text: bool = False) -> str:
        prefix = ".L__rv64_text_restore_landing_" if normal_text else ".L__rv64_restore_landing_"
        return generate_distinct_label_name(prefix, block_uuid)

    def restore_landing_entry_patch(self, block_uuid: UUID, *, normal_text: bool = False,
                                    preserve_marker: bool = False):
        @self.constraints()
        def patch(ctx):
            entry_label = self.landing_pad_entry_label(block_uuid, normal_text=normal_text)
            restore_label = entry_label + "_restore"
            done_label = entry_label + "_done"
            marker = "\n".join(f".word 0x{word:08x}" for word in self.MAGIC_WORDS) if preserve_marker else ""
            return f"""
                {marker}
                {self.load_address("tp", f"scratchpad+{RISCV64_LANDING_TEMP_OFFSET}")}
                sd t0, 0(tp)
                sd t1, 8(tp)
                {self.load_address("tp", f"scratchpad+{RISCV64_LANDING_RESTORE_FLAG_OFFSET}")}
                ld t0, 0(tp)
                bnez t0, {restore_label}
                {self.load_address("tp", f"scratchpad+{RISCV64_LANDING_TEMP_OFFSET}")}
                ld t1, 8(tp)
                ld t0, 0(tp)
                {self.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}")}
                ld tp, 0(tp)
                j {done_label}
            {restore_label}:
                sd zero, 0(tp)
                {self.restore_regs_from_first_spill(self.FIRST_SPILL_T0_T1)}
            {done_label}:
                nop
            """

        return patch
