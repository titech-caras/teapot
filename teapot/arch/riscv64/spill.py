from teapot.configs.slots import (
    RISCV64_LANDING_RESTORE_FLAG_OFFSET,
    RISCV64_ORIGINAL_TP_OFFSET,
    SCRATCHPAD_FIRST_SPILL_OFFSET,
)


class RISCV64FirstSpillMixin:
    FIRST_SPILL_T0_T1 = ("t0", "t1")

    @classmethod
    def set_first_spill_restore_flag(cls) -> str:
        return f"""
            {cls.load_address("t0", f"scratchpad+{RISCV64_LANDING_RESTORE_FLAG_OFFSET}")}
            li t1, 1
            sd t1, 0(t0)
        """

    @classmethod
    def jump_symbol_with_first_spill_restore(cls, symbol: str, reg: str, already_saved: bool = False) -> str:
        save = "" if already_saved else cls.save_regs_to_first_spill(cls.FIRST_SPILL_T0_T1)
        return f"""
            {save}
            {cls.set_first_spill_restore_flag()}
            {cls.jump_symbol(symbol, reg)}
        """

    @classmethod
    def save_regs_to_first_spill(cls, regs) -> str:
        lines = [
            cls.load_address("tp", f"scratchpad+{SCRATCHPAD_FIRST_SPILL_OFFSET}"),
        ]
        lines.extend(
            f"sd {reg}, {idx * 8}(tp)"
            for idx, reg in enumerate(regs)
        )
        lines.extend([
            cls.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}"),
            "ld tp, 0(tp)",
        ])
        return "\n".join(lines) + "\n"

    @classmethod
    def restore_regs_from_first_spill(cls, regs) -> str:
        lines = [
            cls.load_address("tp", f"scratchpad+{SCRATCHPAD_FIRST_SPILL_OFFSET}"),
        ]
        lines.extend(
            f"ld {reg}, {idx * 8}(tp)"
            for idx, reg in reversed(list(enumerate(regs)))
        )
        lines.extend([
            cls.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}"),
            "ld tp, 0(tp)",
        ])
        return "\n".join(lines) + "\n"
