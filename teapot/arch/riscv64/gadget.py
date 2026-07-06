from itertools import count

from teapot.configs.runtime import SCRATCHPAD_SIZE, SYMBOL_SUFFIX


_REPORT_LABEL_COUNTER = count()
_REPORT_CALLER_SAVED_GPRS = (
    1,  # ra
    5, 6, 7,  # t0-t2
    10, 11, 12, 13, 14, 15, 16, 17,  # a0-a7
    28, 29, 30, 31,  # t3-t6
)


class RISCV64GadgetPatchesMixin:
    def coverage_patch(self, idx: int):
        @self.constraints(scratch_registers=2)
        def patch(ctx):
            top_addr_reg, top_reg = ctx.scratch_registers[:2]
            return f"""
                {self.load_address(top_addr_reg, "guard_list_top")}
                ld {top_reg}, 0({top_addr_reg})
                li {top_addr_reg}, {idx}
                sw {top_addr_reg}, 0({top_reg})
                addi {top_reg}, {top_reg}, 4
                {self.load_address(top_addr_reg, "guard_list_top")}
                sd {top_reg}, 0({top_addr_reg})
            """

        return patch

    def report_gadget_snippet(self, gadget_type: str, addr_reg, tag_reg, stack_reg, *,
                              save_float_state: bool = False) -> str:
        saves = "\n".join(f"sd x{i}, {i * 8}(sp)" for i in _REPORT_CALLER_SAVED_GPRS)
        restores = "\n".join(f"ld x{i}, {i * 8}(sp)" for i in _REPORT_CALLER_SAVED_GPRS)
        float_base = 272
        float_saves = ""
        float_restores = ""
        fcsr_save = ""
        fcsr_restore = ""
        if save_float_state:
            fcsr_save = "frcsr a2\nsd a2, 264(sp)"
            fcsr_restore = "ld a2, 264(sp)\nfscsr a2"
            float_saves = "\n".join(f"fsd f{i}, {float_base + i * 8}(sp)" for i in range(32))
            float_restores = "\n".join(f"fld f{i}, {float_base + i * 8}(sp)" for i in range(32))
        frame_size = float_base + (256 if save_float_state else 0)
        frame_symbol = f"scratchpad+{SCRATCHPAD_SIZE - frame_size}"
        report_call_label = f".L__report_gadget_call_{next(_REPORT_LABEL_COUNTER)}{SYMBOL_SUFFIX}"
        return f"""
            {self.load_address(stack_reg, frame_symbol)}
            sd sp, 16({stack_reg})
            mv sp, {stack_reg}
            {saves}
            sd {addr_reg}, 0(sp)
            andi a2, {tag_reg}, 255
            sd a2, 256(sp)
            {fcsr_save}
            {float_saves}
            {self.load_address("a0", report_call_label)}
            ld a1, 0(sp)
            ld a2, 256(sp)
            {self.load_address("ra", f"report_gadget_{gadget_type}")}
        {report_call_label}:
            jalr ra
            {float_restores}
            {fcsr_restore}
            {restores}
            ld sp, 16(sp)
        """
