from itertools import count

from teapot.configs.runtime import SCRATCHPAD_SIZE, SYMBOL_SUFFIX
_REPORT_LABEL_COUNTER = count()


class AArch64GadgetPatchesMixin:
    def coverage_patch(self, idx: int):
        @self.constraints(scratch_registers=2)
        def patch(ctx):
            top_addr_reg, top_reg = ctx.scratch_registers[:2]
            return f"""
                {self.load_address(top_addr_reg, "guard_list_top")}
                ldr {top_reg}, [{top_addr_reg}]
                {self.mov_w_imm32(self.w_reg(top_addr_reg), idx)}
                str {self.w_reg(top_addr_reg)}, [{top_reg}]
                add {top_reg}, {top_reg}, #4
                {self.load_address(top_addr_reg, "guard_list_top")}
                str {top_reg}, [{top_addr_reg}]
            """

        return patch

    def report_gadget_snippet(self, gadget_type: str, addr_reg, tag_reg, stack_reg, temp_reg) -> str:
        report_call_label = f".L__report_gadget_call_{next(_REPORT_LABEL_COUNTER)}{SYMBOL_SUFFIX}"
        args_symbol = f"scratchpad+{SCRATCHPAD_SIZE - 512}"

        return f"""
            {self.load_address(stack_reg, args_symbol)}
            str {addr_reg}, [{stack_reg}, #8]
            str {tag_reg}, [{stack_reg}, #16]
            str x30, [{stack_reg}, #24]
            {self.load_address(temp_reg, report_call_label)}
            str {temp_reg}, [{stack_reg}]
        {report_call_label}:
            bl report_gadget_aarch64_preserve_{gadget_type}
            {self.load_address(stack_reg, args_symbol)}
            ldr x30, [{stack_reg}, #24]
        """
