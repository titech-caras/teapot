
from teapot.configs.runtime import (
    AARCH64_REPORT_ACCESS_ADDR,
    AARCH64_REPORT_LINK_SAVE,
    AARCH64_REPORT_STATE_OFFSET,
    AARCH64_REPORT_TAG,
    GUARD_ENTRY_WIDTH,
    SYMBOL_SUFFIX,
)


class AArch64GadgetPatchesMixin:
    def coverage_patch(self, idx: int, *, index_base_symbol=None):
        if type(idx) is not int or not 0 <= idx < 2**32:
            raise ValueError('coverage index must fit the 32-bit guard ABI')
        @self.constraints(scratch_registers=2)
        def patch(ctx):
            top_addr_reg, top_reg = ctx.scratch_registers[:2]
            index_reg = self.w_reg(top_addr_reg)
            if index_base_symbol is None:
                index = self.mov_w_imm32(index_reg, idx)
            else:
                # Absolute linker-defined index, not an address. A skipped
                # literal uses checked ABS32, supported by the pinned rewriter.
                expression = f'{index_base_symbol.name}+{idx}'
                index = f'ldr {index_reg}, 1f\nb 2f\n1:\n.word {expression}\n2:'
            return f"""
                {self.load_address(top_addr_reg, "guard_list_top")}
                ldr {top_reg}, [{top_addr_reg}]
                {index}
                str {self.w_reg(top_addr_reg)}, [{top_reg}]
                add {top_reg}, {top_reg}, #{GUARD_ENTRY_WIDTH}
                {self.load_address(top_addr_reg, "guard_list_top")}
                str {top_reg}, [{top_addr_reg}]
            """

        return patch

    def report_gadget_snippet(self, gadget_type: str, addr_reg, tag_reg, stack_reg, temp_reg) -> str:
        report_call_label = f".L__report_gadget_call_{self.next_label_number('report')}{SYMBOL_SUFFIX}"
        args_symbol = f"scratchpad+{AARCH64_REPORT_STATE_OFFSET}"

        # Reporting replaces the labeled instruction with one NOP. Materialize
        # the target first so branch relaxation cannot widen that patch site.
        # The call site goes to the block's start (AARCH64_REPORT_GADGET_ADDR).
        return f"""
            {self.load_address(stack_reg, args_symbol)}
            str {addr_reg}, [{stack_reg}, #{AARCH64_REPORT_ACCESS_ADDR}]
            str {tag_reg}, [{stack_reg}, #{AARCH64_REPORT_TAG}]
            str x30, [{stack_reg}, #{AARCH64_REPORT_LINK_SAVE}]
            {self.load_address(temp_reg, report_call_label)}
            str {temp_reg}, [{stack_reg}]
            {self.load_address(temp_reg, f"report_gadget_aarch64_preserve_{gadget_type}")}
        {report_call_label}:
            blr {temp_reg}
            {self.load_address(stack_reg, args_symbol)}
            ldr x30, [{stack_reg}, #{AARCH64_REPORT_LINK_SAVE}]
        """
