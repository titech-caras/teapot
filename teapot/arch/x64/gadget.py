from typing import Optional

from gtirb_rewriting import Register

from teapot.configs.runtime import SCRATCHPAD_SIZE


class X64GadgetPatchesMixin:
    def coverage_patch(self, idx: int):
        @self.constraints(scratch_registers=1)
        def patch(ctx):
            r1, = ctx.scratch_registers
            return f"""
                mov {r1}, guard_list_top
                mov dword ptr [{r1}], {idx}
                lea {r1}, [{r1} + 4]
                mov guard_list_top, {r1}
            """

        return patch

    @staticmethod
    def report_gadget_snippet(gadget_type: str, *,
                              addr_reg: Optional[Register] = None,
                              tag_reg: Optional[Register] = None):
        if tag_reg.name != "rsi":
            load_rsi_rdx_snippet = f"""
                mov rsi, {addr_reg if addr_reg else "0"}
                mov rdx, {tag_reg if tag_reg else "0"}
            """
        else:
            load_rsi_rdx_snippet = f"""
                mov rsi, {addr_reg if addr_reg else "0"}
                mov rdx, scratchpad
            """

        return f"""
            mov old_rsp, rsp
            lea rsp, scratchpad+{SCRATCHPAD_SIZE - 32}
            mov scratchpad+24, rax
            mov scratchpad+32, rcx
            mov scratchpad+40, r8
            mov scratchpad+48, r9
            mov scratchpad+56, r10
            mov scratchpad, rsi
            mov scratchpad+8, rdi
            mov scratchpad+16, rdx
            {load_rsi_rdx_snippet}
            lea rdi, [rip]
            call report_gadget_{gadget_type}
            mov rdx, scratchpad+16
            mov rdi, scratchpad+8
            mov rsi, scratchpad
            mov r10, scratchpad+56
            mov r9, scratchpad+48
            mov r8, scratchpad+40
            mov rcx, scratchpad+32
            mov rax, scratchpad+24
            mov rsp, old_rsp
        """
