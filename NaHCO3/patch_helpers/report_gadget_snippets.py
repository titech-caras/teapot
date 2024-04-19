from gtirb_rewriting import Register
from typing import Optional


from NaHCO3.config import SCRATCHPAD_SIZE


def report_gadget_snippet(gadget_type: str, *,
                          addr_reg: Optional[Register] = None,
                          tag_reg: Optional[Register] = None):
    if tag_reg.name != "rsi":
        load_rsi_rdx_snippet = f"""
            mov rsi, {addr_reg if addr_reg else "0"}
            mov rdx, {tag_reg if tag_reg else "0"}
        """
    else:
        # will get overwritten, so just read it back from scratchpad
        load_rsi_rdx_snippet = f"""
            mov rsi, {addr_reg if addr_reg else "0"}
            mov rdx, scratchpad
        """

    return f"""
        mov old_rsp, rsp
        lea rsp, scratchpad+{SCRATCHPAD_SIZE - 32}
        mov scratchpad, rsi
        mov scratchpad+8, rdi
        mov scratchpad+16, rdx
        {load_rsi_rdx_snippet}
        lea rdi, [rip]
        call report_gadget_{gadget_type}
        mov rdx, scratchpad+16
        mov rdi, scratchpad+8
        mov rsi, scratchpad
        mov rsp, old_rsp
    """
