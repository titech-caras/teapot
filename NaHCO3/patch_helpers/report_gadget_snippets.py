from gtirb_rewriting import Register
from typing import Optional


from NaHCO3.config import SCRATCHPAD_SIZE


def report_gadget_snippet(addr_reg: Optional[Register], gadget_type: str):
    return f"""
        mov old_rsp, rsp
        lea rsp, scratchpad+{SCRATCHPAD_SIZE - 16}
        mov scratchpad, rsi
        mov scratchpad+8, rdi
        mov rsi, {addr_reg if addr_reg else "0"}
        lea rdi, [rip]
        call report_gadget_{gadget_type}
        mov rdi, scratchpad+8
        mov rsi, scratchpad
        mov rsp, old_rsp
    """