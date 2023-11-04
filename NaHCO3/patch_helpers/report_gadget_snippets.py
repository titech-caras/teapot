from gtirb_rewriting import Register


from NaHCO3.config import SCRATCHPAD_SIZE


def report_gadget_snippet(addr_reg: Register, gadget_type: str):
    return f"""
        mov old_rsp, rsp
        lea rsp, scratchpad+{SCRATCHPAD_SIZE - 16}
        mov scratchpad, rsi
        mov scratchpad+8, rdi
        mov rsi, {addr_reg}
        lea rdi, [rip]
        call report_gadget_{gadget_type}
        mov rdi, scratchpad+8
        mov rsi, scratchpad
        mov rsp, old_rsp
    """