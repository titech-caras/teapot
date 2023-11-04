from gtirb_rewriting import Register


def memlog_snippet(addr_reg: Register, access_size: int, *,
                   r1: Register, r2: Register, no_clobber_addr: bool = False):
    asm = f"mov {r1}, [memory_history_top]\n"

    if access_size <= 8:
        asm += f"""
            mov {r2}, [{addr_reg}]
            mov [{r1}], {addr_reg}
            mov [{r1} + 8], {r2}
            add qword ptr [memory_history_top], 16 
        """
    else:
        assert not no_clobber_addr
        for i in range(0, access_size, 8):
            asm += f"""
                mov {r2}, [{addr_reg}]
                mov [{r1}], {addr_reg}
                mov [{r1} + 8], {r2}
                lea {r1}, [{r1} + 16]
                lea {addr_reg}, [{addr_reg} + 8]
            """

        asm += f"mov memory_history_top, {r1}\n"

    return asm
