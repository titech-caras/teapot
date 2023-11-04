from gtirb_rewriting import Register


def reg_to_dift_reg_id(reg: Register) -> int:
    if reg.name.startswith("xmm"):  # xmm0~xmm31 -> 16~47
        return int(reg.name.replace("xmm", "")) + 16
    else:
        # rax~r15 -> 0~15
        mapping = {k: v for v, k in enumerate([
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"])}
        return mapping[reg.name]