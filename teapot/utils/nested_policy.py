"""Outcome stubs for hashed checkpoints, before fixed registers are borrowed."""
from teapot.configs.runtime import CHECKPOINT_TARGET_OUTCOME_OFFSET, CHECKPOINT_TARGET_SITE_INDEX_OFFSET, SYMBOL_SUFFIX


def checkpoint_branch(arch, instruction):
    mnemonic = instruction.mnemonic
    if arch.name == "x64" and mnemonic in ("loop", "loope", "loopne") and instruction.addr_size == 4:
        mnemonic = "addr32 " + mnemonic
    return mnemonic, instruction.op_str


def outcome_stubs(arch, setup, entry_jump, branch, site_index):
    # Evaluate before setup: cbz/tbz and RV branches can name either of the
    # fixed scratch registers, or a spare used to hold one of them. Each stub
    # then uses exactly the existing patch's saves and scratch registers.
    taken = f".L__checkpoint_taken{SYMBOL_SUFFIX}"
    mnemonic, operands = branch
    x64_conditions = {"o", "no", "b", "nae", "c", "ae", "nb", "nc", "e", "z", "ne", "nz",
                      "be", "na", "a", "nbe", "s", "ns", "p", "pe", "np", "po", "l", "nge",
                      "ge", "nl", "le", "ng", "g", "nle"}
    arm_conditions = {"eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
                      "hi", "ls", "ge", "lt", "gt", "le"}
    if arch.name == "x64" and mnemonic.startswith("j") and mnemonic[1:] in x64_conditions:
        return setup + f"""
            mov qword ptr [checkpoint_target_metadata+{CHECKPOINT_TARGET_SITE_INDEX_OFFSET}], {site_index}
            set{mnemonic[1:]} byte ptr [checkpoint_target_metadata+{CHECKPOINT_TARGET_OUTCOME_OFFSET}]
            {entry_jump}
        """
    if arch.name == "aarch64" and mnemonic.startswith("b.") and mnemonic[2:] in arm_conditions:
        index = f"movz x16, #{site_index & 0xffff}\n"
        for shift in (16, 32, 48):
            if site_index >> shift:
                index += f"movk x16, #{(site_index >> shift) & 0xffff}, lsl #{shift}\n"
        return setup + index + f"""
            str x16, [x17, #{CHECKPOINT_TARGET_SITE_INDEX_OFFSET}]
            cset w16, {mnemonic[2:]}
            strb w16, [x17, #{CHECKPOINT_TARGET_OUTCOME_OFFSET}]
            {entry_jump}
        """
    prefix = operands.rsplit(",", 1)[0] + ", " if "," in operands else ""
    pieces = [f"{mnemonic} {prefix}{taken}\n"]
    for outcome in (0, 1):
        if outcome:
            pieces.append(f"{taken}:\n")
        if mnemonic.split()[-1] in ("loop", "loope", "loopne"):
            # LOOP's probe has decremented the counter. Undo without changing
            # flags, so the architectural branch/trampoline decrements once.
            count = "ecx" if mnemonic.startswith("addr32 ") else "rcx"
            pieces.append(f"lea {count}, [rcx+1]\n")
        pieces.append(setup)
        if arch.name == "x64":
            pieces.append(f"""
                mov qword ptr [checkpoint_target_metadata+{CHECKPOINT_TARGET_SITE_INDEX_OFFSET}], {site_index}
                mov byte ptr [checkpoint_target_metadata+{CHECKPOINT_TARGET_OUTCOME_OFFSET}], {outcome}
            """)
        elif arch.name == "aarch64":
            pieces.append(f"movz x16, #{site_index & 0xffff}\n")
            for shift in (16, 32, 48):
                if site_index >> shift:
                    pieces.append(f"movk x16, #{(site_index >> shift) & 0xffff}, lsl #{shift}\n")
            pieces.append(f"""
                str x16, [x17, #{CHECKPOINT_TARGET_SITE_INDEX_OFFSET}]
                mov w16, #{outcome}
                strb w16, [x17, #{CHECKPOINT_TARGET_OUTCOME_OFFSET}]
            """)
        else:
            pieces.append(f"""
                li t0, {site_index}
                sd t0, {CHECKPOINT_TARGET_SITE_INDEX_OFFSET}(t1)
                li t0, {outcome}
                sb t0, {CHECKPOINT_TARGET_OUTCOME_OFFSET}(t1)
            """)
        pieces.append(entry_jump + "\n")
    return "\n".join(pieces)
