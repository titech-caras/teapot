from capstone import CsInsn


def riscv64_link_register(instruction: CsInsn) -> str:
    """Register a real-form jal/jalr writes, including compressed encodings."""
    return instruction.reg_name(instruction.operands[0].reg)


def riscv64_is_call(instruction: CsInsn) -> bool:
    """A jal/jalr that links; zero destinations are jumps or returns."""
    return instruction.mnemonic in ("jal", "jalr") and riscv64_link_register(instruction) != "zero"
