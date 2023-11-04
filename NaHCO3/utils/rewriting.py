import gtirb
from gtirb_capstone import RewritingContext
from gtirb_capstone.x86 import operand_symbolic_expression, operand_to_str
from typing import Union, Optional
from capstone_gt import CsInsn, CS_AC_WRITE
from capstone_gt.x86 import X86Op
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression


def initialize_empty_code_block(byte_interval: gtirb.ByteInterval):
    byte_interval.contents += bytes([0x90])  # nop
    byte_interval.size += 1

    block = gtirb.CodeBlock(
        size=1,
        offset=byte_interval.size - 1,
        byte_interval=byte_interval
    )
    return block


def reconstruct_instruction_str(block: gtirb.CodeBlock, inst: CsInsn):
    operand_strs = []
    for op in inst.operands:
        try:
            operand_strs.append(operand_to_str(inst, op, operand_symbolic_expression(block, inst, op)))
        except NotImplementedError:
            operand_strs.append(operand_to_str(inst, op, None))

    return f"{inst.mnemonic} {', '.join(operand_strs)}"


def mem_access_to_symbolic_str(block: gtirb.CodeBlock, inst: CsInsn, mem_op: X86Op):
    symexp = operand_symbolic_expression(block, inst, mem_op)
    try:
        mem_operand_str = mem_access_to_str(inst, mem_op.mem, symexp)
    except NotImplementedError:
        print(f"Warning: unsupported symexp at {inst}")
        mem_operand_str = mem_access_to_str(inst, mem_op.mem, None)

    return mem_operand_str


def get_cmov_conditional(inst: CsInsn) -> Optional[str]:
    return inst.mnemonic[4:] if inst.mnemonic.startswith("cmov") else None


def mem_operand_is_write_capstone_workaround(inst: CsInsn, mem_op: X86Op):
    # Workaround for capstone: capstone doesn't correctly identify accesses for
    # a lot of SSE/AVX instructions, so we conservatively identify all first
    # SSE/AVX memory operands as being written.
    return (mem_op.access & CS_AC_WRITE or
            (inst.operands[0] == mem_op and inst.operands[0].size > 8))
