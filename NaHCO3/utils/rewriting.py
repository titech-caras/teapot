import gtirb
from gtirb_capstone import RewritingContext
from gtirb_capstone.x86 import operand_symbolic_expression, operand_to_str
from typing import Union, Optional
from capstone_gt import CsInsn


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
