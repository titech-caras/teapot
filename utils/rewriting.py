import gtirb
from gtirb_capstone import RewritingContext
from typing import Union, Optional


def initialize_empty_code_block(byte_interval: gtirb.ByteInterval):
    byte_interval.contents += bytes([0x90])  # nop
    byte_interval.size += 1

    block = gtirb.CodeBlock(
        size=1,
        offset=byte_interval.size - 1,
        byte_interval=byte_interval
    )
    return block


def insert_instruction_with_symbol(
        rewriting_context: RewritingContext,
        block: gtirb.CodeBlock,
        code: Union[list, bytes],
        symbol: gtirb.Symbol,
        insertion_offset: Optional[int] = None,
        symbol_offset_from_back: int = 4):
    if insertion_offset is None:  # Default to inserting at end
        insertion_offset = block.size
    rewriting_context.modify_block_insert(block.module, block, bytes(code), insertion_offset)
    block.byte_interval.symbolic_expressions[block.offset + insertion_offset + len(code) - symbol_offset_from_back] = \
        gtirb.SymAddrConst(offset=0, symbol=symbol)

    return len(code)