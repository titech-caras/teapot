import gtirb
from typing import Tuple

from NaHCO3.datacls.copied_section_mapping import CopiedSectionMapping
from NaHCO3.config import SYMBOL_SUFFIX


def copy_section(section: gtirb.Section, name: str) \
        -> Tuple[gtirb.Section, gtirb.Symbol, CopiedSectionMapping]:
    section_copy = gtirb.Section(
        name=name,
        byte_intervals=(),
        flags=section.flags,
        uuid=None,
        module=section.module
    )

    byte_interval = next(iter(section.byte_intervals))

    byte_interval_copy = gtirb.ByteInterval(
        address=byte_interval.size,
        size=None,
        initialized_size=None,
        contents=byte_interval.contents,
        blocks=(),
        symbolic_expressions={},
        uuid=None,
        section=section_copy
    )

    code_block_copy_mapping = {}
    for block in section.code_blocks:
        code_block_copy = gtirb.CodeBlock(
            size=block.size,
            offset=block.offset,
            uuid=None,
            byte_interval=byte_interval_copy
        )
        code_block_copy_mapping[block.uuid] = code_block_copy

    symbol_list = [s for s in section.module.symbols
                   if isinstance(s.referent, gtirb.CodeBlock) and s.referent.section.name == section.name]
    symbol_copy_mapping = {}
    for symbol in symbol_list:
        symbol_copy = gtirb.Symbol(
            name=symbol.name + SYMBOL_SUFFIX,
            uuid=None,
            payload=code_block_copy_mapping[symbol.referent.uuid],
            at_end=False,
            module=section.module
        )
        symbol_copy_mapping[symbol.uuid] = symbol_copy

    section_end_symbol = gtirb.Symbol(
        name=".__section_end" + SYMBOL_SUFFIX,
        uuid=None,
        payload=gtirb.CodeBlock(
            size=0, offset=byte_interval_copy.size, uuid=None,
            byte_interval=byte_interval_copy
        ),
        at_end=False,
        module=section.module
    )

    for pos, symbolic_expression in byte_interval.symbolic_expressions.items():
        if isinstance(symbolic_expression, gtirb.SymAddrAddr):
            symbolic_expression_copy = gtirb.SymAddrAddr(
                scale=symbolic_expression.scale,
                offset=symbolic_expression.offset,
                symbol1=symbol_copy_mapping.get(symbolic_expression.symbol1.uuid, symbolic_expression.symbol1),
                symbol2=symbol_copy_mapping.get(symbolic_expression.symbol1.uuid, symbolic_expression.symbol2),
                attributes=symbolic_expression.attributes
            )
        elif isinstance(symbolic_expression, gtirb.SymAddrConst):
            symbolic_expression_copy = gtirb.SymAddrConst(
                offset=symbolic_expression.offset,
                symbol=symbol_copy_mapping.get(symbolic_expression.symbol.uuid, symbolic_expression.symbol),
                attributes=symbolic_expression.attributes
            )
        else:
            raise TypeError(symbolic_expression)
        byte_interval_copy.symbolic_expressions[pos] = symbolic_expression_copy

    return section_copy, section_end_symbol, CopiedSectionMapping(code_block_copy_mapping, symbol_copy_mapping)
