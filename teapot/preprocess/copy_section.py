import uuid

import gtirb
import copy
from typing import Tuple

from teapot.datacls.copied_section_mapping import CopiedSectionMapping
from teapot.configs.runtime import SYMBOL_SUFFIX


SECTION_PROPERTIES_AUX_TYPE = "mapping<UUID,tuple<uint64_t,uint64_t>>"
SHT_PROGBITS = 1
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def set_elf_section_properties(section: gtirb.Section, sh_type: int, sh_flags: int):
    if section.module is None:
        return

    if "sectionProperties" not in section.module.aux_data:
        section.module.aux_data["sectionProperties"] = gtirb.AuxData({}, SECTION_PROPERTIES_AUX_TYPE)

    section.module.aux_data["sectionProperties"].data[section] = (sh_type, sh_flags)


def copy_elf_section_properties(source: gtirb.Section, target: gtirb.Section):
    if source.module is None or "sectionProperties" not in source.module.aux_data:
        return

    source_properties = source.module.aux_data["sectionProperties"].data.get(source)
    if source_properties is not None:
        set_elf_section_properties(target, *source_properties)


def create_section_bounds(section: gtirb.Section, name: str) -> Tuple[gtirb.Symbol, gtirb.Symbol]:
    byte_interval = next(iter(section.byte_intervals))
    start_symbol = gtirb.Symbol(
        name=f".__{name}_start" + SYMBOL_SUFFIX,
        uuid=None,
        payload=gtirb.CodeBlock(
            size=0, offset=0, uuid=None,
            byte_interval=byte_interval
        ),
        at_end=False,
        module=section.module
    )
    end_symbol = gtirb.Symbol(
        name=f".__{name}_end" + SYMBOL_SUFFIX,
        uuid=None,
        payload=gtirb.CodeBlock(
            size=0, offset=byte_interval.size, uuid=None,
            byte_interval=byte_interval
        ),
        at_end=False,
        module=section.module
    )
    return start_symbol, end_symbol


_EXCEPTION_METADATA_SECTION_PREFIXES = (
    ".ARM.exidx",
    ".ARM.extab",
    ".eh_frame",
    ".gcc_except_table",
)


def _external_relative_jump_table_base_symbol_uuids(module: gtirb.Module,
                                                     copied_section: gtirb.Section):
    base_symbol_uuids = set()
    for section in module.sections:
        if (section is copied_section or
                section.name.startswith(_EXCEPTION_METADATA_SECTION_PREFIXES)):
            continue
        for byte_interval in section.byte_intervals:
            for symbolic_expression in byte_interval.symbolic_expressions.values():
                if isinstance(symbolic_expression, gtirb.SymAddrAddr):
                    base_symbol_uuids.add(symbolic_expression.symbol2.uuid)
    return base_symbol_uuids


def copy_section(section: gtirb.Section, name: str) \
        -> Tuple[gtirb.Section, gtirb.Symbol, gtirb.Symbol, CopiedSectionMapping]:
    section_copy = gtirb.Section(
        name=name,
        byte_intervals=(),
        flags=section.flags,
        uuid=None,
        module=section.module
    )
    copy_elf_section_properties(section, section_copy)

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

    section_start_symbol = gtirb.Symbol(
        name=".__transient_start" + SYMBOL_SUFFIX,
        uuid=None,
        payload=gtirb.CodeBlock(
            size=0, offset=0, uuid=None,
            byte_interval=byte_interval_copy
        ),
        at_end=False,
        module=section.module
    )

    section_end_symbol = gtirb.Symbol(
        name=".__transient_end" + SYMBOL_SUFFIX,
        uuid=None,
        payload=gtirb.CodeBlock(
            size=0, offset=byte_interval_copy.size, uuid=None,
            byte_interval=byte_interval_copy
        ),
        at_end=False,
        module=section.module
    )

    external_relative_jump_table_base_symbol_uuids = \
        _external_relative_jump_table_base_symbol_uuids(section.module, section)

    def copied_symbol(symbol):
        return symbol_copy_mapping.get(symbol.uuid, symbol)

    def copied_addr_const_symbol(symbol):
        # Keep non-copied relative jump-table bases anchored in the original
        # section.  The computed address then reaches the text marker/bouncer
        # instead of becoming a stale transient-relative offset after inserted
        # instrumentation shifts the copied code.
        if symbol.uuid in external_relative_jump_table_base_symbol_uuids:
            return symbol
        return copied_symbol(symbol)

    for pos, symbolic_expression in byte_interval.symbolic_expressions.items():
        if isinstance(symbolic_expression, gtirb.SymAddrAddr):
            symbolic_expression_copy = gtirb.SymAddrAddr(
                scale=symbolic_expression.scale,
                offset=symbolic_expression.offset,
                symbol1=copied_symbol(symbolic_expression.symbol1),
                symbol2=copied_symbol(symbolic_expression.symbol2),
                attributes=symbolic_expression.attributes
            )
        elif isinstance(symbolic_expression, gtirb.SymAddrConst):
            symbolic_expression_copy = gtirb.SymAddrConst(
                offset=symbolic_expression.offset,
                symbol=copied_addr_const_symbol(symbolic_expression.symbol),
                attributes=symbolic_expression.attributes
            )
        else:
            raise TypeError(symbolic_expression)
        byte_interval_copy.symbolic_expressions[pos] = symbolic_expression_copy

    new_edges = []
    for edge in section.ir.cfg:
        if isinstance(edge.source, gtirb.CodeBlock) and edge.source.byte_interval.section.name == section.name:
            edge_copy = gtirb.Edge(
                code_block_copy_mapping[edge.source.uuid],
                code_block_copy_mapping.get(edge.target.uuid, edge.target),
                copy.copy(edge.label)
            )
            new_edges.append(edge_copy)

    section.ir.cfg.update(new_edges)

    new_functions = []
    for fn_uuid, entry_blocks in section.module.aux_data['functionEntries'].data.items():
        if next(iter(entry_blocks)).section.name != section.name:
            continue

        new_entry_blocks = set([code_block_copy_mapping[b.uuid] for b in entry_blocks])
        new_blocks = set([code_block_copy_mapping[b.uuid]
                          for b in section.module.aux_data["functionBlocks"].data[fn_uuid]])
        new_name = symbol_copy_mapping[section.module.aux_data["functionNames"].data.get(fn_uuid).uuid]

        new_functions.append((fn_uuid, new_entry_blocks, new_blocks, new_name))

    functions_uuid_mapping = {}
    for old_fn_uuid, new_entry_blocks, new_blocks, new_name in new_functions:
        fn_uuid = uuid.uuid4()
        functions_uuid_mapping[old_fn_uuid] = fn_uuid
        section.module.aux_data['functionEntries'].data[fn_uuid] = new_entry_blocks
        section.module.aux_data["functionBlocks"].data[fn_uuid] = new_blocks
        section.module.aux_data["functionNames"].data[fn_uuid] = new_name

    return (section_copy, section_start_symbol, section_end_symbol,
            CopiedSectionMapping(code_block_copy_mapping, symbol_copy_mapping, functions_uuid_mapping))
