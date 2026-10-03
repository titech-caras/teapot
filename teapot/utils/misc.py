import gtirb
from uuid import UUID
from typing import List, Tuple, Iterable, Optional

from teapot.configs.runtime import SYMBOL_SUFFIX


def distinguish_edges(edges: Iterable[gtirb.Edge]) -> Tuple[List[gtirb.Edge], List[gtirb.Edge]]:
    edges_list = list(edges)
    return [e for e in edges_list if e.label.type != gtirb.cfg.Edge.Type.Fallthrough], \
            [e for e in edges_list if e.label.type == gtirb.cfg.Edge.Type.Fallthrough]


def conditional_branch_edge(block: gtirb.CodeBlock) -> Optional[gtirb.Edge]:
    """The block's first non-fallthrough edge if it is a conditional branch, else None."""
    non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
    if (non_fallthrough_edges and non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
            non_fallthrough_edges[0].label.conditional):
        return non_fallthrough_edges[0]
    return None


def generate_distinct_label_name(prefix: str, uuid: UUID):
    return prefix + "_" + str(uuid).replace("-", "_") + SYMBOL_SUFFIX


def get_or_insert_symbol(insert_name: str, payload: gtirb.CfgNode, module: gtirb.Module) -> gtirb.Symbol:
    """A symbol naming the start of payload: an existing one, else a new one called insert_name.

    Never an at_end symbol, which names the address after a nonempty block.
    The block's symbols are a set hashed by identity: take the same one in
    every run.
    """
    starts = [symbol for symbol in payload.references if not symbol.at_end]
    if starts:
        return min(starts, key=lambda symbol: (symbol.name, symbol.uuid.bytes))
    return gtirb.Symbol(name=insert_name, payload=payload, module=module)


def new_label_name(module: gtirb.Module, prefix: str, block: gtirb.ByteBlock,
                   address: Optional[int] = None) -> str:
    """The name of a new label at block (or at address): from the address, not the block's UUID.

    Blocks the rewriter splits off get random UUIDs; addresses follow the
    deterministic layout (teapot/utils/layout.py). A name in use gets a
    numbered suffix.
    """
    if address is None:
        address = block.address
    if address is None:
        return generate_distinct_label_name(prefix, block.uuid)
    base = f"{prefix}_{address:x}"
    name, serial = base + SYMBOL_SUFFIX, 1
    while next(module.symbols_named(name), None) is not None:
        serial += 1
        name = f"{base}_{serial}{SYMBOL_SUFFIX}"
    return name


def symbol_address(symbol: gtirb.Symbol) -> Optional[int]:
    if symbol.value is not None:
        return symbol.value
    referent = symbol.referent
    if not isinstance(referent, gtirb.ByteBlock) or referent.address is None:
        return None
    return referent.address + (referent.size if symbol.at_end else 0)
