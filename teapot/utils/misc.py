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
    try:
        return next(payload.references)
    except StopIteration:
        return gtirb.Symbol(name=insert_name, payload=payload, module=module)


def symbol_address(symbol: gtirb.Symbol) -> Optional[int]:
    if symbol.value is not None:
        return symbol.value
    referent = symbol.referent
    if not isinstance(referent, gtirb.ByteBlock) or referent.address is None:
        return None
    return referent.address + (referent.size if symbol.at_end else 0)
