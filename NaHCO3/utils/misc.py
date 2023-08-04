import gtirb
from uuid import UUID
from typing import List, Tuple, Iterable

from NaHCO3.config import SYMBOL_SUFFIX


def distinguish_edges(edges: Iterable[gtirb.Edge]) -> Tuple[List[gtirb.Edge], List[gtirb.Edge]]:
    edges_list = list(edges)
    return [e for e in edges_list if e.label.type != gtirb.cfg.Edge.Type.Fallthrough], \
            [e for e in edges_list if e.label.type == gtirb.cfg.Edge.Type.Fallthrough]


def generate_distinct_label_name(prefix: str, uuid: UUID):
    return prefix + "_" + str(uuid).replace("-", "_") + SYMBOL_SUFFIX

