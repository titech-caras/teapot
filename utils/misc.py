import gtirb
from typing import List, Tuple, Iterable


def distinguish_edges(edges: Iterable[gtirb.Edge]) -> Tuple[List[gtirb.Edge], List[gtirb.Edge]]:
    edges_list = list(edges)
    return [e for e in edges_list if e.label.type != gtirb.cfg.Edge.Type.Fallthrough], \
            [e for e in edges_list if e.label.type == gtirb.cfg.Edge.Type.Fallthrough]
