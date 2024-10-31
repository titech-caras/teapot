from dataclasses import dataclass
from typing import Dict
from uuid import UUID

import gtirb


@dataclass
class CopiedSectionMapping:
    code_blocks_map: Dict[UUID, gtirb.CodeBlock]
    symbols_map: Dict[UUID, gtirb.Symbol]
    function_uuids_map: Dict[UUID, UUID]
