from dataclasses import dataclass
from typing import Optional

from gtirb_rewriting.assembly import Register


@dataclass(frozen=True)
class StackAccess:
    base: Optional[Register]
    displacement: Optional[int]
    size: int
    return_offset: Optional[int] = None
