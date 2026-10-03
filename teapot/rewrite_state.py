"""One rewrite's shared results, owned by ``TeapotPipeline.run``.

Passes that hand results to later passes write them here instead of onto the
Architecture object, which keeps only ISA semantics and templates. Each result
is a Product with three states, so a consumer can tell a pass that ran and
found nothing from one that has not run (an error) or that an option turned
off (nothing to use).
"""
from dataclasses import dataclass, field
from typing import FrozenSet, Generic, TypeVar

T = TypeVar("T")


class ProductNotReady(RuntimeError):
    """A pass needs a result whose producing pass has not run."""


class Product(Generic[T]):
    _NOT_RUN, _DISABLED, _DONE = "not run", "disabled", "done"

    def __init__(self, name: str, producer: str):
        self.name, self.producer = name, producer
        self._state, self._value, self._reason = self._NOT_RUN, None, None

    def set(self, value: T) -> T:
        if self._state != self._NOT_RUN:
            raise RuntimeError(f"{self.name} was already {self._state}")
        self._state, self._value = self._DONE, value
        return value

    def disable(self, reason: str):
        if self._state != self._NOT_RUN:
            raise RuntimeError(f"{self.name} was already {self._state}")
        self._state, self._reason = self._DISABLED, reason

    @property
    def ran(self) -> bool:
        return self._state == self._DONE

    @property
    def disabled(self) -> bool:
        return self._state == self._DISABLED

    def require(self, consumer: str) -> T:
        """The result; an error if the producer was disabled or has not run."""
        if self._state == self._DONE:
            return self._value
        if self._state == self._DISABLED:
            raise ProductNotReady(f"{consumer} needs {self.name}, which {self._reason} turned off")
        raise ProductNotReady(f"{consumer} needs {self.name} from {self.producer}, which has not run")

    def get(self, consumer: str, *, disabled: T) -> T:
        """The result, or ``disabled`` when an option turned the producer off; an error if it has not run."""
        if self._state == self._DISABLED:
            return disabled
        return self.require(consumer)


@dataclass(frozen=True)
class TransientPads:
    # The copy blocks the pad pass gave the marker pair, and every sized copy
    # block at that time (the anchor search must not cross into another one).
    padded_blocks: FrozenSet
    copy_blocks: FrozenSet


@dataclass
class RewriteState:
    pads: Product = field(default_factory=lambda: Product("the transient pads", "the transient pad pass"))
    direct_entry_pads: Product = field(default_factory=lambda: Product(
        "the direct-entry pads", "the text indirect-branch transform"))
    text_targets: Product = field(default_factory=lambda: Product(
        "the marked text targets", "the text indirect-branch transform"))
    # Normal-text blocks to pad beyond the lift's indirect edges, and on x64 the
    # blocks whose flags are dead on entry (their pads need no flag save).
    potential_targets: Product = field(default_factory=lambda: Product(
        "the potential indirect targets", "the potential-target search"))
    flags_dead_blocks: Product = field(default_factory=lambda: Product(
        "the flags-dead blocks", "the potential-target search"))
