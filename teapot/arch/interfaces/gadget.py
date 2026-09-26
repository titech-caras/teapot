from abc import ABC, abstractmethod


class ArchitectureGadgetMixin(ABC):
    @abstractmethod
    def coverage_patch(self, idx: int, *, index_base_symbol=None):
        pass

    @abstractmethod
    def report_gadget_snippet(self, gadget_type: str, *args, **kwargs) -> str:
        pass
