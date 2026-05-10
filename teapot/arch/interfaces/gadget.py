from abc import ABC, abstractmethod


class ArchitectureGadgetMixin(ABC):
    @abstractmethod
    def coverage_patch(self, idx: int):
        pass

    @abstractmethod
    def report_gadget_snippet(self, gadget_type: str, *args, **kwargs) -> str:
        pass
