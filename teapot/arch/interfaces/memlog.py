from abc import ABC, abstractmethod


class ArchitectureMemlogMixin(ABC):
    @abstractmethod
    def memlog_snippet(self, addr_reg, top_reg, data_reg, access_size: int, **kwargs) -> str:
        pass
