from abc import ABC, abstractmethod


class ArchitectureAsanMixin(ABC):
    @abstractmethod
    def asan_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, **kwargs) -> str:
        pass

    @abstractmethod
    def asan_stack_poison_snippet(self, addr_reg, value_reg, top_reg, *, poison: bool,
                                  shadow_offset: int, insert_memlog: bool, tag_storage: str = "shadow") -> str:
        pass

    @abstractmethod
    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int,
                         tag_storage: str = "shadow"):
        pass
