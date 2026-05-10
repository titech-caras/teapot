from abc import ABC, abstractmethod

class ArchitectureDiftMixin(ABC):
    @staticmethod
    def dift_write_registers(write_regs):
        if isinstance(write_regs, (list, tuple, set, frozenset)):
            return list(write_regs)
        return [write_regs]

    @abstractmethod
    def dift_register_id(self, reg) -> int:
        pass

    def dift_ignored_register_names(self):
        return set()

    def dift_should_skip_instruction(self, inst) -> bool:
        return False

    @abstractmethod
    def dift_clears_destination_tags(self, inst) -> bool:
        pass

    @abstractmethod
    def dift_or_reg_tag_snippet(self, tag_reg, tmp_reg, reg):
        pass

    @abstractmethod
    def dift_store_reg_tag_snippet(self, tag_reg, tmp_reg, reg):
        pass

    @abstractmethod
    def dift_queue_reg_tag_snippet(self, tmp_reg, value_reg, tag: int, write_reg):
        pass

    @abstractmethod
    def dift_apply_queued_tag_snippet(self, tag_reg, addr_reg, tmp_reg, done_label: str):
        pass

    @abstractmethod
    def dift_shadow_addr_snippet(self, addr_reg, tmp_reg, xor_mask: int) -> str:
        pass
