from abc import ABC, abstractmethod
from uuid import UUID


class ArchitectureCheckpointMixin(ABC):
    def can_insert_restore_point(self, reg_manager, function, block, instruction_idx) -> bool:
        return True

    def checkpoint_patch_uses_live_registers(self) -> bool:
        return getattr(self, "CHECKPOINT_PATCH_USES_LIVE_REGISTERS", self.uses_live_registers)

    def restore_point_patch_uses_live_registers(self) -> bool:
        return getattr(self, "RESTORE_POINT_PATCH_USES_LIVE_REGISTERS", self.uses_live_registers)

    @abstractmethod
    def checkpoint_patch(self, block_uuid: UUID, use_scratch_registers: bool = True):
        pass

    @abstractmethod
    def trampoline_patch(self, block_uuid: UUID, transient_block_uuid: UUID, mnemonic: str, op_str: str,
                         conditional_target_symbol_name: str, non_conditional_target_symbol_name: str):
        pass

    @abstractmethod
    def init_library_patch(self):
        pass

    @abstractmethod
    def fini_library_patch(self):
        pass

    @abstractmethod
    def conditional_restore_point_patch(self, instruction_count: int, use_scratch_registers: bool = True):
        pass

    @abstractmethod
    def unconditional_restore_point_patch(self):
        pass
