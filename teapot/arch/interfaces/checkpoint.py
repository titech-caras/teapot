from abc import ABC, abstractmethod
from uuid import UUID


class ArchitectureCheckpointMixin(ABC):
    CHECKPOINT_FIXED_REGISTERS = ()

    def can_insert_restore_point(self, live_registers) -> bool:
        return True

    def static_instruction_cost(self, instruction) -> int:
        return 1

    def checkpoint_spare_registers(self, abi, live_registers):
        fixed_registers = set(self.CHECKPOINT_FIXED_REGISTERS)
        return tuple(
            reg.name for reg in abi._scratch_registers()
            if reg.name not in fixed_registers and reg not in live_registers
        )[:len(self.CHECKPOINT_FIXED_REGISTERS)]

    @abstractmethod
    def checkpoint_patch(self, block_uuid: UUID, spare_registers=()):
        pass

    @abstractmethod
    def trampoline_patch(self, block_uuid: UUID, transient_block_uuid: UUID, mnemonic: str, op_str: str,
                         conditional_target_symbol_name: str, non_conditional_target_symbol_name: str,
                         checkpoint_spare_registers=()):
        pass

    @abstractmethod
    def init_library_patch(self):
        pass

    @abstractmethod
    def fini_library_patch(self):
        pass

    @abstractmethod
    def conditional_restore_point_patch(self, instruction_count: int):
        pass

    @abstractmethod
    def unconditional_restore_point_patch(self):
        pass
