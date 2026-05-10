from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

import gtirb


class ArchitectureControlFlowMixin(ABC):
    @abstractmethod
    def indirect_branch_target_patch(self, target_symbol: gtirb.Symbol):
        pass

    def indirect_transform_uses_live_registers(self) -> bool:
        return False

    def indirect_transform_landing_pad_label(self, block_uuid: UUID):
        return None

    def indirect_transform_target_patch(self, target_symbol: gtirb.Symbol, *,
                                       reg_manager=None, function=None, block=None, instruction_idx: int = 0,
                                       landing_target_uuid=None, landing_pad_targets=None,
                                       ensure_landing_pad_symbol=None):
        return self.indirect_branch_target_patch(target_symbol)

    def trampoline_target_names(self, fallthrough_target_symbol_name: str, branch_target_symbol_name: str, *,
                                fallthrough_target_uuid: UUID, branch_target_uuid: UUID,
                                landing_pad_targets=None):
        return fallthrough_target_symbol_name, branch_target_symbol_name, {}

    def indirect_branch_operand(self, edge_type, last_inst, block: Optional[gtirb.CodeBlock] = None) -> Optional[str]:
        return None

    def indirect_branch_check_allows_allocator_scratch(self) -> bool:
        return False

    @abstractmethod
    def indirect_branch_check_patch(self, operand_str: str, transient_start_symbol: gtirb.Symbol,
                                    transient_end_symbol: gtirb.Symbol, text_start_symbol: gtirb.Symbol,
                                    text_end_symbol: gtirb.Symbol, use_scratch_registers: bool = True,
                                    reads_registers=None):
        pass

    def instruction_must_rollback(self, instruction) -> bool:
        return False

    def is_control_transfer_instruction(self, instruction) -> bool:
        return False

    def is_instrumentation_helper_instruction(self, inst, inst_idx: int, instructions) -> bool:
        return False

    def adjust_insertion_offset(self, block: gtirb.CodeBlock, offset: int, decoder) -> int:
        return offset
