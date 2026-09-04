from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

import gtirb


class ArchitectureControlFlowMixin(ABC):
    def skipped_text_restore_guard_patch(self):
        """Restore before executing a text block skipped by target transforms.

        Architectures override this with a state-preserving checkpoint-count
        test.  The normal path must leave every application register, flags,
        and stack location unchanged.
        """
        return None

    @abstractmethod
    def indirect_branch_target_patch(self, target_symbol: gtirb.Symbol, *, use_scratch_registers: bool = False):
        pass

    def indirect_transform_uses_live_registers(self) -> bool:
        return False

    def indirect_transform_landing_pad_label(self, block_uuid: UUID):
        return None

    def indirect_transform_fallback_patch(self, target_symbol: gtirb.Symbol, *, landing_target_uuid=None):
        return self.indirect_branch_target_patch(target_symbol, use_scratch_registers=False)

    def trampoline_target_names(self, fallthrough_target_symbol_name: str, branch_target_symbol_name: str, *,
                                fallthrough_target_uuid: UUID, branch_target_uuid: UUID,
                                landing_pad_targets=None):
        return fallthrough_target_symbol_name, branch_target_symbol_name, {}

    def indirect_branch_operand(self, edge_type, last_inst, block: Optional[gtirb.CodeBlock] = None) -> Optional[str]:
        return None

    @abstractmethod
    def indirect_branch_check_patch(self, operand_str: str, transient_start_symbol: gtirb.Symbol,
                                    transient_end_symbol: gtirb.Symbol, text_start_symbol: gtirb.Symbol,
                                    text_end_symbol: gtirb.Symbol, reads_registers=None):
        pass

    def instruction_must_rollback(self, instruction) -> bool:
        return False

    def is_control_transfer_instruction(self, instruction) -> bool:
        return False

    def is_instrumentation_helper_instruction(self, inst, inst_idx: int, instructions) -> bool:
        return False

    def adjust_insertion_offset(self, block: gtirb.CodeBlock, offset: int, instructions) -> int:
        return offset
