from abc import ABC

from teapot.configs.runtime import COMMON_CHECKPOINT_LIB_SYMBOLS


class ArchitectureRuntimeMixin(ABC):
    RUN_TEXT_PASSES_BEFORE_TRANSIENT = False
    NEEDS_LATE_TEXT_CHECKPOINTS = False
    NEEDS_CONDITIONAL_BRANCH_RELAX = False

    def register_abi(self, abi_map):
        return self.abi

    def checkpoint_lib_symbols(self):
        return list(COMMON_CHECKPOINT_LIB_SYMBOLS)

    def run_text_passes_before_transient(self) -> bool:
        return self.RUN_TEXT_PASSES_BEFORE_TRANSIENT

    def needs_late_text_checkpoints(self) -> bool:
        return self.NEEDS_LATE_TEXT_CHECKPOINTS

    def needs_conditional_branch_relax(self) -> bool:
        return self.NEEDS_CONDITIONAL_BRANCH_RELAX
