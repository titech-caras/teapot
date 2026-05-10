from abc import ABC

from teapot.configs.runtime import COMMON_CHECKPOINT_LIB_SYMBOLS


class ArchitectureRuntimeMixin(ABC):
    NEEDS_STARTUP_NORMALIZATION = False
    RUN_TEXT_PASSES_BEFORE_TRANSIENT = False
    SUPPORTS_DIFT_EXT_CALLS = True
    TEXT_CHECKPOINTS_IN_MAIN_TEXT_PASS = True
    NEEDS_LATE_TEXT_CHECKPOINTS = False
    NEEDS_CONDITIONAL_BRANCH_RELAX = False

    def register_abi(self, abi_map):
        return self.abi

    def install_decoder_compat(self) -> None:
        pass

    def install_rewriting_compat(self) -> None:
        pass

    def checkpoint_lib_symbols(self):
        return list(COMMON_CHECKPOINT_LIB_SYMBOLS)

    def needs_startup_normalization(self) -> bool:
        return self.NEEDS_STARTUP_NORMALIZATION

    def run_text_passes_before_transient(self) -> bool:
        return self.RUN_TEXT_PASSES_BEFORE_TRANSIENT

    def supports_dift_ext_calls(self) -> bool:
        return self.SUPPORTS_DIFT_EXT_CALLS

    def text_checkpoints_in_main_text_pass(self) -> bool:
        return self.TEXT_CHECKPOINTS_IN_MAIN_TEXT_PASS

    def needs_late_text_checkpoints(self) -> bool:
        return self.NEEDS_LATE_TEXT_CHECKPOINTS

    def needs_conditional_branch_relax(self) -> bool:
        return self.NEEDS_CONDITIONAL_BRANCH_RELAX
