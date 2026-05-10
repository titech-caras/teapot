import gtirb

from teapot.configs.runtime import COMMON_CHECKPOINT_LIB_SYMBOLS


class AArch64RuntimeMixin:
    NEEDS_STARTUP_NORMALIZATION = True
    RUN_TEXT_PASSES_BEFORE_TRANSIENT = True
    NEEDS_CONDITIONAL_BRANCH_RELAX = True

    def register_abi(self, abi_map):
        abi_map[(gtirb.Module.ISA.ARM64, gtirb.Module.FileFormat.ELF)] = self.abi
        return self.abi

    def checkpoint_lib_symbols(self):
        return [
            *COMMON_CHECKPOINT_LIB_SYMBOLS,
            "make_checkpoint_aarch64",
            "report_gadget_aarch64_preserve_KASPER_CACHE",
            "report_gadget_aarch64_preserve_KASPER_MDS",
            "report_gadget_aarch64_preserve_KASPER_PORT",
        ]
