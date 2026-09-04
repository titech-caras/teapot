import gtirb

from teapot.configs.runtime import COMMON_CHECKPOINT_LIB_SYMBOLS


class X64RuntimeMixin:
    NEEDS_CONDITIONAL_BRANCH_RELAX = True

    def register_abi(self, abi_map):
        abi_map[(gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF)] = self.abi
        return self.abi

    def checkpoint_lib_symbols(self):
        return [
            *COMMON_CHECKPOINT_LIB_SYMBOLS,
            "make_checkpoint_x64",
        ]
