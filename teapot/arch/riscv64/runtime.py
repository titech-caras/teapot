import gtirb

from teapot.arch.riscv64.compat.gtirb import (
    install_riscv64_decoder_compat as _install_decoder_compat,
    install_riscv64_rewriting_compat as _install_rewriting_compat,
)
from teapot.configs.runtime import COMMON_CHECKPOINT_LIB_SYMBOLS


class RISCV64RuntimeMixin:
    TEXT_CHECKPOINTS_IN_MAIN_TEXT_PASS = False
    NEEDS_LATE_TEXT_CHECKPOINTS = True

    def register_abi(self, abi_map):
        isa = getattr(gtirb.Module.ISA, "RISCV64", None)
        if isa is not None:
            abi_map[(isa, gtirb.Module.FileFormat.ELF)] = self.abi
        abi_map[(gtirb.Module.ISA.ValidButUnsupported, gtirb.Module.FileFormat.ELF)] = self.abi
        return self.abi

    def install_decoder_compat(self) -> None:
        _install_decoder_compat()

    def install_rewriting_compat(self) -> None:
        _install_rewriting_compat()

    def checkpoint_lib_symbols(self):
        return [
            *COMMON_CHECKPOINT_LIB_SYMBOLS,
            "make_checkpoint_riscv64",
        ]
