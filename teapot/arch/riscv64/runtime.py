import gtirb

from teapot.configs.runtime import COMMON_CHECKPOINT_LIB_SYMBOLS


class RISCV64RuntimeMixin:
    # Landing pads and fixed-point jump relaxation still need the final layout.
    NEEDS_LATE_TEXT_CHECKPOINTS = True

    def register_abi(self, abi_map):
        isa = getattr(gtirb.Module.ISA, "RISCV64", None)
        if isa is not None:
            abi_map[(isa, gtirb.Module.FileFormat.ELF)] = self.abi
        abi_map[(gtirb.Module.ISA.ValidButUnsupported, gtirb.Module.FileFormat.ELF)] = self.abi
        return self.abi

    def checkpoint_lib_symbols(self):
        return [
            *COMMON_CHECKPOINT_LIB_SYMBOLS,
            "make_checkpoint_riscv64",
        ]
