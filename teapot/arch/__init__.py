import gtirb

from teapot.arch.architecture import Architecture

from teapot.arch.aarch64.architecture import AArch64Architecture
from teapot.arch.riscv64.architecture import RISCV64Architecture
from teapot.arch.x64.architecture import X64Architecture


def module_isa_name(module: gtirb.Module) -> str:
    isa_name = module.isa.name
    if isa_name == "ValidButUnsupported" and "archInfo" in module.aux_data:
        arch_info = module.aux_data["archInfo"].data
        if isinstance(arch_info, dict) and "ISA" in arch_info:
            isa_name = arch_info["ISA"]
    return str(isa_name).upper()


def get_arch(module: gtirb.Module) -> Architecture:
    isa_name = module_isa_name(module)
    if isa_name == "X64":
        return X64Architecture()
    if isa_name in ("ARM64", "AARCH64"):
        return AArch64Architecture()
    if isa_name == "RISCV64":
        return RISCV64Architecture()
    if isa_name in ("RISCV32", "RISCV"):
        raise NotImplementedError(
            "Teapot only supports RV64 RISC-V modules; RV32 and generic RISCV modules are not supported"
        )
    raise NotImplementedError(f"Unsupported architecture: {isa_name}")
