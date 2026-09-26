"""Capstone decoders configured the way Teapot's analyses expect, one per supported architecture.

The pipeline decodes x86-64 and AArch64 blocks through gtirb-capstone, whose decoders use Capstone's
defaults with details enabled; these helpers give tests and tools the same view. RISC-V modules are
decoded through ``riscv64_decoder`` everywhere (see ``teapot.arch.riscv64.compat.gtirb``).
"""
import capstone

# RV64GC. Capstone 6 decodes the A, F and D extensions only when their mode flags are set, so a bare
# RV64 decoder stops at the first atomic or floating-point instruction.
RISCV64_MODE = (capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC |
                capstone.CS_MODE_RISCV_A | capstone.CS_MODE_RISCV_FD)


def x64_decoder() -> capstone.Cs:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    return decoder


def aarch64_decoder() -> capstone.Cs:
    decoder = capstone.Cs(capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
    decoder.detail = True
    return decoder


def configure_riscv64(decoder: capstone.Cs) -> capstone.Cs:
    """Real, uncompressed RISC-V instructions with complete details.

    Capstone 6's alias details drop the link register of `jal`, `jalr` and `ret` from the operands, the
    register accesses and the call group; the uncompressed real form lists every operand. A compressed
    instruction keeps its 2-byte size. gtirb-live-register-analysis configures its decoder the same way.
    """
    decoder.syntax = capstone.CS_OPT_SYNTAX_UNCOMPRESSED_REAL
    decoder.option(capstone.CS_OPT_DETAIL, capstone.CS_OPT_ON | capstone.CS_OPT_DETAIL_UNCOMPRESSED_REAL)
    return decoder


def riscv64_decoder(mode: int = 0) -> capstone.Cs:
    """An RV64 decoder; ``mode`` adds flags such as the byte order."""
    return configure_riscv64(capstone.Cs(capstone.CS_ARCH_RISCV, RISCV64_MODE | mode))
