"""Capstone decoders configured the way Teapot's analyses expect, one per supported architecture.

The pipeline decodes x86-64 and AArch64 blocks through gtirb-capstone, whose decoders use Capstone's
defaults with details enabled; these helpers give tests and tools the same view. RISC-V modules are
decoded through ``riscv64_decoder`` everywhere (see ``teapot.arch.riscv64.compat.gtirb``).
"""
import capstone

# Capstone 6 renamed ARM64 to AArch64.
CS_ARCH_AARCH64 = getattr(capstone, "CS_ARCH_AARCH64", None)
if CS_ARCH_AARCH64 is None:
    CS_ARCH_AARCH64 = capstone.CS_ARCH_ARM64

# RV64GC. Capstone 6 decodes the A, F and D extensions only when their mode flags are set (Capstone 5
# always decoded them and has no such flags), so a bare RV64 decoder stops at the first atomic or
# floating-point instruction.
RISCV64_MODE = (capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC |
                getattr(capstone, "CS_MODE_RISCV_A", 0) | getattr(capstone, "CS_MODE_RISCV_FD", 0))


def x64_decoder() -> capstone.Cs:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    return decoder


def aarch64_decoder() -> capstone.Cs:
    decoder = capstone.Cs(CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
    decoder.detail = True
    return decoder


def configure_riscv64(decoder: capstone.Cs) -> capstone.Cs:
    """Real, uncompressed RISC-V instructions with complete details under Capstone 6.

    Capstone 6's alias details drop the link register of `jal`, `jalr` and `ret` from the operands, the
    register accesses and the call group; the uncompressed real form lists every operand. A compressed
    instruction keeps its 2-byte size. gtirb-live-register-analysis configures its decoder the same way.
    Capstone 5 has neither option and is left as is.
    """
    syntax = getattr(capstone, "CS_OPT_SYNTAX_UNCOMPRESSED_REAL", None)
    if syntax is None:
        decoder.detail = True
        return decoder
    decoder.syntax = syntax
    decoder.option(capstone.CS_OPT_DETAIL, capstone.CS_OPT_ON | capstone.CS_OPT_DETAIL_UNCOMPRESSED_REAL)
    return decoder


def riscv64_decoder(mode: int = 0) -> capstone.Cs:
    """An RV64 decoder; ``mode`` adds flags such as the byte order."""
    return configure_riscv64(capstone.Cs(capstone.CS_ARCH_RISCV, RISCV64_MODE | mode))
