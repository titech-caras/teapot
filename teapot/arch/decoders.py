"""Capstone decoders configured the way Teapot's analyses expect, one per supported architecture.

The pipeline decodes x86-64 and AArch64 blocks through gtirb-capstone, whose decoders use Capstone's
defaults with details enabled; these helpers give tests and tools the same view. RISC-V modules are
decoded through the rewriting fork's shared ``riscv64_decoder`` configuration.
"""
import capstone
from gtirb_rewriting.decoder import RISCV64_MODE, configure_riscv64, riscv64_decoder


def x64_decoder() -> capstone.Cs:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    return decoder


def aarch64_decoder() -> capstone.Cs:
    decoder = capstone.Cs(capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM)
    decoder.detail = True
    return decoder
