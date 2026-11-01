"""Instruction decoding shared by Teapot's rewrite passes and liveness masks."""
from typing import Dict, Iterator

import capstone
import gtirb
from capstone import CsInsn
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting.decoder import riscv64_decoder

from teapot.arch import module_isa_name


class CachedGtirbInstructionDecoder(GtirbInstructionDecoder):
    # Cleared at rewrite boundaries and after edits that invalidate decoding.
    cache: dict = {}

    def get_instructions(self, block: gtirb.CodeBlock) -> Iterator[CsInsn]:
        if block.uuid in self.cache:
            return iter(self.cache[block.uuid])

        isa_name = module_isa_name(block.module) if block.module is not None else ""
        if isa_name in ("RISCV32", "RISCV"):
            raise NotImplementedError("RV32 and generic RISC-V decoding are not supported")
        if block.size == 0:
            result = []
        elif isa_name == "RISCV64":
            result = list(self._get_riscv64_decoder(block).disasm(block.contents, block.address or block.offset))
        else:
            result = list(super().get_instructions(block))
        self.cache[block.uuid] = result
        return iter(result)

    def _get_riscv64_decoder(self, block: gtirb.CodeBlock) -> capstone.Cs:
        if not hasattr(self, "_riscv64_decoders"):
            self._riscv64_decoders: Dict[int, capstone.Cs] = {}

        endian = (capstone.CS_MODE_BIG_ENDIAN if block.module and
                  block.module.byte_order == gtirb.Module.ByteOrder.Big else capstone.CS_MODE_LITTLE_ENDIAN)
        if endian not in self._riscv64_decoders:
            self._riscv64_decoders[endian] = riscv64_decoder(endian)
        return self._riscv64_decoders[endian]
