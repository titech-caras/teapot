import gtirb
from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Pass, RewritingContext


class NormalizeAArch64RelocationsPass(Pass):
    """Normalize AArch64 section-relative symbolic expressions from ddisasm.

    ddisasm can represent section-anchor relocations as the chosen object
    symbol plus the original section offset. For AArch64 page/lo12 relocation
    pairs that double-counts the offset when pprinted and reassembled. Use the
    encoded instruction immediate as the source of truth and adjust only the
    symbolic-expression addend.

    ddisasm also emits GOT loads through synthetic .got symbols and records the
    real target in symbolForwarding. Add the GOT attribute expected by the
    AArch64 pprinter so adrp/ldr pairs stay as :got:/:got_lo12: references.
    """

    def __init__(self, decoder: GtirbInstructionDecoder):
        self.decoder = decoder

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        if module.isa != gtirb.Module.ISA.ARM64:
            return

        self._instructions = {
            inst.address: inst
            for block in module.code_blocks
            if block.size
            for inst in self.decoder.get_instructions(block)
        }

        for section in module.sections:
            for byte_interval in section.byte_intervals:
                if byte_interval.address is None:
                    continue

                for offset, symexpr in list(byte_interval.symbolic_expressions.items()):
                    if not isinstance(symexpr, gtirb.SymAddrConst):
                        continue

                    attributes = self._normalized_attributes(module, symexpr)
                    symbol_address = self._symbol_address(symexpr.symbol)
                    if symbol_address is None:
                        continue

                    inst = self._instructions.get(byte_interval.address + offset)
                    if inst is None:
                        continue

                    corrected_offset = self._corrected_offset(
                        byte_interval,
                        offset,
                        inst,
                        symexpr,
                        symbol_address,
                    )
                    if corrected_offset is None:
                        corrected_offset = symexpr.offset

                    if corrected_offset == symexpr.offset and attributes == symexpr.attributes:
                        continue

                    byte_interval.symbolic_expressions[offset] = gtirb.SymAddrConst(
                        offset=corrected_offset,
                        symbol=symexpr.symbol,
                        attributes=attributes,
                    )

    @staticmethod
    def _normalized_attributes(module: gtirb.Module, symexpr: gtirb.SymAddrConst):
        attributes = set(symexpr.attributes)
        if NormalizeAArch64RelocationsPass._is_got_forwarded_symbol(module, symexpr.symbol):
            attributes.add(gtirb.SymbolicExpression.Attribute.GOT)
        return attributes

    @staticmethod
    def _is_got_forwarded_symbol(module: gtirb.Module, symbol) -> bool:
        forwarding = module.aux_data.get("symbolForwarding")
        if forwarding is None or symbol not in forwarding.data:
            return False

        referent = getattr(symbol, "referent", None)
        byte_interval = getattr(referent, "byte_interval", None)
        section = getattr(byte_interval, "section", None)
        return section is not None and section.name in {".got", ".got.plt"}

    @staticmethod
    def _symbol_address(symbol):
        referent = getattr(symbol, "referent", None)
        if referent is None:
            return None
        return getattr(referent, "address", None)

    def _corrected_offset(self, byte_interval, offset: int, inst, symexpr: gtirb.SymAddrConst, symbol_address: int):
        if gtirb.SymbolicExpression.Attribute.LO12 in symexpr.attributes:
            return self._corrected_lo12_offset(inst, symexpr, symbol_address)

        if inst.mnemonic == "adrp":
            return self._paired_lo12_offset(byte_interval, offset, inst, symexpr, symbol_address)

        return None

    def _corrected_lo12_offset(self, inst, symexpr: gtirb.SymAddrConst, symbol_address: int):
        encoded_lo12 = self._encoded_lo12(inst)
        if encoded_lo12 is None:
            return None

        current_lo12 = (symbol_address + symexpr.offset) & 0xfff
        if current_lo12 == encoded_lo12:
            return None

        return (encoded_lo12 - (symbol_address & 0xfff)) & 0xfff

    def _paired_lo12_offset(self, byte_interval, offset: int, inst, symexpr: gtirb.SymAddrConst, symbol_address: int):
        next_offset = offset + inst.size
        next_symexpr = byte_interval.symbolic_expressions.get(next_offset)
        if not isinstance(next_symexpr, gtirb.SymAddrConst):
            return None
        if next_symexpr.symbol is not symexpr.symbol:
            return None
        if gtirb.SymbolicExpression.Attribute.LO12 not in next_symexpr.attributes:
            return None

        next_address = byte_interval.address + next_offset if byte_interval.address is not None else None
        next_inst = self._instructions.get(next_address)
        if next_inst is None or not self._uses_adrp_register(inst, next_inst):
            return None

        corrected_lo12 = self._corrected_lo12_offset(next_inst, next_symexpr, symbol_address)
        return next_symexpr.offset if corrected_lo12 is None else corrected_lo12

    @staticmethod
    def _encoded_lo12(inst):
        for operand in inst.operands:
            if operand.type == CS_OP_MEM:
                return operand.mem.disp & 0xfff

        for operand in reversed(inst.operands):
            if operand.type == CS_OP_IMM:
                return operand.imm & 0xfff

        return None

    @staticmethod
    def _uses_adrp_register(adrp_inst, next_inst):
        if not adrp_inst.operands or adrp_inst.operands[0].type != CS_OP_REG:
            return False
        adrp_reg = adrp_inst.reg_name(adrp_inst.operands[0].reg)

        if next_inst.mnemonic == "add":
            return (
                len(next_inst.operands) >= 2 and
                next_inst.operands[1].type == CS_OP_REG and
                next_inst.reg_name(next_inst.operands[1].reg) == adrp_reg
            )

        for operand in next_inst.operands:
            if operand.type == CS_OP_MEM and next_inst.reg_name(operand.mem.base) == adrp_reg:
                return True
        return False
