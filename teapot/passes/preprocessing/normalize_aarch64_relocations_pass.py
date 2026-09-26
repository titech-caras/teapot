import gtirb
from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Pass, RewritingContext

from teapot.utils.misc import symbol_address


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

    Linker-relaxed ADRPs are restored first (see _restore_relaxed_adrp).
    """

    def __init__(self, decoder: GtirbInstructionDecoder):
        self.decoder = decoder
        self.restored_adrp = 0

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        if module.isa != gtirb.Module.ISA.ARM64:
            return

        self._restore_relaxed_adrp(module)
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
                    address = symbol_address(symexpr.symbol)
                    if address is None:
                        continue

                    inst = self._instructions.get(byte_interval.address + offset)
                    if inst is None:
                        continue

                    corrected_offset = self._corrected_offset(
                        byte_interval,
                        offset,
                        inst,
                        symexpr,
                        address,
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

    def _restore_relaxed_adrp(self, module: gtirb.Module) -> None:
        """Undo the linker's ADRP-to-ADR relaxation of page/lo12 pairs.

        GNU ld's Cortex-A53 erratum 843419 workaround rewrites an ADRP at page
        offset 0xff8/0xffc into an ADR of the same, 4 KiB-aligned address.
        ddisasm leaves that ADR's operand unsymbolized and represents each
        paired lo12 use as "target - page", where page is an integral symbol
        that does not exist in the reassembled program. For an aligned target
        ADR and ADRP produce the same value, so restore the ADRP and the
        ordinary page/lo12 pair (GOT attributes are added afterwards like for
        any other GOT pair). The pair is rewritten only if, within the block,
        the base register is read solely by such uses of one target before it
        is redefined; anything else is left for the assembler to reject.
        """
        for block in module.code_blocks:
            interval = block.byte_interval
            if not block.size or interval is None or interval.address is None:
                continue
            instructions = list(self.decoder.get_instructions(block))
            for index, inst in enumerate(instructions):
                if inst.mnemonic != "adr" or len(inst.operands) != 2:
                    continue
                offset = inst.address - interval.address
                page = inst.operands[1].imm
                if offset in interval.symbolic_expressions or page & 0xfff:
                    continue
                uses = self._relaxed_page_uses(interval, instructions[index + 1:],
                                               self._register(inst.reg_name(inst.operands[0].reg)), page)
                if uses is None:
                    continue
                word = int.from_bytes(interval.contents[offset:offset + 4], "little")
                delta = (page >> 12) - (inst.address >> 12)
                adrp = 0x90000000 | (delta & 3) << 29 | (delta >> 2 & 0x7ffff) << 5 | word & 0x1f
                interval.contents[offset:offset + 4] = adrp.to_bytes(4, "little")
                symbol, addend = uses[0][1]
                interval.symbolic_expressions[offset] = gtirb.SymAddrConst(addend, symbol, set())
                for use_offset, _ in uses:
                    interval.symbolic_expressions[use_offset] = gtirb.SymAddrConst(
                        addend, symbol, {gtirb.SymbolicExpression.Attribute.LO12})
                self.restored_adrp += 1

    def _relaxed_page_uses(self, interval, following, base, page):
        uses = []
        for inst in following:
            reads, writes = ({self._register(inst.reg_name(r)) for r in regs} for regs in inst.regs_access())
            if base in reads:
                use = self._relaxed_page_use(interval, inst, base, page)
                if use is None or (uses and use != uses[0][1]):
                    return None
                uses.append((inst.address - interval.address, use))
            if base in writes:
                return uses or None
        return None

    @staticmethod
    def _relaxed_page_use(interval, inst, base, page):
        symexpr = interval.symbolic_expressions.get(inst.address - interval.address)
        if not isinstance(symexpr, gtirb.SymAddrAddr) or symexpr.scale != 1:
            return None
        target = symbol_address(symexpr.symbol1)
        if symbol_address(symexpr.symbol2) != page or target is None:
            return None
        low = target + symexpr.offset - page
        if not 0 <= low < 0x1000:
            return None
        operands = inst.operands
        register = NormalizeAArch64RelocationsPass._register
        if inst.mnemonic == "add":
            if (len(operands) != 3 or operands[1].type != CS_OP_REG or register(inst.reg_name(operands[1].reg)) != base
                    or operands[2].type != CS_OP_IMM or operands[2].imm != low):
                return None
        else:
            memory = [operand for operand in operands if operand.type == CS_OP_MEM]
            if (len(memory) != 1 or inst.writeback or register(inst.reg_name(memory[0].mem.base)) != base
                    or memory[0].mem.index or memory[0].mem.disp != low):
                return None
        return symexpr.symbol1, symexpr.offset

    @staticmethod
    def _register(name):
        aliases = {"fp": 29, "lr": 30, "ip0": 16, "ip1": 17}
        if name in aliases:
            return aliases[name]
        if len(name) > 1 and name[0] in ("x", "w") and name[1:].isdigit():
            return int(name[1:])
        return name

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
