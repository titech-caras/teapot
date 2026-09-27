import gtirb
from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Pass, RewritingContext

from teapot.arch.aarch64.operands import (
    aarch64_access_displacement,
    aarch64_base_register_writeback,
    aarch64_data_memory_operands,
    aarch64_register_number,
)
from teapot.passes.preprocessing.split_lo12 import (
    AArch64PageState, page_offset, reaching_adrp_definitions, symbolize_split_lo12)
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
    Expressions already marked GOT name the target, not the encoded slot;
    their addends must not be recovered from that slot's address.

    Linker-relaxed ADRPs are restored first (see _restore_relaxed_adrp), and raw
    page-offset users of split ADRPs are symbolized (see split_lo12.py).
    """

    def __init__(self, decoder: GtirbInstructionDecoder):
        self.decoder = decoder
        self.restored_adrp = 0

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        if module.isa != gtirb.Module.ISA.ARM64:
            return

        self._restore_relaxed_adrp(module)
        self._paired_offsets = self._recover_page_addends(module)
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
        # Use the corrected full addends when recovering additional raw users.
        self.symbolized_split_lo12 = symbolize_split_lo12(module, self.decoder)

    def _recover_page_addends(self, module):
        """Recover full (including negative/multi-page) addends from proven pairs.

        Follow all reaching definitions over the CFG, not adjacency in the byte
        stream. A redefinition, unknown entry or caller-saved value across a
        call stops recovery. Every incoming ADRP must name the same symbol and
        original page; otherwise the LO12 cannot safely be normalized.
        """
        state = AArch64PageState(module, self.decoder)
        recovered, high_candidates = {}, {}
        for block in module.code_blocks:
            if not block.size or block.address is None:
                continue
            for index, inst in enumerate(state.insns(block)):
                expr = state.symexpr(block, inst)
                if (not isinstance(expr, gtirb.SymAddrConst) or
                        gtirb.SymbolicExpression.Attribute.LO12 not in expr.attributes or
                        gtirb.SymbolicExpression.Attribute.GOT in expr.attributes):
                    continue
                address = symbol_address(expr.symbol)
                if address is None:
                    continue
                ops = inst.operands
                memory = aarch64_data_memory_operands(inst)
                if inst.mnemonic == 'add' and len(ops) == 3 and ops[1].type == CS_OP_REG:
                    reg = aarch64_register_number(inst.reg_name(ops[1].reg))
                elif len(memory) == 1:
                    reg = aarch64_register_number(inst.reg_name(memory[0].mem.base))
                else:
                    continue
                if reg is None:
                    continue
                low = page_offset(inst, reg)
                if low is None:
                    continue
                origins = reaching_adrp_definitions(state, block, index, reg)
                if not origins:
                    continue
                pages, highs = set(), []
                for source, position in origins:
                    high = state.insns(source)[position]
                    high_expr = state.symexpr(source, high)
                    if not isinstance(high_expr, gtirb.SymAddrConst) or high_expr.symbol is not expr.symbol:
                        break
                    pages.add(high.operands[1].imm)
                    highs.append((source.byte_interval, high.address - source.byte_interval.address))
                else:
                    if len(pages) == 1:
                        addend = next(iter(pages)) + low - address
                        recovered[block.byte_interval, inst.address - block.byte_interval.address] = addend
                        for high in highs:
                            high_candidates.setdefault(high, set()).add(addend)
        for location, candidates in high_candidates.items():
            old = location[0].symbolic_expressions[location[1]].offset
            # Multiple users may name different bytes of one object/page.
            # Any candidate denotes the same original page; stay stable when
            # the existing expression already denotes one of them.
            recovered[location] = old if old in candidates else min(candidates)
        return recovered

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
                # Normalization edits bytes directly, before the pass manager's
                # usual analysis refresh. The next normalizer must see ADRP.
                cache = getattr(self.decoder, "cache", None)
                if cache is not None:
                    cache.pop(block.uuid, None)
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
            memory = aarch64_data_memory_operands(inst)
            if (len(memory) != 1 or aarch64_base_register_writeback(inst) or
                    register(inst.reg_name(memory[0].mem.base)) != base
                    or memory[0].mem.index or memory[0].mem.disp != low):
                return None
        return symexpr.symbol1, symexpr.offset

    @staticmethod
    def _register(name):
        # Numbered registers compare by number, so a w view matches its x register; others by name.
        number = aarch64_register_number(name)
        return name if number is None else number

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
        # A GOT relocation encodes the slot address, which need not resemble
        # the target symbol's address even when that target is defined locally.
        if gtirb.SymbolicExpression.Attribute.GOT in symexpr.attributes:
            return None
        recovered = self._paired_offsets.get((byte_interval, offset))
        if recovered is not None:
            return recovered
        if gtirb.SymbolicExpression.Attribute.LO12 in symexpr.attributes:
            return self._corrected_lo12_offset(inst, symexpr, symbol_address)

        if inst.mnemonic == "adrp":
            # Even an ADRP with no symbolized user must still encode its
            # original page. Preserve its chosen low bits until a pair proves
            # a more precise target, rather than reducing the addend mod 4KiB.
            return inst.operands[1].imm + ((symbol_address + symexpr.offset) & 0xfff) - symbol_address

        return None

    def _corrected_lo12_offset(self, inst, symexpr: gtirb.SymAddrConst, symbol_address: int):
        encoded_lo12 = self._encoded_lo12(inst)
        if encoded_lo12 is None:
            return None

        current_lo12 = (symbol_address + symexpr.offset) & 0xfff
        if current_lo12 == encoded_lo12:
            return None

        raise ValueError(f"cannot normalize LO12 at {inst.address:#x}: encoded offset differs "
                         "but no unique matching ADRP page reaches the instruction")

    @staticmethod
    def _encoded_lo12(inst):
        for operand in aarch64_data_memory_operands(inst):
            return aarch64_access_displacement(inst, operand) & 0xfff

        for operand in reversed(inst.operands):
            if operand.type == CS_OP_IMM:
                return operand.imm & 0xfff

        return None
