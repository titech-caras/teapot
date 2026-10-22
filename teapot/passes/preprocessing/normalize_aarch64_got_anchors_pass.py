"""Canonicalize one-use ADR(P) anchors of imported pointer GOT loads."""
import gtirb
from capstone import CS_GRP_CALL, CS_GRP_INT, CS_GRP_JUMP, CS_GRP_RET, CS_OP_MEM, CS_OP_REG
from gtirb_rewriting import Pass, Patch
from gtirb_rewriting.assembly import Constraints

from teapot.arch.aarch64.operands import aarch64_register_number
from teapot.utils.misc import symbol_address
from teapot.utils.symbol_references import reference_name

GOT_RELOCATIONS = "teapotAArch64GotRelocations"
GOT_SCHEMA = "mapping<Offset,tuple<uint64_t,string,int64_t,bool>>"


def record_got_relocations(module, item):
    """Carry only loader-required GOT relocation facts from ELF inspection."""
    if item["machine"] != "EM_AARCH64":
        return
    facts = {}
    for address, kind, name, addend, imported in item.get("aarch64_got_relocations", ()):
        intervals = [bi for bi in module.byte_intervals
                     if bi.address is not None and bi.section.name in (".got", ".got.plt")
                     and bi.address <= address and address + 8 <= bi.address + bi.size]
        if len(intervals) != 1:
            raise ValueError(f"A64_GOT_SLOT_BOUNDS: loader slot {address:#x} not uniquely recovered")
        offset = gtirb.Offset(intervals[0], address - intervals[0].address)
        if offset in facts:
            raise ValueError(f"A64_GOT_DUPLICATE_RELOCATION: loader slot {address:#x}")
        facts[offset] = (kind, name, addend, imported)
    module.aux_data[GOT_RELOCATIONS] = gtirb.AuxData(facts, GOT_SCHEMA)


class NormalizeAArch64GotAnchorsPass(Pass):
    """No scratch registers or pointer-value lifetime restriction.

    Only a same-block ADR/ADRP anchor whose sole read is one unsigned-immediate
    64-bit LDR is rewritten. Its value must die in that block. Other GOT access
    forms are not guessed; unrelated ADR/ADRP references are left alone.
    """

    def __init__(self, decoder):
        self.decoder = decoder
        self.normalized = 0

    @staticmethod
    def _fail(code, inst, detail):
        raise ValueError(f"{code}: {inst.address:#x}: {detail}")

    @staticmethod
    def _registers(inst, write=False):
        return {aarch64_register_number(inst.reg_name(reg))
                for reg in inst.regs_access()[int(write)]}

    @staticmethod
    def _expression(block, inst):
        return block.byte_interval.symbolic_expressions.get(
            block.offset + inst.address - block.address)

    @staticmethod
    def _got_symbol(symbol):
        return (isinstance(symbol.referent, gtirb.DataBlock) and not symbol.at_end
                and symbol.referent.section.name in (".got", ".got.plt"))

    def begin_module(self, module, functions, rewriting_ctx):
        self.normalized = 0
        facts = module.aux_data.get(GOT_RELOCATIONS)
        forwarding = module.aux_data.get("symbolForwarding")
        info = module.aux_data.get("elfSymbolInfo")
        plans = {}
        for block in sorted(module.code_blocks, key=lambda b: b.address or 0):
            instructions = list(self.decoder.get_instructions(block))
            for index, load in enumerate(instructions):
                expr = self._expression(block, load)
                # This exact noncanonical difference can be printed through
                # symbolForwarding as "import - anchor", which is not linkable.
                if not (isinstance(expr, gtirb.SymAddrAddr) and self._got_symbol(expr.symbol1)):
                    continue
                if sum(inst.size for inst in instructions) != block.size:
                    self._fail("A64_GOT_INCOMPLETE_BLOCK", load, "anchor lifetime cannot be proved")
                word = int.from_bytes(load.bytes, "little")
                if (load.mnemonic != "ldr" or word & 0xffc00000 != 0xf9400000
                        or len(load.operands) != 2 or load.operands[0].type != CS_OP_REG
                        or load.operands[1].type != CS_OP_MEM or load.writeback
                        or load.operands[1].mem.index):
                    self._fail("A64_GOT_LOAD_SHAPE", load, "requires one pointer-sized unsigned-immediate LDR")
                register = aarch64_register_number(load.reg_name(load.operands[1].mem.base))
                anchor_index = next((n for n in range(index - 1, -1, -1)
                                     if register in self._registers(instructions[n], True)), None)
                if anchor_index is None or instructions[anchor_index].mnemonic not in ("adr", "adrp"):
                    self._fail("A64_GOT_ANCHOR_DEFINITION", load, "no same-block ADR/ADRP reaching definition")
                anchor = instructions[anchor_index]
                if register is None or register != aarch64_register_number(anchor.reg_name(anchor.operands[0].reg)):
                    self._fail("A64_GOT_ANCHOR_REGISTER", load, "invalid anchor register")
                uses, killed = [], False
                for n in range(anchor_index + 1, len(instructions)):
                    inst = instructions[n]
                    if any(inst.group(group) for group in (CS_GRP_CALL, CS_GRP_INT, CS_GRP_JUMP, CS_GRP_RET)):
                        self._fail("A64_GOT_ANCHOR_CONTROL_FLOW", inst, "anchor proof crosses a control transfer")
                    if register in self._registers(inst):
                        uses.append(n)
                    if register in self._registers(inst, True):
                        killed = True
                        break
                if uses != [index]:
                    self._fail("A64_GOT_ANCHOR_MULTIPLE_USES", anchor, "anchor's only use must be this LDR")
                if not killed:
                    self._fail("A64_GOT_ANCHOR_LIVE_OUT", anchor, "anchor remains live at block exit")
                base = anchor.operands[1].imm
                if (expr.scale != 1 or expr.offset != 0 or expr.attributes
                        or symbol_address(expr.symbol2) != base):
                    self._fail("A64_GOT_LOAD_EXPRESSION", load, "slot-minus-anchor expression does not match ADR(P)")
                high = self._expression(block, anchor)
                if not isinstance(high, gtirb.SymAddrConst):
                    self._fail("A64_GOT_ANCHOR_EXPRESSION", anchor, "symbolic ADR(P) target required")
                high_address = symbol_address(high.symbol)
                allowed = {gtirb.SymbolicExpression.Attribute.PART0} if anchor.mnemonic == "adrp" else set()
                # DDisasm ADRP metadata denotes the target before page rounding.
                if (high_address is None or high.attributes - allowed
                        or ((high_address + high.offset) & ~4095 if anchor.mnemonic == "adrp"
                            else high_address + high.offset) != base):
                    self._fail("A64_GOT_ANCHOR_EXPRESSION", anchor, "symbolic target does not match ADR(P)")
                slot = expr.symbol1
                address = symbol_address(slot)
                if address is None or base + load.operands[1].mem.disp != address:
                    self._fail("A64_GOT_SLOT_ADDRESS", load, "effective address must equal the exact GOT slot")
                interval = slot.referent.byte_interval
                offset = gtirb.Offset(interval, address - interval.address)
                evidence = facts.data.get(offset) if facts else None
                if evidence is None:
                    self._fail("A64_GOT_RELOCATION_MISSING", load, "loader GOT relocation evidence required")
                kind, name, addend, imported = evidence
                if kind not in (257, 1025):
                    self._fail("A64_GOT_RELOCATION_TYPE", load, "requires ABS64 or GLOB_DAT")
                if addend:
                    self._fail("A64_GOT_RELOCATION_ADDEND", load, "canonical GOT load cannot preserve nonzero addend")
                if not imported:
                    self._fail("A64_GOT_RELOCATION_NOT_IMPORT", load, "loader symbol must be undefined")
                target = forwarding.data.get(slot) if forwarding else None
                if target is None:
                    self._fail("A64_GOT_FORWARDING_MISSING", load, "GOT slot must forward to its imported symbol")
                entry = info.data.get(target) if info else None
                stored = interval.symbolic_expressions.get(offset.displacement)
                if (target.name != name or not isinstance(target.referent, gtirb.ProxyBlock)
                        or entry is None or entry[4] != 0
                        or not isinstance(stored, gtirb.SymAddrConst) or stored.symbol is not target
                        or stored.offset != 0 or stored.attributes):
                    self._fail("A64_GOT_FORWARDING_MISMATCH", load, "slot, loader relocation and imported symbol disagree")
                target_name = reference_name(target, {gtirb.SymbolicExpression.Attribute.GOT})
                base_name = anchor.reg_name(anchor.operands[0].reg)
                value_name = load.reg_name(load.operands[0].reg)
                plan = ((anchor.address, f"adrp {base_name}, :got:{target_name}"),
                        (load.address, f"ldr {value_name}, [{base_name}, :got_lo12:{target_name}]"))
                key = block.byte_interval, block.offset + anchor.address - block.address
                if key in plans and plans[key][1] != plan:
                    self._fail("A64_GOT_OVERLAPPING_VIEWS", anchor, "conflicting anchor/load views")
                plans[key] = block, plan
        # Validate the entire module before scheduling any replacement.
        for block, plan in plans.values():
            for address, assembly in plan:
                rewriting_ctx.replace_at(block, address - block.address, 4,
                    Patch.from_function(lambda _ctx, assembly=assembly: assembly, Constraints()))
            self.normalized += 1

    def end_module(self, module, functions):
        print(f"[teapot] AArch64 GOT anchor normalization: {self.normalized} references in {module.name!r}",
              flush=True)
