"""Coalesce the register wrappers of adjacent x64 patches in the transient copy.

The rewriter saves the registers a patch clobbers before it and restores them
after it (teapot/arch/x64/abi.py). Where one patch restores a register and the
next patch saves it again, the second save stores the value the slot already
holds. Where that next patch then writes the register before it reads it, the
restore is dead as well. This round removes both from the finished copy, after
its pads are anchored, from the decoded instructions and their symbolic
operands:

- Input instructions are barriers, before anything else is considered. The
  pipeline tags every instruction of the copy when it makes the copy, in the
  rewriter's edit-aware comments table (mark_input_instructions), so the tag
  follows the instruction and inserted code has none. An instruction with a
  tag, or with a live-register mask, is input. A missing mask proves nothing.
  Without tags the round does nothing.
- The spill area belongs to the runtime's scratchpad: the one module symbol of
  that name, undefined here. Without exactly one such symbol the round does
  nothing. A wrapper access is a MOV of a whole 64-bit register to or from a
  slot of X64_WRAPPER_AREA, absolute or RIP-relative, whose displacement is
  that symbol's own expression and nothing else: no attributes, slot-aligned
  (8 bytes). The slot's key keeps the symbol's identity. Any other reference
  to the symbol near the area ends every proof, as an input instruction does.
- The proof stays within one code block. Control flow enters a block only at
  its start, so nothing reaches the instructions between a removed access and
  what makes it removable by another path.
- A save of R to S is removable when R was reloaded from S with only wrapper
  accesses since, none of which wrote R or S: S holds R's value. Facts end at
  any other instruction.
- A reload of R is removable when every instruction after it, up to one that
  writes all of R (a 64- or 32-bit destination, a 32- or 64-bit XOR or SUB of
  R with itself, or another reload), is modeled and reads no part of R, except
  for removable saves of R that rely on this reload: those are removed with
  it, or the reload stays. The proof ends, keeping the reload, at a branch,
  call, return or interrupt, at an instruction outside the modeled set, at the
  block's end, and at a barrier, so only the patch that follows can make a
  reload dead.

Neither removal changes what any slot holds at any point, and the register
differs only where nothing reads it: application registers, flags and slot
contents are what they were.
"""
import bisect
import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import gtirb
from capstone import CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_PRIVILEGE, CS_GRP_RET
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, X86_REG_RIP
from gtirb_rewriting import Pass, _auxdata_offsetmap

from teapot.arch.x64.abi import X64_WRAPPER_AREA
from teapot.passes.mixins.visitor_pass_mixin import block_order

INPUT_TAG = "TEAPOT_TRANSIENT_INPUT"
SPILL_SYMBOL = "scratchpad"
SLOT_SIZE = 8
# A reference to the spill symbol from this far below the area up to its end
# could reach a slot (no x64 access is wider); one that is not a wrapper access
# is a barrier.
NEAR_AREA = 65536

_LEGACY = {"a": "rax", "b": "rbx", "c": "rcx", "d": "rdx"}
# Register name -> (64-bit register, whether writing it writes the whole register).
GPR_PARTS: Dict[str, Tuple[str, bool]] = {}
for _letter, _full in _LEGACY.items():
    GPR_PARTS.update({_full: (_full, True), f"e{_letter}x": (_full, True), f"{_letter}x": (_full, False),
                      f"{_letter}l": (_full, False), f"{_letter}h": (_full, False)})
for _name in ("si", "di", "bp", "sp"):
    GPR_PARTS.update({f"r{_name}": (f"r{_name}", True), f"e{_name}": (f"r{_name}", True),
                      _name: (f"r{_name}", False), f"{_name}l": (f"r{_name}", False)})
for _number in range(8, 16):
    GPR_PARTS.update({f"r{_number}": (f"r{_number}", True), f"r{_number}d": (f"r{_number}", True),
                      f"r{_number}w": (f"r{_number}", False), f"r{_number}b": (f"r{_number}", False)})

# Instructions whose register effects the proof takes from the decoder. A
# conditional move also reads its destination; partial writes count as reads.
MODELED = frozenset((
    "mov", "movabs", "movzx", "movsx", "movsxd", "lea", "add", "sub", "adc", "sbb", "and", "or", "xor",
    "not", "neg", "inc", "dec", "shl", "sal", "shr", "sar", "rol", "ror", "test", "cmp", "bt", "imul",
    "lahf", "sahf", "nop", "cld", "clc", "stc", "cmc", "xchg", "bswap", "popcnt", "lzcnt", "tzcnt",
    "bsf", "bsr", "andn", "shlx", "shrx", "sarx", "rorx", "bzhi", "cdqe", "cqo", "cdq", "cwde",
)) | frozenset(f"set{c}" for c in ("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l",
                                       "ge", "le", "g")) \
   | frozenset(f"cmov{c}" for c in ("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l",
                                        "ge", "le", "g"))
ENDS_PROOF = (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET, CS_GRP_PRIVILEGE)


@dataclass
class CoalescingStatistics:
    """What the round removed and kept, for the rewrite log and the static counts."""
    saves_removed: int = 0                 # saves of a value the slot holds, the reload kept
    reloads_removed: int = 0               # dead reloads, with their saves
    saves_removed_with_reloads: int = 0
    reloads_kept: Dict[str, int] = field(default_factory=dict)   # why a reload stayed
    application_writer: int = 0            # kept at an application instruction that writes the register
    blocks: int = 0
    unrecognized: int = 0                  # spill-symbol references near the area that are no wrapper access
    input_without_mask: int = 0            # input instructions (tagged) without a live-register mask
    disabled: Optional[str] = None

    def keep(self, reason: str):
        self.reloads_kept[reason] = self.reloads_kept.get(reason, 0) + 1

    def summary(self) -> str:
        if self.disabled is not None:
            return f"not run: {self.disabled}"
        kept = ", ".join(f"{reason} {count}" for reason, count in sorted(self.reloads_kept.items()))
        return (f"{self.saves_removed + self.saves_removed_with_reloads} saves and {self.reloads_removed} "
                f"reloads removed ({self.reloads_removed} reloads took {self.saves_removed_with_reloads} "
                f"saves with them) in {self.blocks} blocks; reloads kept: {kept or 'none'}; "
                f"{self.application_writer} of those before an application instruction writing the register; "
                f"{self.unrecognized} other spill-area references; "
                f"{self.input_without_mask} input instructions without a mask")


@dataclass(frozen=True)
class WrapperAccess:
    reload: bool          # mov register, slot (else mov slot, register)
    register: str
    slot: Tuple[object, int]   # (the spill symbol's UUID, its offset)


# Barriers: where every proof ends and every fact is dropped.
INPUT = "application instruction"
UNRECOGNIZED = "unrecognized spill-area reference"


@dataclass(frozen=True)
class Effect:
    ends: Optional[str]   # why the proof ends here, or None
    reads: frozenset = frozenset()
    writes: frozenset = frozenset()


class X64WrapperCoalescingPass(Pass):
    def __init__(self, reg_manager, section: gtirb.Section, decoder):
        self.reg_manager = reg_manager
        self.section = section
        self.decoder = decoder
        self.statistics = CoalescingStatistics()

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx) -> None:
        spill = self.spill_symbol(module)
        if spill is None:
            self.statistics.disabled = (f"the module has no single undefined {SPILL_SYMBOL!r} "
                                        "symbol for the runtime's spill area")
            return
        tags = input_offsets(module, self.section)
        if not tags:
            self.statistics.disabled = "the copy's input instructions are not marked"
            return
        masks = self.reg_manager.masks if self.reg_manager is not None else {}
        # The interval offsets of spill-symbol references near the area; blocks
        # without one are skipped undecoded.
        near = {interval: sorted(offset for offset, expression in interval.symbolic_expressions.items()
                                 if _near_area(expression, spill))
                for interval in self.section.byte_intervals}
        for block in sorted(self.section.code_blocks, key=block_order):
            interval = block.byte_interval
            if interval is None:
                continue
            references = near[interval]
            first = bisect.bisect_left(references, block.offset)
            if first == len(references) or references[first] >= block.offset + block.size:
                continue
            instructions = list(self.decoder.get_instructions(block))
            offsets = list(itertools.accumulate((inst.size for inst in instructions[:-1]), initial=0))
            block_tags = tags.get(block, [])
            accesses, barriers = [], []
            for inst, offset in zip(instructions, offsets):
                tagged = bisect.bisect_left(block_tags, offset) < bisect.bisect_left(block_tags, offset + inst.size)
                masked = gtirb.Offset(block, offset) in masks
                if tagged and not masked:
                    self.statistics.input_without_mask += 1
                if tagged or masked:
                    # Input: a barrier before its operands are even looked at.
                    accesses.append(None)
                    barriers.append(INPUT)
                    continue
                access = self.wrapper_access(inst, interval, block.offset + offset, spill)
                if access is UNRECOGNIZED:
                    self.statistics.unrecognized += 1
                    accesses.append(None)
                    barriers.append(UNRECOGNIZED)
                else:
                    accesses.append(access)
                    barriers.append(None)
            removed = self.coalesce(instructions, accesses, barriers)
            if not removed:
                continue
            self.statistics.blocks += 1
            # One deletion per run of adjacent removed instructions.
            runs: List[List[int]] = []
            for index in sorted(removed):
                if runs and runs[-1][-1] == index - 1:
                    runs[-1].append(index)
                else:
                    runs.append([index])
            for run in runs:
                start = offsets[run[0]]
                end = offsets[run[-1]] + instructions[run[-1]].size
                rewriting_ctx.delete_at(block, start, end - start)

    def end_module(self, module, functions) -> None:
        unmark_input_instructions(module)
        print(f"[teapot] x64 wrapper coalescing: {self.statistics.summary()}", flush=True)

    @staticmethod
    def spill_symbol(module: gtirb.Module) -> Optional[gtirb.Symbol]:
        """The runtime's scratchpad: the module's only symbol of that name, defined outside it."""
        candidates = list(module.symbols_named(SPILL_SYMBOL))
        if len(candidates) != 1 or not isinstance(candidates[0].referent, gtirb.ProxyBlock):
            return None
        return candidates[0]

    @staticmethod
    def wrapper_access(inst, interval: gtirb.ByteInterval, interval_offset: int, spill: gtirb.Symbol):
        """A WrapperAccess; UNRECOGNIZED for another reference that could reach the area; else None."""
        expressions = [(offset, expression) for offset in range(interval_offset, interval_offset + inst.size)
                       for expression in (interval.symbolic_expressions.get(offset),) if expression is not None]
        if not any(_near_area(expression, spill) for _, expression in expressions):
            return None
        if inst.mnemonic != "mov" or len(inst.operands) != 2 or len(expressions) != 1:
            return UNRECOGNIZED
        kinds = tuple(operand.type for operand in inst.operands)
        if kinds == (X86_OP_REG, X86_OP_MEM):
            register, memory, reload = inst.operands[0], inst.operands[1], True
        elif kinds == (X86_OP_MEM, X86_OP_REG):
            register, memory, reload = inst.operands[1], inst.operands[0], False
        else:
            return UNRECOGNIZED
        name = inst.reg_name(register.reg)
        if register.size != 8 or memory.size != 8 or GPR_PARTS.get(name) != (name, True) or name == "rsp":
            return UNRECOGNIZED
        if (memory.mem.base not in (X86_REG_INVALID, X86_REG_RIP) or memory.mem.index != X86_REG_INVALID or
                memory.mem.segment != X86_REG_INVALID or memory.mem.scale != 1):
            return UNRECOGNIZED
        (offset, expression), = expressions
        # The expression must be the displacement itself: the operand's address
        # is the symbol's plus the offset, and nothing else.
        if offset != interval_offset + inst.disp_offset or inst.disp_size != 4:
            return UNRECOGNIZED
        if (not isinstance(expression, gtirb.SymAddrConst) or expression.symbol is not spill or
                expression.attributes or expression.offset not in X64_WRAPPER_AREA or
                (expression.offset - X64_WRAPPER_AREA.start) % SLOT_SIZE or
                expression.offset + SLOT_SIZE > X64_WRAPPER_AREA.stop):
            return UNRECOGNIZED
        return WrapperAccess(reload, name, (spill.uuid, expression.offset))

    @staticmethod
    def effect(inst) -> Effect:
        """The general-register effects of an instruction that is not a wrapper access."""
        if any(inst.group(group) for group in ENDS_PROOF):
            return Effect("control transfer")
        mnemonic = inst.mnemonic
        if mnemonic not in MODELED:
            return Effect("unmodeled instruction")
        read_ids, write_ids = inst.regs_access()
        reads, writes = set(), set()
        for register_id in read_ids:
            part = GPR_PARTS.get(inst.reg_name(register_id))
            if part:
                reads.add(part[0])
        for register_id in write_ids:
            part = GPR_PARTS.get(inst.reg_name(register_id))
            if part:
                if part[1]:
                    writes.add(part[0])
                else:
                    reads.add(part[0])      # a partial write merges the old value
        if mnemonic.startswith("cmov"):
            # Unless the condition holds, the destination keeps its value.
            destination = inst.operands[0]
            if destination.type == X86_OP_REG:
                reads.add(GPR_PARTS[inst.reg_name(destination.reg)][0])
        elif (mnemonic in ("xor", "sub") and len(inst.operands) == 2 and
              all(operand.type == X86_OP_REG for operand in inst.operands) and
              inst.operands[0].reg == inst.operands[1].reg and inst.operands[0].size >= 4):
            # Zeroing idiom: the result and the flags do not depend on the old value.
            register = GPR_PARTS[inst.reg_name(inst.operands[0].reg)][0]
            reads.discard(register)
            writes.add(register)
        return Effect(None, frozenset(reads), frozenset(writes - reads))

    def coalesce(self, instructions, accesses: List[Optional[WrapperAccess]], barriers: List[Optional[str]]):
        """The indices of the removable wrapper accesses of one block."""
        # Saves of a value the slot holds, by the reload that established it.
        established: Dict[int, int] = {}
        facts: Dict[str, Tuple[Tuple[object, int], int]] = {}   # register -> (slot, index of its reload)
        for index, access in enumerate(accesses):
            if barriers[index] is not None or access is None:
                facts.clear()
                continue
            if access.reload:
                facts[access.register] = (access.slot, index)
                continue
            fact = facts.get(access.register)
            if fact is not None and fact[0] == access.slot:
                established[index] = fact[1]
                continue
            # The slot now holds another value: facts about it end.
            facts = {register: f for register, f in facts.items() if f[0] != access.slot}

        removed = set()
        for index, access in enumerate(accesses):
            if barriers[index] is not None or access is None or not access.reload:
                continue
            group = self._dead_reload(index, access.register, instructions, accesses, barriers, established)
            if group is not None:
                removed.update(group)
                self.statistics.reloads_removed += 1
                self.statistics.saves_removed_with_reloads += len(group) - 1
        for index, reload in established.items():
            if reload not in removed:
                # The reload stays, so the register still holds the slot's value.
                removed.add(index)
                self.statistics.saves_removed += 1
        return removed

    def _dead_reload(self, start, register, instructions, accesses, barriers, established):
        group = [start]
        for index in range(start + 1, len(instructions)):
            if barriers[index] is not None:
                if barriers[index] == INPUT:
                    effect = self.effect(instructions[index])
                    if effect.ends is None and register in effect.writes:
                        self.statistics.application_writer += 1
                self.statistics.keep(barriers[index])
                return None
            access = accesses[index]
            if access is not None:
                if access.register != register:
                    continue
                if access.reload:
                    return group
                if established.get(index) == start:
                    group.append(index)
                    continue
                self.statistics.keep("read by a save")
                return None
            effect = self.effect(instructions[index])
            if effect.ends is not None:
                self.statistics.keep(effect.ends)
                return None
            if register in effect.reads:
                self.statistics.keep("read")
                return None
            if register in effect.writes:
                return group
        self.statistics.keep("block end")
        return None


def _near_area(expression, spill: gtirb.Symbol) -> bool:
    """Whether a symbolic expression involves the spill symbol near (or in) the area."""
    if isinstance(expression, gtirb.SymAddrConst):
        return (expression.symbol is spill and
                X64_WRAPPER_AREA.start - NEAR_AREA <= expression.offset < X64_WRAPPER_AREA.stop)
    return any(symbol is spill for symbol in expression.symbols)


def mark_input_instructions(section: gtirb.Section, decoder) -> None:
    """Tag each instruction of a just-made copy as input, in the edit-aware comments table.

    The rewriter moves these entries with their instructions as it edits, drops
    them with deleted or replaced bytes, and never adds them for inserted code.
    """
    comments = _auxdata_offsetmap.comments.get_or_insert(section.module)
    for block in sorted(section.code_blocks, key=block_order):
        offset = 0
        for inst in decoder.get_instructions(block):
            key = gtirb.Offset(block, offset)
            existing = comments.get(key, "")
            comments[key] = existing + ("\n" if existing else "") + INPUT_TAG
            offset += inst.size


def input_offsets(module: gtirb.Module, section: gtirb.Section) -> Dict[gtirb.CodeBlock, List[int]]:
    """The tagged displacements of each of the section's blocks, sorted."""
    comments = _auxdata_offsetmap.comments.get(module)
    tags: Dict[gtirb.CodeBlock, List[int]] = {}
    if not comments:
        return tags
    for key, value in comments.items():
        block = key.element_id
        if (isinstance(block, gtirb.CodeBlock) and block.section is section and
                INPUT_TAG in value.split("\n")):
            tags.setdefault(block, []).append(key.displacement)
    for displacements in tags.values():
        displacements.sort()
    return tags


def unmark_input_instructions(module: gtirb.Module) -> None:
    """Remove the input tags, keeping any other comment; drop the table if nothing is left."""
    comments = _auxdata_offsetmap.comments.get(module)
    if comments is None:
        return
    for key, value in tuple(comments.items()):
        lines = value.split("\n")
        if INPUT_TAG not in lines:
            continue
        rest = [line for line in lines if line != INPUT_TAG]
        if rest:
            comments[key] = "\n".join(rest)
        else:
            del comments[key]
    if not comments:
        module.aux_data.pop("comments", None)
