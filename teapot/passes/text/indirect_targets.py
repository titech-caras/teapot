"""Normal-text blocks that may be indirect targets although the lift found no edge.

DDisasm can miss indirect targets: a function called directly and also through a
pointer, or a jump table it did not recover. A simulated branch to such a block
finds no marker pair and rolls back, so simulation loses that path. These rules
pad such blocks too:

- address-taken blocks: referents of symbolic expressions other than the operand
  of a direct branch or call, in data or in code;
- every block of a function containing an unresolved indirect jump that
  dispatches through a table (not an indirect tail call).

Function entries are not padded as such. Teapot relinks normal text at new
addresses, so a code pointer the lift left unsymbolized would already be stale in
the native run; every working pointer is a symbolic expression, which the
address-taken rule covers.

Blocks without a predecessor, and return sites, are handled by the text pass
itself. ``unsymbolized_data_targets`` adds data words that equal a block address
without being symbolized. An integer can coincide with an address, most often in
non-PIE binaries, so each hit costs a pad for nothing; on the evaluation corpus
they are 0-2 per binary beyond the other rules.

Everything is computed on the original IR, before instrumentation.
"""
import bisect
from collections import defaultdict

import gtirb
from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_OP_IMM, CS_OP_MEM

_PCREL = gtirb.SymbolicExpression.Attribute.PCREL
_LO = gtirb.SymbolicExpression.Attribute.LO

# Exception and debug metadata name every function start and landing pad, but
# nothing branches through them in simulation: the unwinder is external code.
_METADATA_SECTIONS = (".eh_frame", ".eh_frame_hdr", ".gcc_except_table")


def _pointer_section(section):
    flags = section.flags
    return (gtirb.Section.Flag.Loaded in flags and section.name not in _METADATA_SECTIONS and
            not section.name.startswith(".debug"))


def _code_blocks_by_address(section):
    return {block.address: block for block in section.code_blocks
            if block.size and block.address is not None}


def _instruction_at(decoder, block, address, cache):
    instructions = cache.get(block)
    if instructions is None:
        instructions = cache[block] = list(decoder.get_instructions(block))
    for instruction in instructions:
        if instruction.address <= address < instruction.address + instruction.size:
            return instruction
    return None


def _direct_pair_offsets(owner, decoder, arch, cache):
    """Interval offsets of a multi-instruction direct transfer ending the block, if any.

    RISC-V calls and tail jumps are AUIPC+JALR pairs; the target's symbol sits on the
    AUIPC, which is not a transfer instruction by itself.
    """
    instructions = cache.get(owner)
    if instructions is None:
        instructions = cache[owner] = list(decoder.get_instructions(owner))
    if len(instructions) < 2 or arch.direct_transfer_expression(owner, instructions) is None:
        return ()
    hi = owner.offset + instructions[-2].address - owner.address
    return (hi, hi + instructions[-2].size)


def _address_taken(module, text_section, decoder, arch):
    """Referents in text of every symbolic expression that is not a direct transfer operand."""
    taken = set()
    cache = {}
    for section in module.sections:
        if not _pointer_section(section):
            continue
        executable = gtirb.Section.Flag.Executable in section.flags
        for interval in section.byte_intervals:
            if interval.address is None:
                continue
            blocks = offsets = None
            for position, expression in interval.symbolic_expressions.items():
                referents = [symbol.referent for symbol in expression.symbols
                             if isinstance(symbol.referent, gtirb.CodeBlock)
                             and symbol.referent.section is text_section]
                if not referents:
                    continue
                # A RISC-V %pcrel_lo operand names its own AUIPC's label, not
                # a target; the AUIPC's %pcrel_hi operand names the target.
                if arch.name == "riscv64" and {_PCREL, _LO} <= set(expression.attributes):
                    continue
                if executable:
                    if blocks is None:
                        blocks = sorted((b for b in interval.blocks
                                         if isinstance(b, gtirb.CodeBlock) and b.size),
                                        key=lambda b: b.offset)
                        offsets = [b.offset for b in blocks]
                    index = bisect.bisect_right(offsets, position) - 1
                    owner = blocks[index] if index >= 0 else None
                    if owner is not None and position < owner.offset + owner.size:
                        instruction = _instruction_at(decoder, owner, interval.address + position, cache)
                        if instruction is not None and arch.is_direct_transfer_instruction(instruction):
                            continue
                        if position in _direct_pair_offsets(owner, decoder, arch, cache):
                            continue
                taken.update(referents)
    return {block.uuid for block in taken}


def _unresolved_jump(block, last, arch):
    """An indirect jump whose targets the lift resolved neither to code nor to a symbol.

    A jump is direct when the architecture classifies its mnemonic as one and
    it has an immediate target; otherwise it jumps through a register or memory
    (x64 jmp rax, AArch64 br, RISC-V jr). The immediate test alone is not
    enough: the decoder spells RISC-V jr t1 as jalr zero, 0(t1), whose offset
    is an immediate operand. Capstone 6 puts RISC-V ret in the jump group, so a
    Return edge or the architecture's own test excludes returns. A branch to a
    symbol's proxy, such as a tail call into a library, is resolved.
    """
    direct = (arch.is_direct_transfer_instruction(last) and
              any(operand.type == CS_OP_IMM for operand in last.operands))
    if not last.group(CS_GRP_JUMP) or last.group(CS_GRP_CALL) or last.group(CS_GRP_RET) or direct:
        return False
    is_return = getattr(arch, "is_return_instruction", None)
    if (last.mnemonic.split()[-1] in ("ret", "retf", "retaa", "retab") or
            is_return is not None and is_return(last)):
        return False
    edges = [edge for edge in block.outgoing_edges if edge.label is not None]
    if any(edge.label.type == gtirb.Edge.Type.Return for edge in edges):
        return False
    return not any(
        edge.label.type == gtirb.Edge.Type.Branch and
        (isinstance(edge.target, gtirb.CodeBlock) or
         isinstance(edge.target, gtirb.ProxyBlock) and any(True for _ in edge.target.references))
        for edge in edges)


def _looks_like_table_dispatch(instructions):
    """The block indexes a table: an indexed memory operand (x64, AArch64), or a
    shifted index added to a base (RISC-V, which has no indexed addressing).

    An unresolved jump without one is usually an indirect tail call, such as a
    C++ virtual call after the epilogue, whose targets are other functions'
    entries, not this function's blocks.
    """
    for instruction in instructions:
        if instruction.mnemonic in ("slli", "sh1add", "sh2add", "sh3add", "c.slli"):
            return True
        for operand in instruction.operands:
            if operand.type == CS_OP_MEM and getattr(operand.mem, "index", 0):
                return True
    return False


def _unresolved_jump_functions(functions, decoder, arch):
    """Functions containing an unresolved indirect jump that dispatches through a table."""
    found = set()
    for function in functions:
        for block in function.get_all_blocks():
            instructions = list(decoder.get_instructions(block))
            if (instructions and _unresolved_jump(block, instructions[-1], arch) and
                    _looks_like_table_dispatch(instructions)):
                found.add(function)
                break
    return found


def potential_indirect_targets(module, text_section, functions, decoder, arch):
    """Rule name -> set of normal-text block UUIDs."""
    rules = defaultdict(set)
    rules["address-taken"] = _address_taken(module, text_section, decoder, arch)
    for function in _unresolved_jump_functions(functions, decoder, arch):
        rules["unresolved-jump-function"].update(
            block.uuid for block in function.get_all_blocks()
            if isinstance(block, gtirb.CodeBlock) and block.section is text_section)
    return dict(rules)


def unsymbolized_data_targets(module, text_section):
    """Text block starts equal to a pointer-aligned, unsymbolized word in data."""
    width = 8
    starts = _code_blocks_by_address(text_section)
    found = set()
    for section in module.sections:
        flags = section.flags
        if (gtirb.Section.Flag.Executable in flags or not _pointer_section(section) or
                gtirb.Section.Flag.Initialized not in flags):
            continue
        for interval in section.byte_intervals:
            if interval.address is None:
                continue
            contents = bytes(interval.contents)
            first = (-interval.address) % width
            for position in range(first, len(contents) - width + 1, width):
                if position in interval.symbolic_expressions:
                    continue
                block = starts.get(int.from_bytes(contents[position:position + width], "little"))
                if block is not None:
                    found.add(block.uuid)
    return found
