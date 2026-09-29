"""Sign eligible AArch64 return addresses with non-hint PACIA/AUTIA pairs.

Opt-in (`--target-identification aarch64-bti-pac`). Runs in the normalize round,
before the transient copy is made, so both copies carry identical code and later
passes see the new instructions as ordinary application instructions.

Eligibility is conservative and never guesses: a function that fails any proof
keeps today's code. The return-lifetime proof reuses `ReturnSlotAnalysis` for
functions that save LR; slotless leaves need a separate proof because the slot
analysis returns early for them.
"""
from collections import Counter

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Patch, RewritingContext, patch_constraints

from teapot.configs.blacklist import is_blacklisted_function
from teapot.passes.common.return_slot_analysis import ReturnSlotAnalysis, UnsupportedReturnSlot

PACIA_X30_SP = 0xdac103fe
AUTIA_X30_SP = 0xdac113fe

PACIA_TEXT = ".arch_extension pauth\npacia x30, sp\n"
AUTIA_TEXT = ".arch_extension pauth\nautia x30, sp\n"


class AArch64SignReturnAddressesPass:
    """Insert one entry PACIA and one AUTIA before every exit of eligible functions."""

    def __init__(self, arch, decoder):
        self.arch = arch
        self.decoder = decoder
        self.signed_functions = []
        self.skipped = Counter()
        self.cfi_skipped = 0

    def begin_module(self, module, functions, rewriting_ctx: RewritingContext = None):
        self.module = module
        self.rewriting_ctx = rewriting_ctx
        self.text_section = next(section for section in module.sections if section.name == ".text")
        eligible, total = [], 0
        for function in sorted(functions, key=self._entry_address):
            if any(block.section is not self.text_section for block in function.get_all_blocks()):
                self.skipped["outside text"] += 1
                continue
            if is_blacklisted_function(function):
                self.skipped["blacklisted"] += 1
                continue
            total += 1
            reason, plan = self._analyze(function)
            if reason is not None:
                self.skipped[reason] += 1
                continue
            eligible.append((function, plan))
        for function, plan in eligible:
            self._insert(*plan["entry"], PACIA_TEXT)
            for block, offset in plan["exits"]:
                self._insert(block, offset, AUTIA_TEXT)
            self.signed_functions.append(function.uuid)
        print(f"[teapot] signed return addresses in {len(eligible)} of {total} functions",
              flush=True)
        for reason, count in self.skipped.most_common():
            print(f"[teapot]   signed-return skip ({reason}): {count}", flush=True)

    def end_module(self, module, functions):
        """Add the RA-state CFI toggles after every inserted PACIA/AUTIA."""
        aux = module.aux_data.get("cfiDirectives")
        if aux is None:
            self.cfi_skipped = len(self.signed_functions)
            return
        procedures = set()
        for offset, directives in aux.data.items():
            if any(name == ".cfi_startproc" for name, _, _ in directives):
                if isinstance(offset.element_id, gtirb.CodeBlock):
                    procedures.add(offset.element_id.uuid)
        decoder = GtirbInstructionDecoder(module.isa)
        wanted = set(self.signed_functions)
        for function in functions:
            if function.uuid not in wanted:
                continue
            if not any(block.uuid in procedures for block in function.get_all_blocks()):
                self.cfi_skipped += 1
                continue
            for block in function.get_all_blocks():
                for instruction in decoder.get_instructions(block):
                    word = int.from_bytes(instruction.bytes, "little")
                    if word not in (PACIA_X30_SP, AUTIA_X30_SP):
                        continue
                    offset = gtirb.Offset(block, instruction.address - block.address + instruction.size)
                    aux.data[offset] = list(aux.data.get(offset, [])) + [
                        (".cfi_escape", [0x2d], module.uuid)]
        if self.cfi_skipped:
            print(f"[teapot]   signed returns without a CFI procedure: {self.cfi_skipped}",
                  flush=True)

    @staticmethod
    def _padding_block(block, entries):
        """Edgeless all-NOP alignment that DDisasm attributed to this function."""
        if block in entries or list(block.incoming_edges) or block.size <= 0 or block.size % 4:
            return False
        return bytes(block.contents) == b"\x1f\x20\x03\xd5" * (block.size // 4)

    @staticmethod
    def _entry_address(function):
        entries = list(function.get_entry_blocks())
        if not entries or entries[0].address is None:
            return (1, 0)
        return (0, entries[0].address)

    def _insert(self, block, offset, text):
        decoded = list(self.decoder.get_instructions(block))
        offset = self.arch.adjust_insertion_offset(block, offset, decoded)

        @patch_constraints()
        def patch(_ctx):
            return text

        self.rewriting_ctx.insert_at(block, offset, Patch.from_function(patch))

    def _analyze(self, function):
        blocks = set(function.get_all_blocks())
        entries = set(function.get_entry_blocks())
        if len(entries) != 1:
            return "multiple function entries", None
        entry = next(iter(entries))
        # DDisasm can attach unreachable inter-function alignment to the
        # preceding function; the DWARF ABI consumer already permits only a
        # contiguous, edgeless NOP tail. Such a block is not an exit and must
        # not disqualify the function.
        blocks = {block for block in blocks if not self._padding_block(block, entries)}
        instructions = {}
        for block in blocks:
            decoded = tuple(self.decoder.get_instructions(block))
            if sum(inst.size for inst in decoded) != block.size:
                return "incomplete instruction decoding", None
            instructions[block] = decoded
            for inst in decoded:
                if inst.size == 4 and self.arch.is_pac_word(int.from_bytes(inst.bytes, "little")):
                    return "native PAC/BTI already present", None
        for block in blocks:
            for edge in block.incoming_edges:
                source = edge.source if isinstance(edge.source, gtirb.CodeBlock) else None
                if block is entry:
                    if source in blocks:
                        return "an edge from inside reaches the entry", None
                elif (source is not None and source not in blocks and
                      edge.label.type != gtirb.Edge.Type.Return):
                    # Callee return sites legitimately land in interior blocks
                    # (ReturnSlotAnalysis exempts Return edges for the same
                    # reason). Only a real branch/call entry is not modelable.
                    return "unmodeled interior function entry", None
        exits = {}
        for block, decoded in instructions.items():
            if not decoded:
                return "empty block", None
            last = decoded[-1]
            for edge in block.outgoing_edges:
                edge_type = edge.label.type
                if edge_type == gtirb.Edge.Type.Call:
                    continue
                if edge_type == gtirb.Edge.Type.Fallthrough:
                    if edge.target not in blocks:
                        return "falls through out of the function", None
                elif edge_type == gtirb.Edge.Type.Return:
                    if last.mnemonic.lower() != "ret" or last.op_str.strip() not in ("", "x30"):
                        return "return does not use x30", None
                    exits[block] = "return"
                elif edge_type == gtirb.Edge.Type.Branch:
                    if edge.label.direct:
                        if edge.target not in blocks:
                            if last.mnemonic.lower() != "b":
                                return "non-call branch leaves the function", None
                            exits[block] = "tail"
                    elif edge.target not in blocks:
                        return "unresolved indirect branch lifetime", None
                else:
                    return "unsupported leaving edge", None
        for block, decoded in instructions.items():
            if block in exits:
                continue
            outgoing = list(block.outgoing_edges)
            if any(edge.label.type == gtirb.Edge.Type.Call for edge in outgoing):
                continue  # a call with no continuation is not a function exit
            if any(edge.label.type in (gtirb.Edge.Type.Fallthrough, gtirb.Edge.Type.Branch,
                                       gtirb.Edge.Type.Return) for edge in outgoing):
                continue  # classified above
            last = decoded[-1]
            if last.mnemonic.lower() == "ret" and last.op_str.strip() in ("", "x30"):
                exits[block] = "return"
            else:
                return "exit without return or tail call", None
        if not exits:
            return "no return or tail-call exit", None

        try:
            sites = ReturnSlotAnalysis(self.arch, self.decoder).analyze(
                function, accept_pac=True)
        except UnsupportedReturnSlot as error:
            return f"return lifetime: {error}", None
        if sites:
            allowed_reads = set()
            for site in sites:
                key = (site.block, site.instruction_index - 1 if site.poison
                       else site.instruction_index)
                allowed_reads.add(key)
        else:
            reason = self._leaf_proof(function, entry, instructions)
            if reason is not None:
                return reason, None
            allowed_reads = set()
        reason = self._x30_read_check(function, instructions, exits, allowed_reads)
        if reason is not None:
            return reason, None
        plan = {"entry": (entry, 0), "exits": []}
        for block in exits:
            decoded = instructions[block]
            plan["exits"].append((block, sum(inst.size for inst in decoded[:-1])))
        return None, plan

    def _leaf_proof(self, function, entry, instructions):
        """Slotless-leaf proof: no calls, LR untouched, SP restored at exits."""
        sp, fp, link = self.arch.saved_return_registers()
        successors, exits = {}, set()
        for block in instructions:
            following = set()
            for edge in block.outgoing_edges:
                if edge.label.type == gtirb.Edge.Type.Call:
                    return "leaf proof: function contains a call"
                if edge.label.type == gtirb.Edge.Type.Return or edge.target not in instructions:
                    exits.add(block)
                else:
                    following.add(edge.target)
            successors[block] = following
        incoming = {entry: {sp: 0, fp: None}}
        queue = [entry]
        while queue:
            block = queue.pop(0)
            frame = incoming[block].copy()
            for inst in instructions[block]:
                assignment = self.arch.stack_register_assignment(inst)
                frame = self._frame_after(frame, self.arch.access_registers(self.arch.abi, inst, 1),
                                          assignment)
                if (self.arch.abi.is_call_instruction(inst) or
                        (link in self.arch.access_registers(self.arch.abi, inst, 1) and
                         inst.mnemonic.lower() != "ret")):
                    return "leaf proof: x30 is written"
            for target in successors[block]:
                previous = incoming.get(target)
                merged = frame.copy() if previous is None else {
                    reg: value if value == frame[reg] else None for reg, value in previous.items()}
                if previous != merged:
                    incoming[target] = merged
                    queue.append(target)
        for block in exits:
            frame = incoming.get(block)
            if frame is None:
                return "leaf proof: unreachable exit"
            final = frame.copy()
            for inst in instructions[block]:
                final = self._frame_after(final, self.arch.access_registers(self.arch.abi, inst, 1),
                                          self.arch.stack_register_assignment(inst))
            if final[sp] != 0:
                return "leaf proof: exit does not restore SP"
        return None

    def _x30_read_check(self, function, instructions, exits, allowed_reads):
        _, _, link = self.arch.saved_return_registers()
        for block, decoded in instructions.items():
            for index, inst in enumerate(decoded):
                if link not in self.arch.access_registers(self.arch.abi, inst, 0):
                    continue
                if (block, index) in allowed_reads or self.arch.is_pac_word(
                        int.from_bytes(inst.bytes, "little")):
                    continue
                if inst.mnemonic.lower() == "ret" and block in exits:
                    continue
                return "x30 is read while holding the incoming return address"
        return None

    @staticmethod
    def _frame_after(frame, writes, assignment):
        result = {reg: None if reg in writes else offset for reg, offset in frame.items()}
        if assignment is not None:
            dst, src, delta = assignment
            if dst in frame:
                source = frame.get(src)
                result[dst] = None if source is None else source + delta
        return result
