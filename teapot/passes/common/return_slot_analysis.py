from collections import deque
from dataclasses import dataclass

import gtirb
from gtirb_rewriting.assembly import Register


class UnsupportedReturnSlot(ValueError):
    pass


@dataclass(frozen=True)
class ReturnSlotSite:
    block: gtirb.CodeBlock
    instruction_index: int
    base: Register
    displacement: int
    poison: bool


class ReturnSlotAnalysis:
    """Prove one explicit saved-return lifetime using instructions and the CFG.

    Stack/frame offsets are relative to the incoming SP. Unknown or conflicting
    offsets are not guessed from unwind rows, which describe recovery rules,
    not the positions of the stores and reloads being instrumented.
    """

    def __init__(self, arch, decoder):
        self.arch = arch
        self.decoder = decoder
        self.sp, self.fp, self.link = arch.saved_return_registers()

    def analyze(self, function, *, checkpoint_sources=(), accept_pac=False):
        """Prove one saved-return lifetime. With accept_pac, PAC signing and
        authentication instructions are transparent to the incoming LR
        (matching the signed-return mode); the caller must still gate this to
        the mode that inserts them."""
        self.accept_pac = accept_pac
        blocks = set(function.get_all_blocks())
        entries = set(function.get_entry_blocks())
        if len(entries) != 1:
            raise UnsupportedReturnSlot("multiple function entries")
        entry = next(iter(entries))
        instructions = {block: tuple(self.decoder.get_instructions(block)) for block in blocks}
        if any(sum(inst.size for inst in decoded) != block.size for block, decoded in instructions.items()):
            raise UnsupportedReturnSlot("incomplete instruction decoding")

        accesses, writes, assignments, calls = {}, {}, {}, set()
        saves, reloads = [], []
        link_used = False
        for block, decoded in instructions.items():
            for index, inst in enumerate(decoded):
                key = block, index
                access = self.arch.stack_memory_access(inst)
                accesses[key] = access
                writes[key] = self.arch.access_registers(self.arch.abi, inst, 1)
                assignments[key] = self.arch.stack_register_assignment(inst)
                if self.arch.abi.is_call_instruction(inst):
                    calls.add(key)
                if not self.arch.is_control_transfer_instruction(inst) and not self._pac(inst):
                    link_used |= self.link in writes[key] or self.link in self.arch.access_registers(
                        self.arch.abi, inst, 0)
                if access is None or access.return_offset is None:
                    continue
                mem = self.arch.memory_operand(inst)
                read = self.arch.mem_operand_is_read(inst, mem)
                write = self.arch.mem_operand_is_write(inst, mem)
                if read == write:
                    raise UnsupportedReturnSlot("unsupported saved-return memory operation")
                (saves if write else reloads).append(key)
        if not saves and not reloads and not calls and not link_used:
            return ()
        if len(saves) != 1 or not reloads:
            raise UnsupportedReturnSlot("requires one memory save and matching reloads")

        successors, exits = {}, set()
        for block in blocks:
            if block.section is not entry.section:
                raise UnsupportedReturnSlot("function spans instrumentation sections")
            for edge in block.incoming_edges:
                checkpoint_entry = (isinstance(edge.source, gtirb.CodeBlock) and
                                    edge.source.section in checkpoint_sources)
                if (edge.source not in blocks and block is not entry and
                        edge.label.type != gtirb.Edge.Type.Return and not checkpoint_entry):
                    raise UnsupportedReturnSlot("unmodeled interior function entry")
            following = set()
            transfers_to_callee = False
            for edge in block.outgoing_edges:
                if edge.label.type == gtirb.Edge.Type.Call:
                    transfers_to_callee = True
                    if any(symbol.name.startswith(("__riscv_save_", "__riscv_restore_"))
                           for symbol in edge.target.references):
                        raise UnsupportedReturnSlot("out-of-line register save/restore helper")
                    continue
                # A resolved indirect branch, such as a switch dispatch, keeps
                # every target inside the function, so its lifetime is still
                # trackable. Only an edge leaving the analysed blocks is not.
                if (edge.label.type == gtirb.Edge.Type.Branch and not edge.label.direct and
                        edge.target not in blocks):
                    raise UnsupportedReturnSlot("unresolved indirect branch lifetime")
                if edge.label.type == gtirb.Edge.Type.Return or edge.target not in blocks:
                    exits.add(block)
                else:
                    following.add(edge.target)
            successors[block] = following
            # A block whose only transfer is a call does not continue here: the
            # callee does not return, which is why the frontend gave the block
            # no fallthrough. It is not a function exit, so it must not be asked
            # to have restored the return slot.
            if not following and not transfers_to_callee:
                exits.add(block)

        # Constant-offset propagation converges by dropping conflicting values.
        incoming = {entry: {self.sp: 0, self.fp: None}}
        queue = deque([entry])
        while queue:
            block = queue.popleft()
            frame = incoming[block].copy()
            for index in range(len(instructions[block])):
                frame = self._frame_after(frame, writes[block, index], assignments[block, index])
            for target in successors[block]:
                previous = incoming.get(target)
                merged = frame.copy() if previous is None else {
                    reg: value if value == frame[reg] else None for reg, value in previous.items()}
                if previous != merged:
                    incoming[target] = merged
                    queue.append(target)

        before, after = {}, {}
        for block, initial in incoming.items():
            frame = initial.copy()
            for index in range(len(instructions[block])):
                key = block, index
                before[key] = frame
                frame = self._frame_after(frame, writes[key], assignments[key])
                after[key] = frame
        if any(key not in before for key in saves + reloads):
            raise UnsupportedReturnSlot("unreachable save or reload")

        save = saves[0]
        slot = self._address(accesses[save], before[save])
        if slot is None:
            raise UnsupportedReturnSlot("unknown save-slot address")
        slot += accesses[save].return_offset
        if slot % 8 or slot + 8 > 0:
            raise UnsupportedReturnSlot("return slot is unaligned or outside the callee frame")
        for key in reloads:
            address = self._address(accesses[key], before[key])
            if address is None or address + accesses[key].return_offset != slot:
                raise UnsupportedReturnSlot("reload does not name the saved slot")
        identified = {save, *reloads}
        # FP is also an ordinary callee-saved GPR, particularly on RV64.
        # Unknown FP accesses only denote an unresolved frame when this
        # function actually derives FP from SP; saved-slot addresses themselves
        # always require a concrete, matching offset above.
        frame_bases = {self.sp}
        if any(assignment is not None and assignment[0] is not None and assignment[1] is not None and
               assignment[:2] == (self.fp, self.sp)
               for assignment in assignments.values()):
            frame_bases.add(self.fp)
        for key, frame in before.items():
            access = accesses[key]
            if access is None or access.base not in frame_bases:
                continue
            address = self._address(access, frame)
            if address is None or access.size <= 0:
                raise UnsupportedReturnSlot("unresolved stack access")
            if key not in identified and address < slot + 8 and slot < address + access.size:
                raise UnsupportedReturnSlot("another instruction accesses the return slot")

        # Keep a small set of lifetime states at joins, so shrink-wrapped paths
        # that never saved LR can meet restored paths without inventing a save.
        states = {entry: {(0, True)}}
        queue = deque([entry])
        while queue:
            block = queue.popleft()
            outgoing = set()
            for phase, original_link in states[block]:
                for index in range(len(instructions[block])):
                    key = block, index
                    if key == save:
                        if phase != 0 or not original_link:
                            raise UnsupportedReturnSlot("save is repeated or no longer holds incoming LR")
                        phase = 1
                    elif key in reloads:
                        if phase != 1:
                            raise UnsupportedReturnSlot("reload is not dominated by its save")
                        phase, original_link = 2, True
                    elif key in calls or (self.link in writes[key] and
                                          not self.arch.is_control_transfer_instruction(instructions[block][index]) and
                                          not self._pac(instructions[block][index])):
                        # The operand-access fallback can mark JR's sole
                        # operand as written. A non-linking transfer cannot
                        # replace the return address; calls still do.
                        original_link = False
                    if phase == 1 and (after[key][self.sp] is None or after[key][self.sp] > slot):
                        raise UnsupportedReturnSlot("active return slot has no stable allocated frame")
                final_frame = after[block, len(instructions[block]) - 1] if instructions[block] else incoming[block]
                if block in exits and (phase == 1 or not original_link or final_frame[self.sp] != 0):
                    raise UnsupportedReturnSlot("exit does not restore LR and its stack frame")
                outgoing.add((phase, original_link))
            for target in successors[block]:
                merged = states.get(target, set()) | outgoing
                if states.get(target) != merged:
                    states[target] = merged
                    queue.append(target)

        sites = []
        for key in (save, *reloads):
            base = accesses[key].base
            poison = key == save
            frame = after[key] if poison else before[key]
            if frame[base] is None:
                raise UnsupportedReturnSlot("slot base is lost at the insertion boundary")
            sites.append(ReturnSlotSite(key[0], key[1] + int(poison), base, slot - frame[base], poison))
        return tuple(sites)

    def _pac(self, instruction) -> bool:
        return (self.accept_pac and instruction is not None and instruction.size == 4 and
                self.arch.is_pac_word(int.from_bytes(instruction.bytes, "little")))

    def _frame_after(self, frame, writes, assignment):
        result = {reg: None if reg in writes else offset for reg, offset in frame.items()}
        if assignment is not None:
            dst, src, delta = assignment
            if dst in frame:
                source = frame.get(src)
                result[dst] = None if source is None else source + delta
        return result

    @staticmethod
    def _address(access, frame):
        base = frame.get(access.base)
        return None if base is None or access.displacement is None else base + access.displacement
