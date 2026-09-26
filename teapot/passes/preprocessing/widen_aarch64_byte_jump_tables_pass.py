"""Keep byte-relative switch tables representable after code growth."""
from functools import lru_cache

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Pass
from gtirb_rewriting._modify.edit import edit_byte_interval

from teapot.arch.aarch64.control_flow import AARCH64_CALL_MNEMONICS
from teapot.utils.misc import symbol_address
from teapot.utils.return_abi import POINTER_RETURNS, has_pointer_return_contract



# AAPCS64 callee-saved general registers: preserved across every conforming call.
CALLEE_SAVED = frozenset(range(19, 29))

class WidenAArch64ByteJumpTablesPass(Pass):
    """Promote ADR(P)-based LDRB/ADR/ADD/BR switch idioms to 32-bit entries.

    The original signed-byte displacement is in instruction units. Instrumented
    case bodies can exceed that range even when GNU as accepts/truncates the
    resulting .byte. Preserve the symbolic destinations and divide-by-four
    scale, widen the table, and change both the indexed load and extension.

    Hoisted bases require one reaching address on every intrafunction path.
    Missing fields require an unsigned index bound and independently recovered
    CFG targets. This is not a decoder for arbitrary computed-jump idioms.
    """

    @staticmethod
    def _expression(instruction, block):
        return block.byte_interval.symbolic_expressions.get(
            block.offset + instruction.address - block.address)

    @staticmethod
    def _address(expression):
        if not isinstance(expression, gtirb.SymAddrConst):
            return None
        address = symbol_address(expression.symbol)
        return address + expression.offset if address is not None else None

    @staticmethod
    def _tables(module):
        widths = module.aux_data.get('symbolicExpressionSizes')
        if widths is None:
            return {}
        tables = {}
        for interval in module.byte_intervals:
            if interval.address is None:
                continue
            current = None
            for position, expression in sorted(interval.symbolic_expressions.items()):
                if not (isinstance(expression, gtirb.SymAddrAddr) and expression.scale == 4 and
                        expression.offset == 0 and not expression.attributes and
                        isinstance(expression.symbol1.referent, gtirb.CodeBlock) and
                        isinstance(expression.symbol2.referent, gtirb.CodeBlock) and
                        widths.data.get(gtirb.Offset(interval, position)) == 1):
                    current = None
                    continue
                if (current is None or position != current['end'] or
                        expression.symbol2 is not current['base']):
                    current = {'interval': interval, 'start': position, 'end': position,
                               'base': expression.symbol2, 'entries': [], 'consumers': [], 'signed': set()}
                    tables[interval.address + position] = current
                current['entries'].append((position, expression))
                current['end'] = position + 1
        return tables

    @staticmethod
    def _register_number(name):
        aliases = {'fp': 29, 'lr': 30, 'ip0': 16, 'ip1': 17}
        if name in aliases:
            return aliases[name]
        if len(name) > 1 and name[0] in ('x', 'w') and name[1:].isdigit():
            return int(name[1:])
        return None

    @staticmethod
    def _function(module, block):
        blocks = module.aux_data.get('functionBlocks')
        entries = module.aux_data.get('functionEntries')
        if blocks is None or entries is None:
            return None
        owners = [key for key, members in blocks.data.items() if block in members]
        if len(owners) != 1:
            return None
        key = owners[0]
        return blocks.data[key], entries.data.get(key, set())

    def _reaching_address(self, module, block, index, register, decoded):
        """Find all last definitions, including loop backedges; never guess.

        Revisiting an unchanged (block, instruction index) adds no definition.
        A pure cycle therefore proves nothing; an initialized invariant loop
        is accepted only when every terminal path supplies the same address.
        Calls terminate the proof unless the register is callee-saved under
        AAPCS64 (x19-x28), which every conforming callee preserves; unknown or
        external entry paths always terminate it.
        """
        context = self._function(module, block)
        pending, seen, definitions, references = [(block, index)], set(), set(), set()
        roots = set()
        while pending:
            current, stop = pending.pop()
            if (current, stop) in seen:
                continue
            seen.add((current, stop))
            instructions = decoded(current)
            if sum(i.size for i in instructions) != current.size:
                return None
            for position in range(stop - 1, -1, -1):
                inst = instructions[position]
                if inst.mnemonic in AARCH64_CALL_MNEMONICS:
                    if register in CALLEE_SAVED:
                        # AAPCS64: every conforming callee preserves x19-x28, so
                        # a hoisted base in one survives the call unchanged.
                        continue
                    return None
                writes = {self._register_number(inst.reg_name(r)) for r in inst.regs_access()[1]}
                if register not in writes:
                    continue
                word = int.from_bytes(inst.bytes, 'little')
                address = self._address(self._expression(inst, current))
                sites = (inst,)
                if inst.mnemonic == 'adr' and word & 31 == register and address is not None:
                    pass
                elif (inst.mnemonic == 'add' and word & 0xffc00000 == 0x91000000 and
                      word & 31 == register and address is not None and position > 0):
                    # The ADRP need not be adjacent: schedulers interleave unrelated
                    # instructions. It must be the nearest earlier write of the ADD's
                    # source register in this block; nothing between may write it.
                    source = (word >> 5) & 31
                    high = None
                    for earlier in range(position - 1, -1, -1):
                        candidate = instructions[earlier]
                        if (candidate.mnemonic in AARCH64_CALL_MNEMONICS and
                                source not in CALLEE_SAVED):
                            break
                        if source in {self._register_number(candidate.reg_name(r))
                                      for r in candidate.regs_access()[1]}:
                            high = candidate
                            break
                    if high is None:
                        return None
                    high_word = int.from_bytes(high.bytes, 'little')
                    if (high.mnemonic != 'adrp' or high_word & 31 != source or
                            self._address(self._expression(high, current)) != address):
                        return None
                    sites = high, inst
                else:
                    return None
                definitions.add(address)
                roots.add((current, position + 1, register))
                references.update((current.byte_interval, current.offset + i.address - current.address)
                                  for i in sites)
                break
            else:
                if context is None or current in context[1]:
                    return None
                parents = []
                for edge in current.incoming_edges:
                    if edge.label is not None and edge.label.type == gtirb.Edge.Type.Return:
                        # The caller's fallthrough path still crosses the call,
                        # which is conservatively a clobber above.
                        continue
                    if (edge.label is None or edge.label.type not in
                            (gtirb.Edge.Type.Branch, gtirb.Edge.Type.Fallthrough) or
                            not isinstance(edge.source, gtirb.CodeBlock) or edge.source not in context[0]):
                        return None
                    parents.append(edge.source)
                if not parents:
                    return None
                pending.extend((parent, len(decoded(parent))) for parent in parents)
        if len(definitions) != 1:
            return None
        return next(iter(definitions)), references, roots

    def _validate_base_uses(self, module, roots, loads, decoded):
        """A hoisted pointer may not also feed an unwidened byte-stride use.

        Follow each proven definition until it is overwritten. Reject pointer
        copies/escapes and unknown exits rather than widening only one user of
        an array. The recognized loads are the only permitted reads.
        """
        def call_input_effect(block, index, register, active=frozenset()):
            # Do not infer argument counts from a function's name. Inspect a
            # resolved callee before any read/copy/unknown transfer. True means
            # killed on every path, False means unread but may survive, and
            # None means no proof. A surviving value stays tracked at return.
            if index != len(decoded(block)) - 1 or len(active) >= 32:
                return None
            targets = [e.target for e in block.outgoing_edges if e.label is not None and
                       e.label.type == gtirb.Edge.Type.Call]
            if not targets:
                return None

            def combine(effects):
                return None if any(e is None for e in effects) else all(effects)

            def discards(current, visiting):
                if current in visiting or len(visiting) >= 32:
                    return None
                if isinstance(current, gtirb.ProxyBlock):
                    # Linux libc's void-argument errno accessor returns a new
                    # pointer in x0. Other volatile registers can survive, so
                    # keep tracking them in the caller. This is a system ABI
                    # summary, not an OpenSSL-function exception.
                    if register <= 18 and {s.name for s in current.references} == {'__errno_location'}:
                        return register == 0
                    return None
                if not isinstance(current, gtirb.CodeBlock):
                    return None
                instructions = decoded(current)
                if not instructions or sum(i.size for i in instructions) != current.size:
                    return None
                visiting = visiting | {current}
                for offset, inst in enumerate(instructions):
                    reads, writes = inst.regs_access()
                    if register in {self._register_number(inst.reg_name(r)) for r in reads}:
                        return None
                    if inst.mnemonic in AARCH64_CALL_MNEMONICS:
                        effect = call_input_effect(current, offset, register, visiting)
                        if effect is not False:
                            return effect
                    if inst.mnemonic in ('svc', 'hvc', 'smc'):
                        return None
                    if inst.mnemonic in ('ret', 'retaa', 'retab'):
                        return False
                    if register in {self._register_number(inst.reg_name(r)) for r in writes}:
                        return True
                successors = [edge for edge in current.outgoing_edges
                              if edge.label is None or edge.label.type != gtirb.Edge.Type.Call]
                if not successors or any(edge.label is None or edge.label.type not in
                        (gtirb.Edge.Type.Branch, gtirb.Edge.Type.Fallthrough) for edge in successors):
                    return None
                return combine([discards(edge.target, visiting) for edge in successors])

            return combine([discards(target, active) for target in targets])

        for root in roots:
            context = self._function(module, root[0])
            pending, seen = [root], set()
            while pending:
                block, start, register = pending.pop()
                if (block, start, register) in seen:
                    continue
                seen.add((block, start, register))
                instructions = decoded(block)
                if sum(i.size for i in instructions) != block.size:
                    raise ValueError('unproved byte jump-table base lifetime')
                for index in range(start, len(instructions)):
                    inst = instructions[index]
                    reads, writes = inst.regs_access()
                    if (register in {self._register_number(inst.reg_name(r)) for r in reads} and
                            (block, index, register) not in loads):
                        raise ValueError('unrecognized register use of widened byte jump-table base')
                    if (inst.mnemonic in AARCH64_CALL_MNEMONICS and
                            register not in CALLEE_SAVED):
                        # A callee-saved base is not an argument and survives the
                        # call (AAPCS64), so it stays tracked past it unchanged.
                        effect = call_input_effect(block, index, register)
                        if effect is True:
                            break
                        if effect is None:
                            raise ValueError('byte jump-table base x{} from {:#x} escapes through an unproved call at {:#x}'.format(
                                register, root[0].address, inst.address))
                    if inst.mnemonic in ('svc', 'hvc', 'smc'):
                        raise ValueError('byte jump-table base escapes through a system call')
                    if register in {self._register_number(inst.reg_name(r)) for r in writes}:
                        break
                    if inst.mnemonic in ('ret', 'retaa', 'retab'):
                        if register in (0, 1):
                            owners = [key for key, members in module.aux_data['functionBlocks'].data.items()
                                      if block in members]
                            # A debug-backed, object-bound pointer return uses
                            # x0 under AAPCS64. Never infer this from the name,
                            # observed callers, or a generic liveness mask.
                            if not (register == 1 and len(owners) == 1 and
                                    has_pointer_return_contract(module, owners[0])):
                                raise ValueError('byte jump-table base x{} from {:#x} escapes through a return value at {:#x}'.format(
                                    register, root[0].address, inst.address))
                        break
                else:
                    successors = []
                    for edge in block.outgoing_edges:
                        if edge.label is not None and edge.label.type == gtirb.Edge.Type.Call:
                            continue
                        if (context is None or edge.label is None or edge.label.type not in
                                (gtirb.Edge.Type.Branch, gtirb.Edge.Type.Fallthrough) or
                                not isinstance(edge.target, gtirb.CodeBlock) or edge.target not in context[0]):
                            raise ValueError('unproved byte jump-table base exit')
                        successors.append(edge.target)
                    if not successors:
                        # A block ending in a call with no fallthrough (DDisasm's
                        # no-return analysis, e.g. abort) ends every path through it.
                        if instructions and instructions[-1].mnemonic in AARCH64_CALL_MNEMONICS:
                            continue
                        raise ValueError('unproved byte jump-table base lifetime')
                    pending.extend((successor, 0, register) for successor in successors)

    @staticmethod
    def _index_bound(block, index, load_word, decoded):
        # A W-register bound does not constrain the high half of an X index.
        if (load_word >> 13) & 7 not in (2, 6) or any(i.mnemonic != 'nop' for i in decoded(block)[:index]):
            return None
        counts = set()
        for edge in block.incoming_edges:
            if (edge.label is None or edge.label.type != gtirb.Edge.Type.Fallthrough or
                    not edge.label.conditional or not isinstance(edge.source, gtirb.CodeBlock)):
                return None
            instructions = decoded(edge.source)
            if len(instructions) < 2 or instructions[-1].mnemonic != 'b.hi':
                return None
            compare = instructions[-2]
            word = int.from_bytes(compare.bytes, 'little')
            if (compare.mnemonic != 'cmp' or word & 0xffc0001f != 0x7100001f or
                    (word >> 5) & 31 != (load_word >> 16) & 31):
                return None
            if not any(e.label is not None and e.label.type == gtirb.Edge.Type.Branch and
                       e.label.conditional and e.label.direct and e.target is not block
                       for e in edge.source.outgoing_edges):
                return None
            counts.add(((word >> 10) & 4095) + 1)
        return next(iter(counts)) if len(counts) == 1 and max(counts) <= 256 else None

    def _recover_table(self, module, block, address, base, count, signed, pending_symbols):
        if count is None:
            raise ValueError('partial byte jump table lacks a proven unsigned index bound at ' + hex(address))
        context = self._function(module, block)
        if context is None:
            raise ValueError('partial byte jump table has ambiguous function ownership')
        intervals = [bi for bi in module.byte_intervals if bi.address is not None and
                     bi.address <= address < address + count <= bi.address + len(bi.contents)]
        if len(intervals) != 1:
            raise ValueError('bounded byte jump table lacks initialized data')
        interval = intervals[0]
        start = address - interval.address
        widths = module.aux_data['symbolicExpressionSizes'].data
        for position in interval.symbolic_expressions:
            if position >= start + count:
                continue
            width = widths.get(gtirb.Offset(interval, position))
            if width is None or (position + width > start and (width != 1 or position < start)):
                raise ValueError('partial byte jump table overlaps an unproved symbolic field')
        targets = {e.target for e in block.outgoing_edges if e.label is not None and
                   e.label.type == gtirb.Edge.Type.Branch and not e.label.direct}
        table = {'interval': interval, 'start': start, 'end': start + count, 'base': base,
                 'entries': [], 'consumers': [], 'signed': set()}
        base_address = symbol_address(base)
        for position in range(start, start + count):
            byte = interval.contents[position]
            value = byte - 256 if signed and byte & 128 else byte
            destination = base_address + 4 * value
            candidates = [b for b in targets if isinstance(b, gtirb.CodeBlock) and
                          b in context[0] and b.address == destination]
            if len(candidates) != 1:
                raise ValueError('partial byte jump-table target lacks matching intrafunction CFG evidence')
            target = candidates[0]
            expression = interval.symbolic_expressions.get(position)
            if expression is not None:
                if (not isinstance(expression, gtirb.SymAddrAddr) or expression.scale != 4 or
                        expression.offset or expression.attributes or
                        symbol_address(expression.symbol1) != destination or
                        symbol_address(expression.symbol2) != base_address):
                    raise ValueError('byte jump-table expression disagrees with its bounded lookup')
            else:
                symbol = next((s for s in target.references if not s.at_end), None)
                if symbol is None:
                    if target not in pending_symbols:
                        name = '.L__teapot_table_target_' + target.uuid.hex
                        if next(module.symbols_named(name), None) is not None:
                            raise ValueError('reserved byte jump-table target symbol collision')
                        pending_symbols[target] = gtirb.Symbol(name=name, payload=target)
                    symbol = pending_symbols[target]
                expression = gtirb.SymAddrAddr(4, 0, symbol, base)
            table['entries'].append((position, expression))
        return table

    def end_module(self, module, functions):
        if module.isa != gtirb.Module.ISA.ARM64:
            return
        tables = self._tables(module)
        decoder = GtirbInstructionDecoder(module.isa)

        @lru_cache(maxsize=1024)
        def decoded(block):
            return tuple(decoder.get_instructions(block))

        allowed_references = set()
        base_roots, allowed_loads = set(), set()
        pending_symbols = {}
        replacements = []
        for block in module.code_blocks:
            instructions = decoded(block)
            for index in range(len(instructions) - 3):
                seq = instructions[index:index + 4]
                if [i.mnemonic for i in seq] != ['ldrb', 'adr', 'add', 'br']:
                    continue
                load, base, add, branch = seq
                load_word, base_word, add_word, branch_word = [
                    int.from_bytes(i.bytes, 'little') for i in seq]
                table_reg, loaded_reg, base_reg = (load_word >> 5) & 31, load_word & 31, base_word & 31
                # Register-offset LDRB; 64-bit extended ADD; matching BR.
                if (table_reg == 31 or base_reg == 31 or loaded_reg in (31, base_reg) or
                        load_word & 0xffe00c00 != 0x38600800 or
                        add_word & 0xffe00000 != 0x8b200000 or
                        (add_word >> 5) & 31 != base_reg or (add_word >> 16) & 31 != loaded_reg or
                        (add_word >> 10) & 7 != 2 or (add_word >> 13) & 7 not in (0, 4) or
                        add_word & 31 == 31 or (branch_word >> 5) & 31 != add_word & 31):
                    raise ValueError('unsupported byte jump-table register/extension form at ' + hex(load.address))
                if any(self._expression(i, block) is not None for i in (load, add, branch)):
                    raise ValueError('unexpected relocation on byte jump-table lookup')
                base_expression = self._expression(base, block)
                if (not isinstance(base_expression, gtirb.SymAddrConst) or base_expression.offset or
                        base_expression.attributes or
                        not isinstance(base_expression.symbol.referent, gtirb.CodeBlock) or
                        symbol_address(base_expression.symbol) is None):
                    raise ValueError('unproved code base for byte jump table at ' + hex(load.address))
                reaching = self._reaching_address(module, block, index, table_reg, decoded)
                if reaching is None:
                    raise ValueError('unproved table base for byte jump table at ' + hex(load.address))
                address, references, roots = reaching
                count = self._index_bound(block, index, load_word, decoded)
                signed = bool((add_word >> 13) & 4)
                table = tables.get(address)
                if table is not None and symbol_address(table['base']) != symbol_address(base_expression.symbol):
                    raise ValueError('incompatible code bases for shared byte jump table')
                if table is None or (count is not None and len(table['entries']) < count):
                    recovered = self._recover_table(module, block, address, base_expression.symbol,
                                                    count, signed, pending_symbols)
                    if table is not None:
                        recovered['consumers'] = table['consumers']
                        recovered['signed'] = table['signed']
                    table = tables[address] = recovered
                # Size=32 bits and S=1 makes the index stride four bytes. SXT[B]
                # or UXT[B] becomes SXT[W] or UXT[W], retaining the #2 scale.
                new_load = load_word | (2 << 30) | (1 << 12)
                new_add = (add_word & ~(7 << 13)) | (((add_word >> 13) & 4 | 2) << 13)
                for instruction, word in ((load, new_load), (add, new_add)):
                    position = block.offset + instruction.address - block.address
                    replacements.append((block.byte_interval, position, word.to_bytes(4, 'little')))
                table['consumers'].append(load.address)
                table['signed'].add(signed)
                allowed_references.update(references)
                base_roots.update(roots)
                allowed_loads.add((block, index, table_reg))

        selected = [table for table in tables.values() if table['consumers']]
        if not selected:
            module.aux_data.pop(POINTER_RETURNS, None)
            return
        self._validate_base_uses(module, base_roots, allowed_loads, decoded)
        selected.sort(key=lambda table: table['interval'].address + table['start'])
        for previous, table in zip(selected, selected[1:]):
            if previous['interval'].address + previous['end'] > table['interval'].address + table['start']:
                raise ValueError('overlapping byte jump-table extents')
        # Never silently resize an array also accessed with an unrecognized
        # byte stride or via a separately stored pointer/interior address.
        for interval in module.byte_intervals:
            for position, expression in interval.symbolic_expressions.items():
                addresses = {self._address(expression)}
                addresses.update(symbol_address(symbol) for symbol in expression.symbols)
                for address in addresses - {None}:
                    for table in selected:
                        begin = table['interval'].address + table['start']
                        end = table['interval'].address + table['end']
                        if begin <= address < end and (interval, position) not in allowed_references:
                            raise ValueError('unrecognized reference to widened byte jump table at ' + hex(address))

        entries = []
        data_owners = set()
        padding = []
        alignments = module.aux_data.get('alignment')
        alignments = alignments.data if alignments is not None else {}
        for table in selected:
            interval = table['interval']
            for position, expression in table['entries']:
                owners = [block for block in interval.blocks
                          if block.offset <= position < block.offset + block.size]
                if len(owners) != 1 or not isinstance(owners[0], gtirb.DataBlock):
                    raise ValueError('byte jump-table entry lacks unique data ownership')
                data_owners.add(owners[0])
                difference = symbol_address(expression.symbol1) - symbol_address(expression.symbol2)
                if difference % 4 or not -(1 << 31) <= difference // 4 < (1 << 31):
                    raise ValueError('byte jump-table target is not a signed 32-bit instruction offset')
                value = difference // 4
                if (interval.contents[position] != value & 255 or
                        any(not (-128 <= value <= 127 if signed else 0 <= value <= 255)
                            for signed in table['signed'])):
                    raise ValueError('byte jump-table expression disagrees with its original lookup')
                entries.append((interval, position, expression, value))

            # Scaled AArch64 LO12 loads require 2/4/8/16-byte alignment even
            # when the frontend did not annotate their data blocks. Keep the
            # suffix's original residue modulo 16, or a stronger explicit
            # interval/suffix alignment. Merely widening N bytes by 3*N can
            # otherwise misalign every later constant in the same interval.
            requirements = [16, alignments.get(interval, 1)]
            requirements.extend(alignments.get(block, 1) for block in interval.blocks
                                if block.offset >= table['end'])
            if any(a < 1 or a & (a - 1) for a in requirements):
                raise ValueError('non-power-of-two data alignment at widened byte jump table')
            growth = 3 * len(table['entries'])
            pad = -growth % max(requirements)
            if pad:
                padding.append((interval, table['end'], pad))

        # Validate everything before changing any bytes. Code edits preserve
        # instruction count, register dependencies, CFG, and liveness offsets.
        for symbol in pending_symbols.values():
            module.symbols.add(symbol)
            if 'elfSymbolInfo' in module.aux_data:
                module.aux_data['elfSymbolInfo'].data[symbol] = (0, 'NOTYPE', 'LOCAL', 'DEFAULT', 1)
        if 'encodings' in module.aux_data:
            for owner in data_owners:
                module.aux_data['encodings'].data.pop(owner, None)
        for interval, position, content in replacements:
            interval.contents[position:position + 4] = content
        edits = [(interval, position, expression, value) for interval, position, expression, value in entries]
        edits.extend((interval, position, None, pad) for interval, position, pad in padding)
        for interval, position, expression, value in sorted(edits, key=lambda row: row[1], reverse=True):
            if expression is None:
                owned = any(b.offset < position < b.offset + b.size for b in interval.blocks)
                edit_byte_interval(interval, position, 0, bytes(value))
                if not owned:
                    gtirb.DataBlock(offset=position, size=value, byte_interval=interval)
                continue
            edit_byte_interval(interval, position, 1, value.to_bytes(4, 'little', signed=True))
            interval.symbolic_expressions[position] = expression
            # edit_byte_interval can replace the AuxData's underlying map.
            module.aux_data['symbolicExpressionSizes'].data[gtirb.Offset(interval, position)] = 4
        print('[teapot] widened {} AArch64 byte jump tables ({} entries)'.format(
            len(selected), len(entries)), flush=True)
        # These contracts describe the pre-normalization body. Do not emit
        # stale evidence after code/data mutation or normal/transient copying.
        module.aux_data.pop(POINTER_RETURNS, None)
