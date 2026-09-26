"""Symbolize page-offset users of a split AArch64 ADRP that DDisasm left raw.

A compiler can hoist one `adrp Xn, page` and reuse Xn in several blocks, e.g. in the cases
of a jump-table switch (`add x22, x22, #0xab8` in each case of OpenSSL's test_evp_iv_aes).
DDisasm symbolizes the ADRP and the users it pairs, but can leave other users with a raw
low-12-bit immediate. After rewriting, the ADRP's page follows the symbol while the raw
immediate keeps the original low bits, so the user computes a wrong address, silently.

For each ADRP with a plain page expression `S + a` (no GOT/LO12 attributes), follow its
register over the intra-procedural CFG to every `add Xd, Xn, #imm` (unshifted) or load/store
with base Xn and an immediate offset that has no symbolic expression. Such a user is given
`:lo12:(S + a)` only if
  * its original target (page + imm) is exactly S + a, and
  * every definition of Xn reaching it (backwards over all predecessors; calls are crossed
    only for callee-saved x19-x28) is an ADRP with the same expression.
Anything else is left unchanged. Runs before instrumentation, so both copies get it.
"""
import gtirb
from capstone import CS_OP_IMM, CS_OP_REG

from teapot.arch.aarch64.operands import aarch64_base_register_writeback, aarch64_data_memory_operands

CALLEE_SAVED = frozenset(range(19, 29))
LO12 = gtirb.SymbolicExpression.Attribute.LO12


def _regnum(name):
    if name is None:
        return None
    aliases = {'fp': 29, 'lr': 30}
    if name in aliases:
        return aliases[name]
    if len(name) > 1 and name[0] in 'xw' and name[1:].isdigit():
        return int(name[1:])
    return None


def _symbol_address(symbol):
    if symbol.value is not None:
        return symbol.value
    referent = symbol.referent
    if not isinstance(referent, gtirb.ByteBlock) or referent.address is None:
        return None
    return referent.address + (referent.size if symbol.at_end else 0)


class _Module:
    def __init__(self, module, decoder):
        self.module = module
        self.decoder = decoder
        self.cache = {}

    def insns(self, block):
        if block not in self.cache:
            self.cache[block] = list(self.decoder.get_instructions(block))
        return self.cache[block]

    @staticmethod
    def symexpr(block, inst):
        interval = block.byte_interval
        return interval.symbolic_expressions.get(inst.address - interval.address)

    @staticmethod
    def access(inst):
        return tuple({_regnum(inst.reg_name(r)) for r in regs} for regs in inst.regs_access())


def _page_offset(inst, reg):
    """Immediate page offset if inst uses reg as an ADRP page base, else None."""
    ops = inst.operands
    if inst.mnemonic == 'add' and len(ops) == 3 and ops[1].type == CS_OP_REG and \
            _regnum(inst.reg_name(ops[1].reg)) == reg and ops[2].type == CS_OP_IMM:
        shift = ops[2].shift
        if getattr(shift, 'type', 0) and getattr(shift, 'value', 0):
            return None
        return ops[2].imm if 0 <= ops[2].imm < 4096 else None
    memory = aarch64_data_memory_operands(inst)
    if len(memory) == 1 and _regnum(inst.reg_name(memory[0].mem.base)) == reg and \
            not memory[0].mem.index and not aarch64_base_register_writeback(inst) and 0 <= memory[0].mem.disp < 4096:
        return memory[0].mem.disp
    return None


def _definition_key(state, block, inst):
    """(symbol, addend) if inst is an ADRP with a plain page expression."""
    if inst.mnemonic != 'adrp':
        return None
    expr = state.symexpr(block, inst)
    if not isinstance(expr, gtirb.SymAddrConst) or expr.attributes:
        return None
    return expr.symbol, expr.offset


def _reaching_definitions(state, block, index, reg):
    """Set of definition keys reaching (block, index), or None if any is not an ADRP key."""
    found = set()
    work = [(block, index)]
    visited = set()
    while work:
        current, end = work.pop()
        if (current, end) in visited:
            continue
        visited.add((current, end))
        stream = state.insns(current)
        defined = False
        for position in range(end - 1, -1, -1):
            inst = stream[position]
            reads, writes = state.access(inst)
            if reg in writes:
                key = _definition_key(state, current, inst)
                if key is None:
                    return None
                found.add(key)
                defined = True
                break
            if inst.mnemonic in ('bl', 'blr') and position != end - 1 and reg not in CALLEE_SAVED:
                return None
        if defined:
            continue
        predecessors = []
        for edge in current.incoming_edges:
            kind = edge.label.type if edge.label else None
            if kind == gtirb.cfg.Edge.Type.Return:
                continue
            if kind == gtirb.cfg.Edge.Type.Call or not isinstance(edge.source, gtirb.CodeBlock):
                return None   # function entry: the register is an input
            source_stream = state.insns(edge.source)
            if source_stream and source_stream[-1].mnemonic in ('bl', 'blr') and reg not in CALLEE_SAVED:
                return None
            predecessors.append(edge.source)
        if not predecessors:
            return None
        for predecessor in predecessors:
            work.append((predecessor, len(state.insns(predecessor))))
    return found


def symbolize_split_lo12(module, decoder):
    """Returns the number of users given a :lo12: expression."""
    if module.isa != gtirb.Module.ISA.ARM64:
        return 0
    state = _Module(module, decoder)
    fixed = 0
    for block in list(module.code_blocks):
        if block.address is None or not block.size:
            continue
        for index, inst in enumerate(state.insns(block)):
            key = _definition_key(state, block, inst)
            if key is None:
                continue
            symbol, addend = key
            target = _symbol_address(symbol)
            if target is None:
                continue
            target += addend
            reg = _regnum(inst.reg_name(inst.operands[0].reg))
            page = inst.operands[1].imm
            work = [(block, index + 1)]
            visited = set()
            while work:
                current, start = work.pop()
                if (current, start) in visited:
                    continue
                visited.add((current, start))
                stream = state.insns(current)
                alive = True
                for position in range(start, len(stream)):
                    use = stream[position]
                    reads, writes = state.access(use)
                    if reg in reads and use.mnemonic != 'adrp':
                        offset = _page_offset(use, reg)
                        if (offset is not None and page + offset == target and
                                state.symexpr(current, use) is None and
                                _reaching_definitions(state, current, position, reg) == {key}):
                            interval = current.byte_interval
                            interval.symbolic_expressions[use.address - interval.address] = \
                                gtirb.SymAddrConst(addend, symbol, {LO12})
                            fixed += 1
                    if reg in writes or (use.mnemonic in ('bl', 'blr') and reg not in CALLEE_SAVED):
                        alive = False
                        break
                if not alive:
                    continue
                for edge in current.outgoing_edges:
                    kind = edge.label.type if edge.label else None
                    if kind in (gtirb.cfg.Edge.Type.Return, gtirb.cfg.Edge.Type.Call) or \
                            not isinstance(edge.target, gtirb.CodeBlock):
                        continue
                    work.append((edge.target, 0))
    return fixed
