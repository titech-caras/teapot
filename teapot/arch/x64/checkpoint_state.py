"""Conservative checkpoint-state selection on the unmodified application CFG."""
from collections import deque

import gtirb
from capstone import CsError
from gtirb_functions import Function

from teapot.configs.runtime import X64_VECTOR_STATE_ARGUMENTS

# Vector-piece mask bits as LiveRegisterManager.producer_vector_mask gives them:
# the low 128 bits of xmm0-31 first, then the next 128 and the high 256 bits of
# each register, then the mask registers.
XMM0_7 = sum(1 << n for n in range(8))


def checkpoint_case(mask):
    """The checkpoint entry a site needs: 0 integer only, 1 XMM0-7, 2 full (also when unknown)."""
    if mask is None or mask & ~XMM0_7:
        return 2
    return int(bool(mask))


def extended_state_clobbers(module, decoder):
    """Blocks that can speculate into x87, MMX or saved-environment state.

    Vector values are ABI caller-saved, but an interrupted internal callee may
    leave, for example, a nonempty x87 stack; the vector masks do not model that
    state, so such blocks, and every block that can reach one (internal calls
    included), need the full save. External and PLT calls stop simulation and
    are not traversed.
    """
    blocks = {b for b in module.code_blocks if b.section.name == '.text'}
    unsafe = set()
    predecessors = {b: set() for b in blocks}

    def unmodeled(insn):
        op = insn.mnemonic.split()[-1]
        reads, writes = insn.regs_access()
        return (op.startswith(('f', 'xsave', 'xrstor')) or op == 'emms' or
                any(insn.reg_name(r).startswith(('st', 'mm')) for r in (*reads, *writes)))

    for block in blocks:
        try:
            instructions = list(decoder.get_instructions(block))
            if (sum(i.size for i in instructions) != block.size or
                    any(unmodeled(i) for i in instructions)):
                unsafe.add(block)
        except (CsError, ValueError):
            unsafe.add(block)
        for edge in block.outgoing_edges:
            if (edge.target in blocks and edge.label and
                    edge.label.type != gtirb.EdgeType.Return):
                predecessors[edge.target].add(block)
    queue = deque(unsafe)
    while queue:
        for source in predecessors[queue.popleft()] - unsafe:
            unsafe.add(source)
            queue.append(source)
    return {b.uuid for b in unsafe}


def df_checkpoint_blocks(module, decoder, abi):
    """Return blocks whose final instruction may execute with DF set."""
    result = set()
    if any(key not in module.aux_data for key in ('functionEntries', 'functionBlocks', 'functionNames')):
        return {b.uuid for b in module.code_blocks}
    for function in Function.build_functions(module):
        blocks = set(function.get_all_blocks())
        entries = set(function.get_entry_blocks())
        decoded = {b: list(decoder.get_instructions(b)) for b in blocks}
        # The ABI enters with DF clear. A fully decoded function with no way
        # to set/restore DF cannot make it set, including disconnected padding
        # or blocks missing CFG predecessors. Do not turn those into DF saves
        # merely because the entry-rooted traversal below cannot reach them.
        if (all(sum(i.size for i in decoded[b]) == b.size for b in blocks) and
                not any(i.mnemonic.split()[-1] == 'std' or
                        i.mnemonic.split()[-1].startswith(('popf', 'iret'))
                        for instructions in decoded.values() for i in instructions)):
            continue
        incoming, outgoing = {b: False for b in blocks}, {b: False for b in blocks}
        successors = {b: {e.target for e in b.outgoing_edges
                          if e.target in blocks and e.label and
                          e.label.type not in (gtirb.EdgeType.Call, gtirb.EdgeType.Return)}
                      for b in blocks}
        queue, visited = deque(entries), set()
        while queue:
            block = queue.popleft()
            state = incoming[block] if block not in entries else False
            before_last = state
            for insn in decoded[block]:
                before_last = state
                op = insn.mnemonic.split()[-1]
                if op == 'std' or op.startswith(('popf', 'iret')):
                    state = True
                elif op == 'cld' or abi.is_call_instruction(insn):
                    state = False
            if sum(i.size for i in decoded[block]) != block.size:
                state = True
            if before_last or sum(i.size for i in decoded[block]) != block.size:
                result.add(block.uuid)
            changed = block not in visited or state != outgoing[block]
            visited.add(block)
            outgoing[block] = state
            if changed:
                for target in successors[block]:
                    incoming[target] |= state
                    queue.append(target)
        result.update(b.uuid for b in blocks - visited)
    covered = set().union(*(set(f.get_all_blocks()) for f in Function.build_functions(module)))
    result.update(b.uuid for b in module.code_blocks if b not in covered)
    return result


def vector_checkpoint_cases(module, reg_manager, requested='auto'):
    """Select at the original branch, before patches change uses or offsets."""
    if requested != 'auto':
        case = 1 if requested == 'xmm0-7' else 2
        return {b.uuid: case for b in module.code_blocks}
    result, reasons = {}, {}
    opaque = extended_state_clobbers(module, reg_manager.decoder)
    for block in module.code_blocks:
        try:
            instructions = list(reg_manager.decoder.get_instructions(block))
        except (CsError, ValueError):
            instructions = []
        mask = None
        if instructions and block.address is not None and sum(i.size for i in instructions) == block.size:
            mask = reg_manager.producer_vector_mask(block, instructions[-1].address - block.address)
        case = checkpoint_case(mask)
        reason = 'missing-mask' if mask is None else 'wide-or-high-vector' if case == 2 else 'reduced'
        if block.uuid in opaque:
            case, reason = 2, 'reachable-extended-state'
        result[block.uuid], reasons[block.uuid] = case, reason
    reg_manager.checkpoint_vector_reasons = reasons
    return result


def vector_state(requested='auto'):
    """The full entry's XSAVE mask; auto reduction is now selected per site."""
    return X64_VECTOR_STATE_ARGUMENTS['full' if requested == 'auto' else requested]
