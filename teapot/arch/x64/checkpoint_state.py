"""Conservative checkpoint-state selection on the unmodified application CFG."""
from collections import deque

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis.vectors import checkpoint_case, extended_state_clobbers


def df_checkpoint_blocks(module, decoder, abi):
    """Return blocks whose final instruction may execute with DF set."""
    result = set()
    if any(key not in module.aux_data for key in ('functionEntries', 'functionBlocks', 'functionNames')):
        return {b.uuid for b in module.code_blocks}
    for function in Function.build_functions(module):
        blocks = set(function.get_all_blocks())
        entries = set(function.get_entry_blocks())
        decoded = {b: list(decoder.get_instructions(b)) for b in blocks}
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
    result = {}
    opaque = extended_state_clobbers(module, reg_manager.analyzer.decoder)
    if all(key in module.aux_data for key in ('functionEntries', 'functionBlocks', 'functionNames')):
        for function in Function.build_functions(module):
            masks = reg_manager.analyze_vectors(function)
            for block in function.get_all_blocks():
                values = masks.get(block.uuid) if masks is not None else None
                case = checkpoint_case(values[-1] if values else None)
                # Overlapping function ownership cannot weaken another proof.
                result[block.uuid] = max(result.get(block.uuid, 0), case)
    return {b.uuid: 2 if b.uuid in opaque else result.get(b.uuid, 2)
            for b in module.code_blocks}


def vector_state(requested='auto'):
    """The full entry's XSAVE mask; auto reduction is now selected per site."""
    return {'auto': 4, 'xmm0-7': 1, 'sse': 2, 'avx': 3, 'full': 4}[requested]
