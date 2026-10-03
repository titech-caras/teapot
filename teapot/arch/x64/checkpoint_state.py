"""Conservative checkpoint-state selection on the unmodified application CFG."""
from collections import deque

import gtirb
from capstone import CsError
from gtirb_functions import Function
from gtirb_live_register_analysis.vectors import checkpoint_case, extended_state_clobbers

from teapot.configs.runtime import X64_VECTOR_STATE_ARGUMENTS


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


def vector_checkpoint_cases(module, reg_manager, requested='auto', *, debug_cross_check=False):
    """Select at the original branch, before patches change uses or offsets."""
    if requested != 'auto':
        case = 1 if requested == 'xmm0-7' else 2
        return {b.uuid: case for b in module.code_blocks}
    result, reasons = {}, {}
    opaque = extended_state_clobbers(module, reg_manager.analyzer.decoder)
    for block in module.code_blocks:
        try:
            instructions = list(reg_manager.analyzer.decoder.get_instructions(block))
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
    if debug_cross_check and all(key in module.aux_data for key in ('functionEntries', 'functionBlocks', 'functionNames')):
        python_cases = {}
        for function in Function.build_functions(module):
            masks = reg_manager.analyze_vectors(function)
            for block in function.get_all_blocks():
                values = masks.get(block.uuid) if masks is not None else None
                case = checkpoint_case(values[-1] if values else None)
                python_cases[block.uuid] = max(python_cases.get(block.uuid, 0), case)
        from collections import Counter
        differences = Counter()
        for block in sorted(module.code_blocks, key=lambda b: (b.address or 0, b.size)):
            other = 2 if block.uuid in opaque else python_cases.get(block.uuid, 2)
            if other != result[block.uuid]:
                differences[(result[block.uuid], other)] += 1
                print(f'[teapot] vector cross-check {block.address!r}: '
                      f'ddisasm={result[block.uuid]} python={other} reason={reasons[block.uuid]}')
        print(f'[teapot] vector cross-check disagreements (ddisasm,python): {dict(differences)}')
    reg_manager.checkpoint_vector_reasons = reasons
    return result


def vector_state(requested='auto'):
    """The full entry's XSAVE mask; auto reduction is now selected per site."""
    return X64_VECTOR_STATE_ARGUMENTS['full' if requested == 'auto' else requested]
