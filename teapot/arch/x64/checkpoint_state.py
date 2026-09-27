"""Conservative checkpoint-state selection on the unmodified application CFG."""
from collections import deque

import gtirb
from capstone import CsError, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM
from gtirb_functions import Function


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


def vector_state(module, decoder, requested='auto', *, component=False):
    """Select only proven state reductions; opaque/external code means full."""
    modes = {'xmm0-7': 1, 'sse': 2, 'avx': 3, 'full': 4}
    if requested != 'auto':
        return modes[requested]
    if component:
        return 4
    mode = 1
    for block in module.code_blocks:
        for edge in block.outgoing_edges:
            if (edge.label and edge.label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Branch)
                    and (not isinstance(edge.target, gtirb.CodeBlock)
                         or edge.target.module is not module)):
                return 4
        try:
            instructions = list(decoder.get_instructions(block))
            if sum(i.size for i in instructions) != block.size:
                return 4
            for insn in instructions:
                if ((insn.group(CS_GRP_CALL) or insn.group(CS_GRP_JUMP)) and
                        not any(op.type == CS_OP_IMM for op in insn.operands)):
                    return 4
                reads, writes = insn.regs_access()
                names = [insn.reg_name(r) for r in (*reads, *writes)]
                op = insn.mnemonic.split()[-1]
                # EVEX can touch AVX-512 state even with an XMM/YMM destination
                # and no printed mask (including registers 16 through 31).
                if (insn.bytes[0] == 0x62
                        or any(n.startswith(('zmm', 'k', 'st', 'mm')) for n in names)
                        or any(n.startswith(('xmm', 'ymm')) and int(n[3:]) >= 16
                               for n in names)
                        or op.startswith(('f', 'xrstor', 'fxrstor'))
                        or op in ('syscall', 'sysenter', 'int', 'iretq')):
                    return 4
                if op.startswith('v') or any(n.startswith('ymm') for n in names):
                    mode = max(mode, 3)
                if any(n.startswith('xmm') for n in names):
                    # Arithmetic may modify MXCSR even if it only writes XMM0.
                    if (op not in {'movaps', 'movups', 'movdqa', 'movdqu', 'movq', 'movd',
                                   'pxor', 'pand', 'pandn', 'por', 'xorps', 'xorpd'}
                            or any(n.startswith('xmm') and int(n[3:]) >= 8 for n in names)):
                        mode = max(mode, 2)
                if op in ('ldmxcsr', 'vldmxcsr'):
                    mode = max(mode, 2)
        except CsError:
            return 4
    return mode
