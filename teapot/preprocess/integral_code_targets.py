"""Give direct transfers relocatable labels, not coincident ABS constants."""
from collections import defaultdict

import gtirb
from capstone import CS_GRP_BRANCH_RELATIVE, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM

from teapot.utils.misc import new_label_name


def normalize_integral_code_targets(module, decoder=None, arch=None):
    from gtirb_rewriting.decoder import GtirbInstructionDecoder
    from teapot.arch import get_arch

    candidates = defaultdict(set)
    for interval in module.byte_intervals:
        for offset, expression in interval.symbolic_expressions.items():
            if (isinstance(expression, gtirb.SymAddrConst) and expression.offset == 0
                    and expression.symbol.value is not None):
                candidates[interval].add(offset)
    if not candidates:
        return 0
    arch = arch or get_arch(module)
    decoder = decoder or GtirbInstructionDecoder(module.isa)
    blocks = [block for section in module.sections
              if gtirb.Section.Flag.Executable in section.flags for block in section.code_blocks]
    entries = defaultdict(list)
    for block in blocks:
        if block.address is not None:
            entries[block.address].append(block)
    rebound = 0
    for block in blocks:
        interval = block.byte_interval
        if not any(block.offset <= offset < block.offset + block.size
                   for offset in candidates[interval]):
            continue
        instructions = list(decoder.get_instructions(block))
        for index, instruction in enumerate(instructions):
            offset = block.offset + instruction.address - block.address
            sites = []
            if (arch.is_direct_transfer_instruction(instruction) and instruction.operands
                    and instruction.operands[-1].type == CS_OP_IMM
                    and any(instruction.group(group) for group in
                            (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_BRANCH_RELATIVE))):
                sites = [site for site in candidates[interval] if offset <= site < offset + instruction.size]
            pair = arch.direct_transfer_expression(block, instructions[:index + 1])
            if pair is not None:
                sites += [site for site in candidates[interval]
                          if interval.symbolic_expressions[site] is pair]
            for site in sites:
                expression = interval.symbolic_expressions[site]
                value = expression.symbol.value
                if value is None:  # An overlapping instruction view may already have rebound it.
                    continue
                targets = entries[value]
                if len(targets) != 1:
                    raise ValueError(f'direct transfer at {instruction.address:#x} to integral symbol '
                                     f'{expression.symbol.name!r} ({value:#x}) has '
                                     f'{len(targets)} executable CodeBlocks at its target; expected one')
                target = targets[0]
                info = module.aux_data.setdefault('elfSymbolInfo', gtirb.AuxData(
                    {}, 'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')).data
                # ELF mapping symbols describe bytes; they are not linkable code labels.
                labels = [symbol for symbol in target.references if not symbol.at_end
                          and not symbol.name.startswith(('$x', '$d'))
                          and info.get(symbol, (0, 'NOTYPE'))[1] in ('FUNC', 'NOTYPE')]
                if labels:
                    label = min(labels, key=lambda symbol: (symbol.name, symbol.uuid.bytes))
                else:
                    label = gtirb.Symbol(new_label_name(module, '.L__integral_code_target', target),
                                         payload=target, module=module)
                    info[label] = (0, 'NOTYPE', 'LOCAL', 'DEFAULT', 0)
                interval.symbolic_expressions[site] = gtirb.SymAddrConst(
                    0, label, expression.attributes)
                rebound += 1
    return rebound
