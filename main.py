import functools
from typing import List

import gtirb
import keystone
from gtirb_capstone import RewritingContext
from capstone_gt import CsInsn

from copy_section import copy_section
from utils.rewriting import insert_instruction_with_symbol, initialize_empty_code_block
from utils.misc import distinguish_edges
from config import SYMBOL_SUFFIX


ir = gtirb.IR.load_protobuf("test/test.gtirb")
module = ir.modules[0]
text_section = [s for s in module.sections if s.name == ".text"][0]

transient_section, transient_section_end_symbol, code_blocks_copy_mapping, symbol_copy_mapping = (
    copy_section(text_section, ".NaHCO3_transient"))

trampoline_section = gtirb.Section(
    name=".NaHCO3_trampolines",
    byte_intervals=(),
    flags=transient_section.flags,
    uuid=None,
    module=module)

trampoline_byte_interval = gtirb.ByteInterval(section=trampoline_section)

rewriting_context = RewritingContext(ir)
decoder = rewriting_context.get_instruction_decoder(module.isa)
assembler = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
assembler.syntax = keystone.KS_OPT_SYNTAX_INTEL


for block in text_section.code_blocks:
    non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
    if len(non_fallthrough_edges) == 0:
        continue

    if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and non_fallthrough_edges[0].label.conditional:
        fallthrough_edge: gtirb.Edge = fallthrough_edges[0]
        branch_edge: gtirb.Edge = non_fallthrough_edges[0]

        last_instruction: CsInsn
        *_, last_instruction = decoder.get_instructions(block)

        trampoline_block = initialize_empty_code_block(trampoline_byte_interval)
        insert_instruction_with_symbol(
            rewriting_context, trampoline_block, assembler.asm(f"{last_instruction.mnemonic} 0x114514")[0],
            gtirb.Symbol(
                name=".__trampoline_target" + SYMBOL_SUFFIX,
                payload=code_blocks_copy_mapping[fallthrough_edge.target.uuid],
                module=module))
        insert_instruction_with_symbol(
            rewriting_context, trampoline_block, assembler.asm(f"jmp 0x114514")[0],
            symbol_copy_mapping[next(branch_edge.target.references).uuid])

retpoline_block = initialize_empty_code_block(trampoline_byte_interval)
retpoline_jmpret_block = initialize_empty_code_block(trampoline_byte_interval)
rewriting_context.modify_block_insert(module, retpoline_jmpret_block, assembler.asm("jmp r11")[0], 0)
insert_instruction_with_symbol(rewriting_context, retpoline_block, assembler.asm("pop r11; lea r10, [rip+0x114514]")[0],
                               transient_section_end_symbol)
insert_instruction_with_symbol(rewriting_context, retpoline_block, assembler.asm("cmp r10, r11; jl 0x114514")[0],
                               gtirb.Symbol(name=".__retpoline_jmpret" + SYMBOL_SUFFIX,
                                            payload=retpoline_jmpret_block, module=module))
rewriting_context.modify_block_insert(module, retpoline_block, assembler.asm("pop r11")[0],
                                      retpoline_block.size)
retpoline_block_symbol = gtirb.Symbol(name=".__retpoline" + SYMBOL_SUFFIX, payload=retpoline_block, module=module)

for block in text_section.code_blocks:
    non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
    if len(non_fallthrough_edges) == 0:
        continue

    if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Call:
        call_edge: gtirb.Edge = non_fallthrough_edges[0]
        if isinstance(call_edge.target, gtirb.ProxyBlock):
            # TODO: call to external library
            pass
        elif call_edge.target.byte_interval.section.name == ".text":
            if len(fallthrough_edges) == 0:
                continue
            fallthrough_edge: gtirb.Edge = fallthrough_edges[0]

            instructions: List[CsInsn] = list(decoder.get_instructions(block))
            call_offset = functools.reduce(lambda x, i: x + i.size, instructions[:-1], 0)
            rewriting_context.modify_block_insert(module, block, assembler.asm("add rsp, 8")[0],
                                                  call_offset + instructions[-1].size)
            lea_len = insert_instruction_with_symbol(
                rewriting_context, block, assembler.asm("lea r11, [rip+0x114514]")[0],
                gtirb.Symbol(name=".__call_transform_target" + SYMBOL_SUFFIX,
                             payload=code_blocks_copy_mapping[fallthrough_edge.target.uuid],
                             module=module),
                call_offset)
            rewriting_context.modify_block_insert(module, block, assembler.asm("push r11")[0], call_offset + lea_len)

        # TODO: add symbol


for block in text_section.code_blocks:
    non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
    if len(non_fallthrough_edges) == 0:
        continue

    transient_block = code_blocks_copy_mapping[block.uuid]

    if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return:
        # last instruction must be `ret`
        insert_instruction_with_symbol(rewriting_context, transient_block, assembler.asm("jmp 0x114514")[0],
                                       retpoline_block_symbol, transient_block.size - 1)


ir.save_protobuf("test/test_modified.gtirb")