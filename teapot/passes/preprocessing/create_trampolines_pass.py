import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from uuid import UUID
from typing import Optional

from teapot.passes.mixins import VisitorPassMixin
from teapot.datacls.copied_section_mapping import CopiedSectionMapping
from teapot.utils.misc import distinguish_edges, generate_distinct_label_name


class CreateTrampolinesPass(VisitorPassMixin):
    text_section: gtirb.Section
    trampoline_section: gtirb.Section
    branch_counter_section: gtirb.Section

    trampoline_byte_interval: gtirb.ByteInterval
    branch_counter_byte_interval: gtirb.ByteInterval

    text_transient_mapping: CopiedSectionMapping

    def __init__(self,
                 text_section: gtirb.Section, trampoline_section: gtirb.Section, branch_counter_section: gtirb.Section,
                 text_transient_mapping: CopiedSectionMapping, decoder: GtirbInstructionDecoder):
        self.text_section = text_section
        self.trampoline_section = trampoline_section
        self.branch_counter_section = branch_counter_section
        self.text_transient_mapping = text_transient_mapping

        self.decoder = decoder
        self.trampoline_byte_interval = next(iter(trampoline_section.byte_intervals))
        self.branch_counter_byte_interval = next(iter(branch_counter_section.byte_intervals))

    def __initialize_empty_trampoline_code_block(self):
        self.trampoline_byte_interval.contents += bytes([0x90])  # nop
        self.trampoline_byte_interval.size += 1

        block = gtirb.CodeBlock(
            size=1,
            offset=self.trampoline_byte_interval.size - 1,
            byte_interval=self.trampoline_byte_interval
        )
        return block

    def __initialize_empty_counter_data_block(self):
        size = 4

        self.branch_counter_byte_interval.contents += bytes([0x00] * size)
        self.branch_counter_byte_interval.size += size

        block = gtirb.DataBlock(
            size=size,
            offset=self.branch_counter_byte_interval.size - size,
            byte_interval=self.branch_counter_byte_interval
        )
        return block

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.visit_code_blocks(self.text_section)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        if (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                non_fallthrough_edges[0].label.conditional):
            fallthrough_edge: gtirb.Edge = fallthrough_edges[0]
            branch_edge: gtirb.Edge = non_fallthrough_edges[0]

            last_instruction: CsInsn
            *_, last_instruction = self.decoder.get_instructions(block)

            trampoline_target_payload = self.text_transient_mapping.code_blocks_map[fallthrough_edge.target.uuid]
            trampoline_target_symbol = gtirb.Symbol(
                name=generate_distinct_label_name(".L__trampoline_target_", fallthrough_edge.target.uuid),
                payload=trampoline_target_payload,
                module=self.module)

            trampoline_block = self.__initialize_empty_trampoline_code_block()
            self.rewriting_ctx.replace_at(trampoline_block, 0, 1, Patch.from_function(self.__build_trampoline_patch(
                block.uuid, self.text_transient_mapping.code_blocks_map[block.uuid].uuid,
                last_instruction.mnemonic, trampoline_target_symbol.name,
                self.text_transient_mapping.symbols_map[next(branch_edge.target.references).uuid].name
            )))

            counter_block = self.__initialize_empty_counter_data_block()
            gtirb.Symbol(
                name=generate_distinct_label_name(".__branch_counter_", block.uuid),
                payload=counter_block,
                module=self.module
            )
            gtirb.Symbol(
                name=generate_distinct_label_name(".__branch_counter_", self.text_transient_mapping.code_blocks_map[block.uuid].uuid),
                payload=counter_block,
                module=self.module
            )

            '''edges = [
                gtirb.Edge(block, trampoline_target_payload, gtirb.EdgeLabel(gtirb.EdgeType.Branch, conditional=True)),
                gtirb.Edge(block, branch_edge.target, gtirb.EdgeLabel(gtirb.EdgeType.Branch, conditional=True)),
            ]
            block.ir.cfg.update(edges)'''

    @staticmethod
    def __build_trampoline_patch(block_uuid: UUID, transient_block_uuid: UUID,
                                 mnemonic: str,
                                 conditional_target_symbol_name: str,
                                 non_conditional_target_symbol_name: str):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
        {generate_distinct_label_name(".__trampoline_", block_uuid)}:
        {generate_distinct_label_name(".__trampoline_", transient_block_uuid)}:
            {mnemonic} {conditional_target_symbol_name}
            jmp {non_conditional_target_symbol_name}
        """)
