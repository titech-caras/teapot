import gtirb
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from uuid import UUID

from NaHCO3.datacls.copied_section_mapping import CopiedSectionMapping
from NaHCO3.utils.misc import distinguish_edges, generate_distinct_label_name


class CreateTrampolinesPass(Pass):
    text_section: gtirb.Section
    trampoline_section: gtirb.Section
    trampoline_byte_interval: gtirb.ByteInterval
    text_transient_mapping: CopiedSectionMapping

    def __init__(self, text_section: gtirb.Section, trampoline_section: gtirb.Section,
                 text_transient_mapping: CopiedSectionMapping):
        self.text_section = text_section
        self.trampoline_section = trampoline_section
        self.text_transient_mapping = text_transient_mapping

        self.decoder = GtirbInstructionDecoder(text_section.module.isa)
        self.trampoline_byte_interval = next(iter(trampoline_section.byte_intervals))

    def __initialize_empty_code_block(self):
        self.trampoline_byte_interval.contents += bytes([0x90])  # nop
        self.trampoline_byte_interval.size += 1

        block = gtirb.CodeBlock(
            size=1,
            offset=self.trampoline_byte_interval.size - 1,
            byte_interval=self.trampoline_byte_interval
        )
        return block

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        rewriting_ctx.get_or_insert_extern_symbol("scratchpad", "") # FIXME: shouldn't be put here!

        for block in self.text_section.code_blocks:
            non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                continue

            if (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                    non_fallthrough_edges[0].label.conditional):
                fallthrough_edge: gtirb.Edge = fallthrough_edges[0]
                branch_edge: gtirb.Edge = non_fallthrough_edges[0]

                last_instruction: CsInsn
                *_, last_instruction = self.decoder.get_instructions(block)

                trampoline_target_symbol = gtirb.Symbol(
                    name=generate_distinct_label_name(".L__trampoline_target_", fallthrough_edge.target.uuid),
                    payload=self.text_transient_mapping.code_blocks_map[fallthrough_edge.target.uuid],
                    module=module)

                trampoline_block = self.__initialize_empty_code_block()
                rewriting_ctx.replace_at(trampoline_block, 0, 1, Patch.from_function(self.__build_trampoline_patch(
                    block.uuid, last_instruction.mnemonic, trampoline_target_symbol.name,
                    self.text_transient_mapping.symbols_map[next(branch_edge.target.references).uuid].name
                )))

    @staticmethod
    def __build_trampoline_patch(block_uuid: UUID,
                                 mnemonic: str,
                                 conditional_target_symbol_name: str,
                                 non_conditional_target_symbol_name: str):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
        {generate_distinct_label_name(".__trampoline_", block_uuid)}:
            {mnemonic} {conditional_target_symbol_name}
            jmp {non_conditional_target_symbol_name}
        """)
