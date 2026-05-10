import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn

from teapot.arch.architecture import Architecture
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
                 text_transient_mapping: CopiedSectionMapping, decoder: GtirbInstructionDecoder,
                 arch: Architecture, reg_manager=None, landing_pad_targets=None):
        self.text_section = text_section
        self.trampoline_section = trampoline_section
        self.branch_counter_section = branch_counter_section
        self.text_transient_mapping = text_transient_mapping
        self.arch = arch
        self.reg_manager = reg_manager
        self.landing_pad_targets = landing_pad_targets if landing_pad_targets is not None else set()

        self.decoder = decoder
        self.trampoline_byte_interval = next(iter(trampoline_section.byte_intervals))
        self.branch_counter_byte_interval = next(iter(branch_counter_section.byte_intervals))
        self.processed_blocks = set()

    def __initialize_empty_trampoline_code_block(self):
        nop = self.arch.nop_bytes
        self.trampoline_byte_interval.contents += nop
        self.trampoline_byte_interval.size += len(nop)

        block = gtirb.CodeBlock(
            size=len(nop),
            offset=self.trampoline_byte_interval.size - len(nop),
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
        self.processed_blocks = set()
        self.visit_functions(functions, self.text_section)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        if block.uuid in self.processed_blocks:
            return

        non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        if (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                non_fallthrough_edges[0].label.conditional):
            self.processed_blocks.add(block.uuid)
            fallthrough_edge: gtirb.Edge = fallthrough_edges[0]
            branch_edge: gtirb.Edge = non_fallthrough_edges[0]

            last_instruction: CsInsn
            instructions = list(self.decoder.get_instructions(block))
            *_, last_instruction = instructions
            instruction_idx = max(len(instructions) - 1, 0)

            trampoline_kwargs = {}

            trampoline_target_payload = self.text_transient_mapping.code_blocks_map[fallthrough_edge.target.uuid]
            trampoline_target_symbol = gtirb.Symbol(
                name=generate_distinct_label_name(
                    ".L__trampoline_target_" + str(block.uuid).replace("-", "_") + "_",
                    fallthrough_edge.target.uuid),
                payload=trampoline_target_payload,
                module=self.module)
            branch_target_payload = self.text_transient_mapping.code_blocks_map[branch_edge.target.uuid]
            branch_target_symbol = gtirb.Symbol(
                name=generate_distinct_label_name(
                    ".L__trampoline_taken_target_" + str(block.uuid).replace("-", "_") + "_",
                    branch_edge.target.uuid),
                payload=branch_target_payload,
                module=self.module)
            fallthrough_target_symbol_name = trampoline_target_symbol.name
            branch_target_symbol_name = branch_target_symbol.name
            fallthrough_target_symbol_name, branch_target_symbol_name, trampoline_kwargs = (
                self.arch.trampoline_target_names(
                    fallthrough_target_symbol_name,
                    branch_target_symbol_name,
                    fallthrough_target_uuid=fallthrough_edge.target.uuid,
                    branch_target_uuid=branch_edge.target.uuid,
                    landing_pad_targets=self.landing_pad_targets))

            trampoline_block = self.__initialize_empty_trampoline_code_block()
            trampoline_patch = self.arch.trampoline_patch(
                block.uuid, self.text_transient_mapping.code_blocks_map[block.uuid].uuid,
                last_instruction.mnemonic, last_instruction.op_str, fallthrough_target_symbol_name,
                branch_target_symbol_name,
                **trampoline_kwargs,
            )
            self.rewriting_ctx.replace_at(
                trampoline_block, 0, trampoline_block.size, Patch.from_function(trampoline_patch))

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
