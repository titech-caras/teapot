import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch.architecture import Architecture
from teapot.configs.blacklist import is_blacklisted_function
from teapot.passes.mixins import VisitorPassMixin
from teapot.datacls.copied_section_mapping import CopiedSectionMapping
from teapot.utils.misc import distinguish_edges, generate_distinct_label_name


class TextIndirectBranchTransformPass(VisitorPassMixin):
    text_section: gtirb.Section
    text_transient_mapping: CopiedSectionMapping

    def __init__(self, text_section: gtirb.Section, text_transient_mapping: CopiedSectionMapping,
                 decoder: GtirbInstructionDecoder, arch: Architecture,
                 reg_manager: LiveRegisterManager = None, landing_pad_targets=None):
        self.text_section = text_section
        self.text_transient_mapping = text_transient_mapping
        self.arch = arch
        self.reg_manager = reg_manager
        self.landing_pad_targets = landing_pad_targets if landing_pad_targets is not None else set()

        self.decoder = decoder
        self.analyzed_function_ids = set()

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.analyzed_function_ids = set()
        self.symbol_names = {symbol.name for symbol in module.symbols}
        self.functions = list(functions)
        self.function_by_block_uuid = {
            block.uuid: function
            for function in self.functions
            for block in function.get_all_blocks()
        }
        self.visit_functions(self.functions, self.text_section)

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        if self.arch.indirect_transform_uses_live_registers() and self.reg_manager is not None:
            self._analyze_function(function)
        super().visit_function(function)

    def _analyze_function(self, function: Function):
        function_id = id(function)
        if function_id in self.analyzed_function_ids:
            return
        self.reg_manager.analyze(function)
        self.analyzed_function_ids.add(function_id)

    def _ensure_landing_pad_symbol(self, original_block_uuid):
        landing_name = self.arch.indirect_transform_landing_pad_label(original_block_uuid)
        if landing_name is None or landing_name in self.symbol_names:
            return

        transient_block = self.text_transient_mapping.code_blocks_map.get(original_block_uuid)
        if transient_block is None:
            return

        gtirb.Symbol(
            name=landing_name,
            payload=transient_block,
            module=self.module)
        self.symbol_names.add(landing_name)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        incoming_edges = list(block.incoming_edges)
        non_fallthrough_edges, fallthrough_edges = distinguish_edges(incoming_edges)
        # FIXME: this thing clobbers flags!

        if (len(incoming_edges) == 0 or  # Sometimes GTIRB doesn't detect indirect branches
                any(e.label.type in (gtirb.cfg.Edge.Type.Call, gtirb.cfg.Edge.Type.Branch) and
                    not e.label.direct for e in non_fallthrough_edges)):
            # FIXME: Can we handle jump tables better altogether? Maybe there's a better way...
            transient_target = self.text_transient_mapping.code_blocks_map[block.uuid]
            indbr_transform_target_symbol = self._transform_target_symbol(
                ".L__indbr_transform_target_" + function.get_name() + "_",
                block,
                transient_target)
            self.insert_at(block, 0, Patch.from_function(
                self.arch.indirect_transform_target_patch(
                    indbr_transform_target_symbol,
                    reg_manager=self.reg_manager,
                    function=function,
                    block=block,
                    instruction_idx=0,
                    landing_target_uuid=block.uuid,
                    landing_pad_targets=self.landing_pad_targets,
                    ensure_landing_pad_symbol=self._ensure_landing_pad_symbol)))

        if (len(fallthrough_edges) > 0 and
                any(e.label.type == gtirb.cfg.Edge.Type.Call for e in fallthrough_edges[0].source.outgoing_edges)):
            transient_target = self.text_transient_mapping.code_blocks_map[block.uuid]
            ret_transform_target_symbol = self._transform_target_symbol(
                ".L__ret_transform_target_" + function.get_name() + "_",
                block,
                transient_target)
            source_block = fallthrough_edges[0].source
            source_instructions = list(self.decoder.get_instructions(source_block))
            source_instruction_idx = max(len(source_instructions) - 1, 0)
            self.insert_at(source_block, source_block.size, Patch.from_function(
                self.arch.indirect_transform_target_patch(
                    ret_transform_target_symbol,
                    reg_manager=self.reg_manager,
                    function=function,
                    block=source_block,
                    instruction_idx=source_instruction_idx,
                    landing_target_uuid=block.uuid,
                    landing_pad_targets=self.landing_pad_targets,
                    ensure_landing_pad_symbol=self._ensure_landing_pad_symbol)))

    def _transform_target_symbol(self, prefix: str, block: gtirb.CodeBlock, transient_target: gtirb.CodeBlock):
        target_symbol = gtirb.Symbol(
            name=generate_distinct_label_name(prefix, block.uuid),
            payload=transient_target,
            module=self.module)
        return target_symbol
