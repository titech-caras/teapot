import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.manager import NotEnoughFreeRegistersException
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

    def _indirect_transform_target_patch(self, target_symbol: gtirb.Symbol, function: Function,
                                         block: gtirb.CodeBlock, instruction_idx: int,
                                         fallback_target_uuid):
        # The fallback target is not part of live-register allocation.  It is
        # only needed if allocation fails and the arch fallback must redirect
        # through a restore/landing pad.
        patch = self._allocated_indirect_transform_target_patch(
            target_symbol, function, block, instruction_idx)
        if patch is not None:
            return patch

        return self._indirect_transform_fallback_patch(
            target_symbol, fallback_target_uuid or block.uuid)

    def _allocated_indirect_transform_target_patch(self, target_symbol: gtirb.Symbol, function: Function,
                                                   block: gtirb.CodeBlock, instruction_idx: int):
        if self.reg_manager is None or not self.arch.indirect_transform_uses_live_registers():
            return None

        patch = self.arch.indirect_branch_target_patch(target_symbol, use_scratch_registers=True)
        try:
            return self.reg_manager.allocate_registers(function, block, instruction_idx, False)(patch)
        except NotEnoughFreeRegistersException:
            return None

    def _indirect_transform_fallback_patch(self, target_symbol: gtirb.Symbol,
                                           target_uuid):
        # RISC-V fallback jumps through per-block landing pads so fixed first
        # spills are restored before entering the transient copy.  Architectures
        # without landing-pad fallback keep the original target symbol.
        if self.arch.indirect_transform_landing_pad_label(target_uuid) is not None:
            self.landing_pad_targets.add(target_uuid)
            self._ensure_landing_pad_symbol(target_uuid)
        return self.arch.indirect_transform_fallback_patch(
            target_symbol, landing_target_uuid=target_uuid)

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
                self._indirect_transform_target_patch(
                    indbr_transform_target_symbol,
                    function, block, 0, block.uuid)))

        if (len(fallthrough_edges) > 0 and
                any(e.label.type == gtirb.cfg.Edge.Type.Call for e in fallthrough_edges[0].source.outgoing_edges)):
            transient_target = self.text_transient_mapping.code_blocks_map[block.uuid]
            ret_transform_target_symbol = self._transform_target_symbol(
                ".L__ret_transform_target_" + function.get_name() + "_",
                block,
                transient_target)
            self.insert_at(
                fallthrough_edges[0].source,
                fallthrough_edges[0].source.size,
                Patch.from_function(
                    self._indirect_transform_target_patch(
                        ret_transform_target_symbol,
                        function,
                        fallthrough_edges[0].source,
                        max(
                            len(list(self.decoder.get_instructions(fallthrough_edges[0].source))) - 1,
                            0),
                        block.uuid)))

    def _transform_target_symbol(self, prefix: str, block: gtirb.CodeBlock, transient_target: gtirb.CodeBlock):
        target_symbol = gtirb.Symbol(
            name=generate_distinct_label_name(prefix, block.uuid),
            payload=transient_target,
            module=self.module)
        return target_symbol
