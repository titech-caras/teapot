import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Patch, RewritingContext

from teapot.arch.architecture import Architecture
from teapot.passes.mixins import ArchSpecificPassMixin, RegInstAwarePassMixin, VisitorPassMixin
from teapot.utils.misc import conditional_branch_edge


class TransientPortContentionPolicyPassBase(ArchSpecificPassMixin, VisitorPassMixin, RegInstAwarePassMixin):
    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder, arch: Architecture, *, dift_layout):
        self.check_expected_arch(arch)
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.transient_section = transient_section
        self.arch = arch
        self.dift_layout = dift_layout

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_function(self, function: Function):
        self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        instructions = self._conditional_branch_instructions(block)
        if instructions is None:
            return

        predicate_idx = self.predicate_instruction_index(instructions)
        if predicate_idx is None:
            return

        inst = instructions[predicate_idx]
        if self.arch.is_instrumentation_helper_instruction(inst, predicate_idx, instructions):
            return

        inst_offset = sum(i.size for i in instructions[:predicate_idx])
        patch_info = self.build_patch(block, inst, inst_offset)
        if patch_info is None:
            return

        patch, regs_read = patch_info
        self.reg_manager.add_live_registers(function, block, predicate_idx, regs_read)
        patch = self.allocate_registers(function, block, predicate_idx)(patch)
        self.insert_at(block, inst_offset, Patch.from_function(patch))

    def _conditional_branch_instructions(self, block: gtirb.CodeBlock):
        if conditional_branch_edge(block) is None:
            return None
        return list(self.decoder.get_instructions(block))

    def predicate_instruction_index(self, instructions):
        raise NotImplementedError(type(self).__name__)

    def build_patch(self, block: gtirb.CodeBlock, inst, inst_offset: int):
        raise NotImplementedError(type(self).__name__)
