import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_live_register_analysis import LiveRegisterManager

from teapot.arch.architecture import Architecture
from teapot.preprocess.create_guards import create_guards
from teapot.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from teapot.configs.blacklist import is_blacklisted_function


class TransientCoveragePass(VisitorPassMixin, RegInstAwarePassMixin):
    transient_section: gtirb.Section
    guard_section: gtirb.Section

    idx: int = 0

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder, guard_section: gtirb.Section, arch: Architecture):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.transient_section = transient_section
        self.guard_section = guard_section
        self.arch = arch

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def end_module(self, module: gtirb.Module, functions):
        create_guards(self.guard_section, self.idx)

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        if self.reg_manager is not None and self.arch.uses_live_registers:
            self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        patch = self.arch.coverage_patch(self.idx)
        if self.reg_manager is not None and self.arch.uses_live_registers:
            patch = self.reg_manager.allocate_registers(function, block, 0)(patch)
        self.insert_at(block, 0, Patch.from_function(patch))
        self.idx += 1
