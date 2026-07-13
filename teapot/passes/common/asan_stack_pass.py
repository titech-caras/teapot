import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Patch, RewritingContext

from teapot.arch.architecture import Architecture
from teapot.configs.runtime import ASAN_TAG_STORAGE_SHADOW
from teapot.configs.blacklist import function_symbol_names, is_blacklisted_function_name
from teapot.datacls.dift_layout import get_dift_layout
from teapot.passes.mixins import RegInstAwarePassMixin, VisitorPassMixin
from teapot.utils.misc import distinguish_edges


class AsanStackPass(VisitorPassMixin, RegInstAwarePassMixin):
    section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager,
                 section: gtirb.Section, decoder: GtirbInstructionDecoder, arch: Architecture,
                 insert_memlog: bool, *, dift_layout=None, tag_storage: str = ASAN_TAG_STORAGE_SHADOW):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.section = section
        self.arch = arch
        self.insert_memlog = insert_memlog
        self.dift_layout = dift_layout or get_dift_layout(arch.name)
        self.tag_storage = tag_storage

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.section)

    def visit_function(self, function: Function):
        if any(name == "main" or is_blacklisted_function_name(name) for name in function_symbol_names(function)):
            return

        self.reg_manager.analyze(function)
        for block in function.get_entry_blocks():
            patch = self.arch.asan_stack_patch(
                self.reg_manager.abi, poison=True,
                insert_memlog=self.insert_memlog,
                shadow_offset=self.dift_layout.asan_shadow_offset,
                tag_storage=self.tag_storage)
            patch = self.reg_manager.allocate_registers(function, block, 0)(patch)
            self.insert_at(block, 0, Patch.from_function(patch))

        for block in function.get_exit_blocks():
            non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                return

            instructions = list(self.decoder.get_instructions(block))
            patch = self.arch.asan_stack_patch(
                self.reg_manager.abi, poison=False,
                insert_memlog=self.insert_memlog,
                shadow_offset=self.dift_layout.asan_shadow_offset,
                tag_storage=self.tag_storage)
            patch = self.reg_manager.allocate_registers(function, block, len(instructions) - 1)(patch)
            self.insert_at(block, sum(inst.size for inst in instructions[:-1]), Patch.from_function(patch))

        super().visit_function(function)
