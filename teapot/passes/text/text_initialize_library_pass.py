import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch, AllFunctionsScope, FunctionPosition, BlockPosition
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch.architecture import Architecture
from teapot.passes.mixins import VisitorPassMixin
from teapot.utils.misc import distinguish_edges


class TextInitializeLibraryPass(VisitorPassMixin):
    text_section: gtirb.Section

    def __init__(self, text_section: gtirb.Section, decoder: GtirbInstructionDecoder, arch: Architecture):
        self.text_section = text_section
        self.decoder = decoder
        self.arch = arch

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        rewriting_ctx.register_insert(AllFunctionsScope(FunctionPosition.ENTRY, BlockPosition.ENTRY, {"main"}),
                                      Patch.from_function(self.arch.init_library_patch()))

        self.visit_functions(functions, self.text_section)

    def visit_function(self, function: Function):
        if function.get_name() == "main":
            for block in function.get_exit_blocks():
                non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
                if len(non_fallthrough_edges) == 0:
                    continue

                if non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Return:
                    instructions = list(self.decoder.get_instructions(block))
                    return_offset = sum(inst.size for inst in instructions[:-1])
                    self.insert_at(
                        block, return_offset, Patch.from_function(self.arch.fini_library_patch()))
