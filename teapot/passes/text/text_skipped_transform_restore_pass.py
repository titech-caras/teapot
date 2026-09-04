import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext

from teapot.arch.architecture import Architecture
from teapot.configs.blacklist import is_blacklisted_function
from teapot.passes.mixins import VisitorPassMixin


class TextSkippedTransformRestorePass(VisitorPassMixin):
    """Keep active checkpoints out of text excluded from target transforms.

    External code can return to an interior basic block, so guarding only
    function entries is insufficient.  Each distinct block in a skipped
    function receives a state-preserving checkpoint-count test at its start.
    """

    def __init__(self, text_section: gtirb.Section, arch: Architecture):
        self.text_section = text_section
        self.arch = arch
        self.guarded_blocks = set()

    def begin_module(self, module: gtirb.Module, functions,
                     rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.guarded_blocks = set()
        self.visit_functions(functions, self.text_section)

    def visit_function(self, function: Function):
        if not is_blacklisted_function(function):
            return
        super().visit_function(function)

    def visit_code_block(self, block: gtirb.CodeBlock,
                         function: Function = None):
        if block.uuid in self.guarded_blocks:
            return
        patch = self.arch.skipped_text_restore_guard_patch()
        if patch is None:
            return
        self.insert_at(block, 0, Patch.from_function(patch))
        self.guarded_blocks.add(block.uuid)
