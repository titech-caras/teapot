import gtirb
from gtirb_rewriting import Pass, RewritingContext

from teapot.config import CHECKPOINT_LIB_SYMBOLS


class ImportSymbolsPass(Pass):
    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        for symbol_name in CHECKPOINT_LIB_SYMBOLS:
            rewriting_ctx.get_or_insert_extern_symbol(symbol_name, '')
