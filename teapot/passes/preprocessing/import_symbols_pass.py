import gtirb
from gtirb_rewriting import Pass, RewritingContext


class ImportSymbolsPass(Pass):
    def __init__(self, symbol_names):
        self.symbol_names = tuple(dict.fromkeys(symbol_names))

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        for symbol_name in self.symbol_names:
            rewriting_ctx.get_or_insert_extern_symbol(symbol_name, '')
