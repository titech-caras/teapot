from typing import Set

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext

from teapot.configs.blacklist import DIFT_IGNORE_LIST, DIFT_WRAPPER_FUNCTIONS, is_blacklisted_function
from teapot.passes.mixins import VisitorPassMixin
from teapot.utils.misc import distinguish_edges


class DiftExtCallPass(VisitorPassMixin):
    section: gtirb.Section
    symbols_to_rename: Set[gtirb.Symbol]

    def __init__(self, section: gtirb.Section, wrap_dift_calls: bool = True):
        self.section = section
        self.wrap_dift_calls = wrap_dift_calls
        self.symbols_to_rename = set()

    @staticmethod
    def should_ignore_dift_wrapper(name: str) -> bool:
        return name in DIFT_IGNORE_LIST or name.startswith("__asan_") or name not in DIFT_WRAPPER_FUNCTIONS

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)

        self.visit_functions(functions, self.section)

    def end_module(self, module: gtirb.Module, functions) -> None:
        symbol_forwarding = module.aux_data.get('symbolForwarding')
        forwarding = symbol_forwarding.data if symbol_forwarding is not None else {}
        symbol_versions = module.aux_data.get('elfSymbolVersions')
        version_entries = symbol_versions.data[2] if symbol_versions is not None else {}
        for sym in self.symbols_to_rename:
            forwarded_sym: gtirb.Symbol = forwarding.get(sym, sym)
            version_entries.pop(forwarded_sym, None)
            if self.wrap_dift_calls and not self.should_ignore_dift_wrapper(forwarded_sym.name):
                forwarded_sym.name += "__dift_wrapper__"

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        super().visit_function(function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        if (non_fallthrough_edges[0].label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Branch) and
                (isinstance(non_fallthrough_edges[0].target, gtirb.ProxyBlock) or
                 non_fallthrough_edges[0].target.section.name != self.section.name)):
            target_refs = list(non_fallthrough_edges[0].target.references)
            if len(target_refs) > 0:
                # is an external function call
                self.symbols_to_rename.add(target_refs[0])
