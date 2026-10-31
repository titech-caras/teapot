from typing import Set

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext

from teapot.configs.blacklist import DIFT_WRAPPER_FUNCTIONS, MAPPING_WRAPPER_FUNCTIONS, is_blacklisted_function, wrapper_destinations
from teapot.configs.runtime import GENERATED_NAME_SUFFIXES
from teapot.dfsan_abilist import call_effect, category
from teapot.passes.mixins import VisitorPassMixin
from teapot.preprocess.runtime_names import _undefined


class DiftExtCallPass(VisitorPassMixin):
    section: gtirb.Section
    symbols_to_rename: Set[gtirb.Symbol]

    def __init__(self, section: gtirb.Section, decoder: GtirbInstructionDecoder,
                 wrap_dift_calls: bool = True, enforce_mappings: bool = False,
                 linked_function_symbols=frozenset()):
        self.section = section
        self.decoder = decoder
        self.wrap_dift_calls = wrap_dift_calls
        self.enforce_mappings = enforce_mappings
        self.linked_function_symbols = frozenset(linked_function_symbols)
        self.symbols_to_rename = set()

    @staticmethod
    def should_ignore_dift_wrapper(name: str) -> bool:
        return name not in DIFT_WRAPPER_FUNCTIONS

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)

        if self.enforce_mappings:
            # Bind import identities, not only direct-call instructions. This
            # includes constructor/blacklist references and data-held function
            # pointers. Runtime objects are not rewritten, so their original
            # libc binding is distinct from these renamed application imports.
            for symbol in module.symbols:
                if symbol.name in MAPPING_WRAPPER_FUNCTIONS and _undefined(module, symbol):
                    self.symbols_to_rename.add(symbol)

        self.visit_functions(functions, self.section)

    def end_module(self, module: gtirb.Module, functions) -> None:
        symbol_forwarding = module.aux_data.get('symbolForwarding')
        forwarding = symbol_forwarding.data if symbol_forwarding is not None else {}
        symbol_versions = module.aux_data.get('elfSymbolVersions')
        version_entries = symbol_versions.data[2] if symbol_versions is not None else {}
        destinations = wrapper_destinations(self.wrap_dift_calls, self.enforce_mappings)
        for forwarded_sym in {forwarding.get(sym, sym) for sym in self.symbols_to_rename}:
            # A PLT/forwarding edge can target this module's own definition.
            # Renaming it destroys the public export and rewrites every reference.
            if not _undefined(module, forwarded_sym):
                continue
            # These names are supplied only by the validated component link set.
            # Its instrumented providers already propagate DIFT; their imports
            # must retain the link identity rather than enter an external wrapper.
            if (forwarded_sym.name in DIFT_WRAPPER_FUNCTIONS and
                    forwarded_sym.name in self.linked_function_symbols):
                continue
            wrapper = destinations.get(forwarded_sym.name)
            if wrapper:
                version_entries.pop(forwarded_sym, None)
                forwarded_sym.name = wrapper
        super().end_module(module, functions)

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        super().visit_function(function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        self.symbols_to_rename.update(external_call_symbols(block, self.section, self.decoder))


class ExternalCallTags:
    """DFSan's tag rule for the library calls DiftExtCallPass leaves unwrapped.

    The text DIFT pass applies it where a call returns, in the call's own
    return block, since the callee may call back into instrumented code that
    writes tags. A tail jump, or a call whose return block is also reached
    otherwise, gets it before the call instead: the callee does not touch tags
    itself. Wrapped calls and instrumented component providers are excluded.
    """

    def __init__(self, arch_name: str, *, soft_float: bool = False, linked_function_symbols=frozenset()):
        self.arch_name = arch_name
        self.soft_float = soft_float
        self.linked_function_symbols = frozenset(linked_function_symbols)
        self.unlisted = set()  # imported callees on neither list, for the rewrite log

    def before_call(self, block: gtirb.CodeBlock, section: gtirb.Section, decoder):
        """(argument register names, result register names) to apply before block's final call."""
        if _private_return_block(block) is not None:
            return None
        return self._effect(block, section, decoder)

    def on_return(self, block: gtirb.CodeBlock, section: gtirb.Section, decoder):
        """The effect to apply first in block, when block is a call's own return block."""
        incoming = list(block.incoming_edges)
        if len(incoming) != 1 or not isinstance(incoming[0].source, gtirb.CodeBlock):
            return None
        caller = incoming[0].source
        if _private_return_block(caller) is not block:
            return None
        return self._effect(caller, section, decoder)

    def _effect(self, block, section, decoder):
        symbols = external_call_symbols(block, section, decoder, unconditional=True)
        if not symbols:
            return None
        module = block.module
        forwarding = module.aux_data.get('symbolForwarding')
        forwarding = forwarding.data if forwarding is not None else {}
        names = {forwarding.get(symbol, symbol).name for symbol in symbols
                 if _undefined(module, forwarding.get(symbol, symbol))}
        if len(names) != 1:
            return None
        name = names.pop()
        if name.endswith(GENERATED_NAME_SUFFIXES) or name in self.linked_function_symbols:
            return None
        name = name.split("@", 1)[0]
        if category(name) is None:
            self.unlisted.add(name)
        reads, writes = call_effect(self.arch_name, name, soft_float=self.soft_float)
        if not writes or (len(writes) == 1 and reads == writes):
            return None  # nothing, or a register that keeps its own tag
        return reads, writes


def _private_return_block(block: gtirb.CodeBlock):
    """The block block's final call returns to, if no other edge reaches it."""
    edges = [edge for edge in block.outgoing_edges if edge.label is not None]
    if not any(edge.label.type == gtirb.EdgeType.Call for edge in edges):
        return None
    returns = [edge.target for edge in edges if edge.label.type == gtirb.EdgeType.Fallthrough]
    if len(returns) != 1 or not isinstance(returns[0], gtirb.CodeBlock):
        return None
    if len(list(returns[0].incoming_edges)) != 1:
        return None
    return returns[0]

def external_call_symbols(block: gtirb.CodeBlock, section: gtirb.Section, decoder,
                          *, unconditional: bool = False) -> Set[gtirb.Symbol]:
    """Symbols that may name the external function block's last instruction calls or jumps to.

    unconditional: none unless every such call or jump is unconditional.
    """
    edges = [
        edge for edge in block.outgoing_edges
        if edge.label is not None
        and edge.label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Branch)
        and (isinstance(edge.target, gtirb.ProxyBlock) or edge.target.section is not section)
    ]
    if not edges or (unconditional and any(edge.label.conditional for edge in edges)):
        return set()
    symbols = set()

    # A PLT block can be referenced only by a RISC-V AUIPC/LO anchor.
    # The call relocation, not that anchor, names the external function.
    # Inspect the terminator and, for a verified RISC-V control-flow pair,
    # its high relocation. Other earlier expressions may be data operands.
    last_instruction = None
    for last_instruction in decoder.get_instructions(block):
        pass
    if last_instruction is not None:
        offset = block.offset + last_instruction.address - block.address
        for position in range(offset, offset + last_instruction.size):
            expression = block.byte_interval.symbolic_expressions.get(position)
            if isinstance(expression, gtirb.SymAddrConst):
                symbols.add(expression.symbol)
        pair_expression = riscv_call_pair_expression(block, last_instruction, decoder)
        if pair_expression is not None:
            symbols.add(pair_expression.symbol)

    # Other frontends use PLT aliases plus symbolForwarding. Keep all
    # candidates; callers filter by the forwarded callable name.
    for edge in edges:
        symbols.update(edge.target.references)
    return symbols


def riscv_call_pair_expression(block, terminator, decoder):
    arch_info = block.module.aux_data.get("archInfo")
    if (arch_info is None or not isinstance(arch_info.data, dict)
            or str(arch_info.data.get("ISA", "")).upper() != "RISCV64"
            or block.module.byte_order != gtirb.Module.ByteOrder.Little
            or terminator.size != 4):
        return None

    interval = block.byte_interval
    low_offset = block.offset + terminator.address - block.address
    high_offset = low_offset - 4
    if high_offset < 0:
        return None
    high_word = int.from_bytes(interval.contents[high_offset:low_offset], "little")
    low_word = int.from_bytes(terminator.bytes, "little")
    # R_RISCV_CALL[_PLT] is attached to AUIPC, not the JALR terminator.
    # Check both opcodes and the shared base register before inspecting
    # that earlier expression: an unrelated data address must not qualify.
    base = (high_word >> 7) & 31
    if ((high_word & 0x7f) != 0x17 or (low_word & 0x707f) != 0x67
            or base == 0 or base != ((low_word >> 15) & 31)):
        return None

    # A frontend can split the two instructions at the low anchor. Confirm
    # the high word starts a decoded code instruction, even across blocks.
    high_address = terminator.address - 4
    owners = interval.code_blocks_on_offset(high_offset)
    if not any(inst.address == high_address and inst.size == 4 and inst.mnemonic == "auipc"
               for owner in owners for inst in decoder.get_instructions(owner)):
        return None
    expression = interval.symbolic_expressions.get(high_offset)
    if not isinstance(expression, gtirb.SymAddrConst):
        return None
    attrs = gtirb.SymbolicExpression.Attribute
    if expression.attributes & {attrs.GOT, attrs.TLSGD, attrs.LO}:
        return None
    return expression
