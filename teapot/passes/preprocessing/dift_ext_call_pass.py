from typing import Set

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext

from teapot.configs.blacklist import DIFT_WRAPPER_FUNCTIONS, is_blacklisted_function, wrapper_destinations
from teapot.passes.mixins import VisitorPassMixin


class DiftExtCallPass(VisitorPassMixin):
    section: gtirb.Section
    symbols_to_rename: Set[gtirb.Symbol]

    def __init__(self, section: gtirb.Section, decoder: GtirbInstructionDecoder,
                 wrap_dift_calls: bool = True):
        self.section = section
        self.decoder = decoder
        self.wrap_dift_calls = wrap_dift_calls
        self.symbols_to_rename = set()

    @staticmethod
    def should_ignore_dift_wrapper(name: str) -> bool:
        return name not in DIFT_WRAPPER_FUNCTIONS

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)

        self.visit_functions(functions, self.section)

    def end_module(self, module: gtirb.Module, functions) -> None:
        symbol_forwarding = module.aux_data.get('symbolForwarding')
        forwarding = symbol_forwarding.data if symbol_forwarding is not None else {}
        symbol_versions = module.aux_data.get('elfSymbolVersions')
        version_entries = symbol_versions.data[2] if symbol_versions is not None else {}
        destinations = wrapper_destinations(self.wrap_dift_calls)
        for forwarded_sym in {forwarding.get(sym, sym) for sym in self.symbols_to_rename}:
            wrapper = destinations.get(forwarded_sym.name)
            if wrapper:
                version_entries.pop(forwarded_sym, None)
                forwarded_sym.name = wrapper
        super().end_module(module, functions)

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        super().visit_function(function)

    def _riscv_call_pair_expression(self, block, terminator):
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
                   for owner in owners for inst in self.decoder.get_instructions(owner)):
            return None
        expression = interval.symbolic_expressions.get(high_offset)
        if not isinstance(expression, gtirb.SymAddrConst):
            return None
        attrs = gtirb.SymbolicExpression.Attribute
        if expression.attributes & {attrs.GOT, attrs.TLSGD, attrs.LO}:
            return None
        return expression

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        targets = {
            edge.target for edge in block.outgoing_edges
            if edge.label is not None
            and edge.label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Branch)
            and (isinstance(edge.target, gtirb.ProxyBlock) or edge.target.section is not self.section)
        }
        if not targets:
            return

        # A PLT block can be referenced only by a RISC-V AUIPC/LO anchor.
        # The call relocation, not that anchor, names the external function.
        # Inspect the terminator and, for a verified RISC-V control-flow pair,
        # its high relocation. Other earlier expressions may be data operands.
        last_instruction = None
        for last_instruction in self.decoder.get_instructions(block):
            pass
        if last_instruction is not None:
            offset = block.offset + last_instruction.address - block.address
            for position in range(offset, offset + last_instruction.size):
                expression = block.byte_interval.symbolic_expressions.get(position)
                if isinstance(expression, gtirb.SymAddrConst):
                    self.symbols_to_rename.add(expression.symbol)
            pair_expression = self._riscv_call_pair_expression(block, last_instruction)
            if pair_expression is not None:
                self.symbols_to_rename.add(pair_expression.symbol)

        # Other frontends use PLT aliases plus symbolForwarding. Keep all
        # candidates; end_module filters by the forwarded callable name.
        for target in targets:
            self.symbols_to_rename.update(target.references)
