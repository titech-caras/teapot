from dataclasses import dataclass
from bisect import bisect_left
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import RewritingContext
from capstone_gt import CS_OP_IMM, CS_OP_REG

from teapot.arch.aarch64.architecture import AArch64Architecture
from teapot.passes.mixins import VisitorPassMixin
from teapot.utils.misc import distinguish_edges, generate_distinct_label_name, get_or_insert_symbol


@dataclass
class _BranchTarget:
    symbol: gtirb.Symbol
    addend: int
    address: Optional[int]


@dataclass
class _Replacement:
    offset: int
    bytes: bytes
    target: Optional[_BranchTarget] = None
    skip_target: Optional[_BranchTarget] = None
    symbolic_expressions: Optional[Tuple[Tuple[int, _BranchTarget, set], ...]] = None
    needs_skip_target: bool = False

    @property
    def delta(self) -> int:
        return len(self.bytes) - 4


class AArch64RelaxConditionalBranchesPass(VisitorPassMixin):
    SHORT_BRANCH_SAFETY_MARGIN = 4096
    CONDITIONAL_BRANCH_SAFETY_MARGIN = 32768
    DIRECT_BRANCH_SAFETY_MARGIN = 1048576
    ADR_SAFETY_MARGIN = 32768
    LITERAL_LOAD_SAFETY_MARGIN = 32768

    def __init__(self, decoder: GtirbInstructionDecoder):
        self.decoder = decoder
        self.relaxed_instructions = 0

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.relaxed_instructions = 0
        self.replacements_by_interval: Dict[gtirb.ByteInterval, List[_Replacement]] = {}
        forwarding = module.aux_data.get("symbolForwarding")
        self.symbol_forwarding = forwarding.data if forwarding is not None else {}
        self.code_block_by_address = {
            block.address: block
            for section in module.sections
            for block in section.code_blocks
            if block.address is not None
        }
        for section in module.sections:
            if section.name == ".teapot_trampolines":
                continue
            if gtirb.Section.Flag.Executable in section.flags:
                self.visit_code_blocks(section)
        self._apply_replacements()
        print(
            f"[teapot] AArch64RelaxConditionalBranchesPass relaxed {self.relaxed_instructions} instructions",
            flush=True,
        )

    def visit_code_block(self, block: gtirb.CodeBlock, function=None):
        if block.size == 0:
            return

        instructions = list(self.decoder.get_instructions(block))
        if not instructions:
            return

        instruction_offset = 0
        for idx, instruction in enumerate(instructions):
            self._visit_instruction(block, instructions, idx, instruction_offset)
            instruction_offset += instruction.size

    def _visit_instruction(self, block: gtirb.CodeBlock, instructions, instruction_idx: int, inst_offset: int):
        instruction = instructions[instruction_idx]
        if self._relax_literal_load(block, instruction, inst_offset):
            return
        if self._relax_adr(block, instruction, inst_offset):
            return

        target = self._branch_target(block, instructions, instruction_idx, inst_offset)
        if target is None:
            return
        if target.address is None:
            self._relax_external_direct_branch(block, instruction, inst_offset, target)
            return

        if not self._branch_out_of_range(block, inst_offset, instruction.mnemonic, target.address):
            return

        if self._relax_direct_branch(block, instruction, inst_offset, target):
            return

        inverted_branch = AArch64Architecture.invert_conditional_branch(
            instruction.mnemonic, instruction.op_str, ".")
        if inverted_branch is None:
            return
        if inst_offset + instruction.size > block.size:
            return
        replacement = self._encode_long_branch(instruction, inverted_branch)
        if replacement is None:
            return
        self.replacements_by_interval.setdefault(block.byte_interval, []).append(_Replacement(
            offset=block.offset + inst_offset,
            bytes=replacement,
            target=target,
            skip_target=self._skip_target(block, instructions, instruction_idx),
            needs_skip_target=True,
        ))
        self.relaxed_instructions += 1

    def _relax_direct_branch(self, block: gtirb.CodeBlock, instruction, inst_offset: int,
                             target: _BranchTarget) -> bool:
        """Replace an out-of-range B/BL with the standard IP0 long-branch sequence.

        AAPCS64 reserves x16/IP0 for linker-generated veneers at inter-procedure
        branches. Materializing the exact symbolic target at the original branch
        site avoids relying on section-wide veneer placement while preserving BL's
        link-register behavior (BLR writes x30; BR does not).
        """
        mnemonic = instruction.mnemonic.lower()
        if mnemonic not in ("b", "bl"):
            return False
        if mnemonic == "b" and not self._is_function_entry_target(target):
            # IP0 is reserved for veneers at inter-procedure boundaries, but a
            # local intra-procedure branch may legitimately keep x16 live.
            return False

        branch = 0xD63F0200 if mnemonic == "bl" else 0xD61F0200
        replacement = self._encode_adrp_add(16) + branch.to_bytes(4, "little")
        self.replacements_by_interval.setdefault(block.byte_interval, []).append(_Replacement(
            offset=block.offset + inst_offset,
            bytes=replacement,
            symbolic_expressions=(
                (0, target, {gtirb.SymbolicExpression.Attribute.PAGE}),
                (4, target, {gtirb.SymbolicExpression.Attribute.LO12}),
            ),
        ))
        self.relaxed_instructions += 1
        return True

    def _is_function_entry_target(self, target: _BranchTarget) -> bool:
        if target.addend != 0 or not isinstance(target.symbol.referent, gtirb.CodeBlock):
            return False
        function_entries = self.module.aux_data.get("functionEntries")
        if function_entries is None:
            return False
        return any(target.symbol.referent in entries for entries in function_entries.data.values())

    def _relax_external_direct_branch(self, block: gtirb.CodeBlock, instruction,
                                      inst_offset: int, target: _BranchTarget) -> bool:
        """Replace an external B/BL with an inline GOT-based IP0 veneer."""
        mnemonic = instruction.mnemonic.lower()
        if mnemonic not in ("b", "bl"):
            return False
        if target.addend != 0 or not isinstance(target.symbol.referent, gtirb.ProxyBlock):
            return False

        branch = 0xD63F0200 if mnemonic == "bl" else 0xD61F0200
        replacement = self._encode_adrp_ldr(16) + branch.to_bytes(4, "little")
        self.replacements_by_interval.setdefault(block.byte_interval, []).append(_Replacement(
            offset=block.offset + inst_offset,
            bytes=replacement,
            symbolic_expressions=(
                (0, target, {
                    gtirb.SymbolicExpression.Attribute.GOT,
                    gtirb.SymbolicExpression.Attribute.PAGE,
                }),
                (4, target, {
                    gtirb.SymbolicExpression.Attribute.GOT,
                    gtirb.SymbolicExpression.Attribute.LO12,
                }),
            ),
        ))
        self.relaxed_instructions += 1
        return True

    def _relax_literal_load(self, block: gtirb.CodeBlock, instruction,
                            inst_offset: int) -> bool:
        """Replace a range-fragile GPR literal load with ADRP plus LDR.

        AArch64 literal loads have a signed 19-bit word-scaled displacement and
        therefore only reach roughly one MiB.  A symbolic literal in a different
        section has no stable range after the linker lays out large rewritten
        sections.  Reusing the destination GPR as the temporary page base keeps
        the transformation register-neutral.
        """
        if instruction.mnemonic.lower() != "ldr":
            return False
        if len(instruction.operands) < 2 or instruction.operands[1].type != CS_OP_IMM:
            return False

        target = self._symbolic_target(block, inst_offset, instruction)
        if target is None or target.address is None:
            return False
        if gtirb.SymbolicExpression.Attribute.GOT in self._symbolic_attributes(
                block, inst_offset, instruction):
            return False
        if not self._literal_load_needs_relaxation(block, inst_offset, target):
            return False

        reg_num = self._destination_register_number(instruction)
        if reg_num is None:
            return False
        reg_name = instruction.reg_name(instruction.operands[0].reg)
        if not reg_name.startswith("x"):
            return False

        replacement = self._encode_adrp_ldr(reg_num)
        self.replacements_by_interval.setdefault(block.byte_interval, []).append(_Replacement(
            offset=block.offset + inst_offset,
            bytes=replacement,
            symbolic_expressions=(
                (0, target, {gtirb.SymbolicExpression.Attribute.PAGE}),
                (4, target, {gtirb.SymbolicExpression.Attribute.LO12}),
            ),
        ))
        self.relaxed_instructions += 1
        return True

    def _literal_load_needs_relaxation(self, block: gtirb.CodeBlock,
                                       inst_offset: int, target: _BranchTarget) -> bool:
        source_interval = block.byte_interval
        target_interval = getattr(target.symbol.referent, "byte_interval", None)
        if (source_interval is not None and target_interval is not None and
                source_interval.section is not target_interval.section):
            return True

        source_address = self._block_layout_address(block)
        if source_address is None or target.address is None:
            return False
        source_address += inst_offset
        literal_range = 1048576 - self.LITERAL_LOAD_SAFETY_MARGIN
        delta = target.address - source_address
        return delta < -literal_range or delta > literal_range - 4

    def _relax_adr(self, block: gtirb.CodeBlock, instruction, inst_offset: int) -> bool:
        if instruction.mnemonic.lower() != "adr":
            return False

        target = self._symbolic_target(block, inst_offset, instruction)
        if target is None or target.address is None:
            return False
        if not self._adr_needs_relaxation(block, inst_offset, target):
            return False
        if gtirb.SymbolicExpression.Attribute.GOT in self._symbolic_attributes(block, inst_offset, instruction):
            return False

        reg_num = self._destination_register_number(instruction)
        if reg_num is None:
            return False

        replacement = self._encode_adrp_add(reg_num)
        self.replacements_by_interval.setdefault(block.byte_interval, []).append(_Replacement(
            offset=block.offset + inst_offset,
            bytes=replacement,
            symbolic_expressions=(
                (0, target, {gtirb.SymbolicExpression.Attribute.PAGE}),
                (4, target, {gtirb.SymbolicExpression.Attribute.LO12}),
            ),
        ))
        self.relaxed_instructions += 1
        return True

    def _adr_needs_relaxation(self, block: gtirb.CodeBlock,
                              inst_offset: int, target: _BranchTarget) -> bool:
        source_interval = block.byte_interval
        target_interval = getattr(target.symbol.referent, "byte_interval", None)
        if (source_interval is not None and target_interval is not None and
                source_interval.section is not target_interval.section):
            return True
        return self._adr_out_of_range(block, inst_offset, target.address)

    def _branch_target(self, block: gtirb.CodeBlock, instructions, instruction_idx: int,
                       inst_offset: int) -> Optional[_BranchTarget]:
        instruction = instructions[instruction_idx]
        symbolic_target = self._symbolic_target(block, inst_offset, instruction)
        if symbolic_target is not None:
            return self._forward_branch_target(symbolic_target)

        if instruction_idx == len(instructions) - 1:
            edge_target = self._terminator_branch_target(block)
            if edge_target is not None:
                symbol = get_or_insert_symbol(
                    generate_distinct_label_name(".L__aarch64_long_branch_target_", edge_target.uuid),
                    edge_target,
                    self.module,
                )
                return _BranchTarget(symbol, 0, self._block_layout_address(edge_target))

        immediate_target = self._immediate_target(instruction)
        if immediate_target is None:
            return None
        target_block = self.code_block_by_address.get(immediate_target)
        if target_block is None:
            return None
        symbol = get_or_insert_symbol(
            generate_distinct_label_name(".L__aarch64_long_branch_target_", target_block.uuid),
            target_block,
            self.module,
        )
        return _BranchTarget(symbol, 0, self._block_layout_address(target_block))

    def _forward_branch_target(self, target: _BranchTarget) -> _BranchTarget:
        symbol = target.symbol
        seen = set()
        while symbol in self.symbol_forwarding and symbol not in seen:
            seen.add(symbol)
            symbol = self.symbol_forwarding[symbol]
        if symbol is target.symbol:
            return target
        symbol_address = self._symbol_address(symbol)
        address = None if symbol_address is None else symbol_address + target.addend
        return _BranchTarget(symbol, target.addend, address)

    @staticmethod
    def _symbolic_target(block: gtirb.CodeBlock, inst_offset: int, instruction) -> Optional[_BranchTarget]:
        symexpr = AArch64RelaxConditionalBranchesPass._instruction_symbolic_expression(
            block, inst_offset, instruction
        )
        if not isinstance(symexpr, gtirb.SymAddrConst):
            return None

        symbol_address = AArch64RelaxConditionalBranchesPass._symbol_address(symexpr.symbol)
        if symbol_address is None and not isinstance(symexpr.symbol.referent, gtirb.ProxyBlock):
            return None

        address = None if symbol_address is None else symbol_address + symexpr.offset
        return _BranchTarget(symexpr.symbol, symexpr.offset, address)

    @staticmethod
    def _symbolic_attributes(block: gtirb.CodeBlock, inst_offset: int, instruction):
        symexpr = AArch64RelaxConditionalBranchesPass._instruction_symbolic_expression(
            block, inst_offset, instruction
        )
        if not isinstance(symexpr, gtirb.SymAddrConst):
            return set()
        return set(symexpr.attributes)

    @staticmethod
    def _instruction_symbolic_expression(block: gtirb.CodeBlock, inst_offset: int, instruction):
        interval = block.byte_interval
        if interval is None:
            return None

        offsets = []
        imm_offset = getattr(instruction, "imm_offset", None)
        if imm_offset is not None:
            offsets.append(block.offset + inst_offset + imm_offset)
        offsets.append(block.offset + inst_offset)

        for offset in dict.fromkeys(offsets):
            symexpr = interval.symbolic_expressions.get(offset)
            if symexpr is not None:
                return symexpr
        return None

    @staticmethod
    def _symbol_address(symbol: gtirb.Symbol) -> Optional[int]:
        payload = symbol.referent
        if payload is None:
            return None
        if isinstance(payload, gtirb.ProxyBlock):
            return None
        return AArch64RelaxConditionalBranchesPass._block_layout_address(payload)

    @staticmethod
    def _block_layout_address(block) -> Optional[int]:
        interval = getattr(block, "byte_interval", None)
        if interval is not None and interval.address is not None:
            return interval.address + block.offset
        return getattr(block, "address", None)

    @classmethod
    def _branch_out_of_range(cls, block: gtirb.CodeBlock, inst_offset: int, mnemonic: str,
                             target_address: int) -> bool:
        source_address = cls._block_layout_address(block)
        if source_address is None:
            return False
        source_address += inst_offset

        branch_range = cls._branch_range(mnemonic)
        if branch_range is None:
            return False

        delta = target_address - source_address
        return delta < -branch_range or delta > branch_range - 4

    @classmethod
    def _adr_out_of_range(cls, block: gtirb.CodeBlock, inst_offset: int, target_address: int) -> bool:
        source_address = cls._block_layout_address(block)
        if source_address is None:
            return False
        source_address += inst_offset

        adr_range = 1048576 - cls.ADR_SAFETY_MARGIN
        delta = target_address - source_address
        return delta < -adr_range or delta > adr_range - 4

    @classmethod
    def _branch_range(cls, mnemonic: str) -> Optional[int]:
        mnemonic = mnemonic.lower()
        if mnemonic in ("tbz", "tbnz"):
            return 32768 - cls.SHORT_BRANCH_SAFETY_MARGIN
        if mnemonic in ("cbz", "cbnz") or mnemonic.startswith("b."):
            return 1048576 - cls.CONDITIONAL_BRANCH_SAFETY_MARGIN
        if mnemonic in ("b", "bl"):
            return 134217728 - cls.DIRECT_BRANCH_SAFETY_MARGIN
        return None

    @staticmethod
    def _terminator_branch_target(block: gtirb.CodeBlock) -> Optional[gtirb.CodeBlock]:
        non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
        if not non_fallthrough_edges:
            return None

        branch_edge = non_fallthrough_edges[0]
        if branch_edge.label.type != gtirb.cfg.Edge.Type.Branch or not branch_edge.label.conditional:
            return None
        if not isinstance(branch_edge.target, gtirb.CodeBlock):
            return None
        return branch_edge.target

    def _skip_target(self, block: gtirb.CodeBlock, instructions, instruction_idx: int) -> Optional[_BranchTarget]:
        if instruction_idx != len(instructions) - 1:
            return None

        _, fallthrough_edges = distinguish_edges(block.outgoing_edges)
        if not fallthrough_edges or not isinstance(fallthrough_edges[0].target, gtirb.CodeBlock):
            return None

        fallthrough_target = fallthrough_edges[0].target
        symbol = get_or_insert_symbol(
            generate_distinct_label_name(".L__aarch64_long_branch_fallthrough_", fallthrough_target.uuid),
            fallthrough_target,
            self.module,
        )
        return _BranchTarget(symbol, 0, self._block_layout_address(fallthrough_target))

    @staticmethod
    def _immediate_target(instruction) -> Optional[int]:
        immediates = [operand.imm for operand in instruction.operands if operand.type == CS_OP_IMM]
        if immediates:
            return immediates[-1]
        return None

    @staticmethod
    def _encode_long_branch(instruction, inverted_branch: str) -> Optional[bytes]:
        if not inverted_branch:
            return None
        try:
            word = int.from_bytes(bytes(instruction.bytes), "little")
        except AttributeError:
            return None

        mnemonic = instruction.mnemonic.lower()
        if mnemonic in ("cbz", "cbnz") or mnemonic.startswith("b."):
            word &= ~0x00ffffe0
            word |= 2 << 5
            if mnemonic in ("cbz", "cbnz"):
                word ^= 1 << 24
            else:
                word ^= 1
        elif mnemonic in ("tbz", "tbnz"):
            word &= ~0x0007ffe0
            word |= 2 << 5
            word ^= 1 << 24
        else:
            return None

        # The inverted branch skips over the symbolic unconditional branch
        # when the original condition is false.
        return word.to_bytes(4, "little") + (0x14000000).to_bytes(4, "little")

    @staticmethod
    def _destination_register_number(instruction) -> Optional[int]:
        if not instruction.operands or instruction.operands[0].type != CS_OP_REG:
            return None

        reg_name = instruction.reg_name(instruction.operands[0].reg)
        if reg_name == "fp":
            return 29
        if reg_name == "lr":
            return 30
        if reg_name.startswith("w"):
            reg_name = "x" + reg_name[1:]
        if not reg_name.startswith("x"):
            return None

        try:
            reg_num = int(reg_name[1:])
        except ValueError:
            return None

        if reg_num < 0 or reg_num > 30:
            return None
        return reg_num

    @staticmethod
    def _encode_adrp_add(reg_num: int) -> bytes:
        adrp = 0x90000000 | reg_num
        add = 0x91000000 | (reg_num << 5) | reg_num
        return adrp.to_bytes(4, "little") + add.to_bytes(4, "little")

    @staticmethod
    def _encode_adrp_ldr(reg_num: int) -> bytes:
        adrp = 0x90000000 | reg_num
        ldr = 0xF9400000 | (reg_num << 5) | reg_num
        return adrp.to_bytes(4, "little") + ldr.to_bytes(4, "little")

    def _apply_replacements(self) -> None:
        for interval, replacements in self.replacements_by_interval.items():
            replacements.sort(key=lambda replacement: replacement.offset)
            if not replacements:
                continue
            old_size = interval.size
            self._rewrite_interval_contents(interval, replacements)
            self._rewrite_interval_symbolic_expressions(interval, replacements)
            self._rewrite_interval_blocks(interval, replacements)
            self._create_missing_skip_targets(interval, replacements)
            added_symexpr_offsets = self._add_replacement_symbolic_expressions(interval, replacements)
            self._rewrite_symbolic_expression_sizes(interval, replacements, added_symexpr_offsets)
            total_delta = sum(replacement.delta for replacement in replacements)
            interval.size = old_size + total_delta
            if interval.initialized_size is not None:
                interval.initialized_size = len(interval.contents)
                if interval.size < interval.initialized_size:
                    interval.size = interval.initialized_size

    @staticmethod
    def _rewrite_interval_contents(interval: gtirb.ByteInterval, replacements: List[_Replacement]) -> None:
        contents = bytes(interval.contents)
        rewritten = bytearray()
        source_offset = 0
        for replacement in replacements:
            rewritten += contents[source_offset:replacement.offset]
            rewritten += replacement.bytes
            source_offset = replacement.offset + 4
        rewritten += contents[source_offset:]
        interval.contents = bytes(rewritten)

    @staticmethod
    def _rewrite_interval_symbolic_expressions(interval: gtirb.ByteInterval,
                                               replacements: List[_Replacement]) -> None:
        new_symexprs = {}
        replacement_idx = 0
        delta = 0

        for offset, symexpr in sorted(interval.symbolic_expressions.items()):
            while (replacement_idx < len(replacements) and
                   offset >= replacements[replacement_idx].offset + 4):
                delta += replacements[replacement_idx].delta
                replacement_idx += 1

            if (replacement_idx < len(replacements) and
                    replacements[replacement_idx].offset <= offset < replacements[replacement_idx].offset + 4):
                continue

            new_symexprs[offset + delta] = symexpr

        interval.symbolic_expressions = new_symexprs

    @staticmethod
    def _rewrite_interval_blocks(interval: gtirb.ByteInterval, replacements: List[_Replacement]) -> None:
        replacement_offsets = [replacement.offset for replacement in replacements]
        prefix_delta = [0]
        for replacement in replacements:
            prefix_delta.append(prefix_delta[-1] + replacement.delta)

        for block in list(interval.blocks):
            original_start = block.offset
            original_end = block.offset + block.size
            before_idx = bisect_left(replacement_offsets, original_start)
            end_idx = bisect_left(replacement_offsets, original_end)
            delta_before = prefix_delta[before_idx]
            delta_inside = prefix_delta[end_idx] - prefix_delta[before_idx]
            block.offset = original_start + delta_before
            block.size += delta_inside

    def _create_missing_skip_targets(self, interval: gtirb.ByteInterval, replacements: List[_Replacement]) -> None:
        delta = 0
        for replacement in replacements:
            if not replacement.needs_skip_target:
                delta += replacement.delta
                continue
            if replacement.skip_target is None:
                skip_block = gtirb.CodeBlock(
                    size=0,
                    offset=replacement.offset + delta + len(replacement.bytes),
                    byte_interval=interval,
                )
                skip_symbol = gtirb.Symbol(
                    name=f".L__aarch64_long_branch_skip_{uuid4().hex}__teapot__",
                    payload=skip_block,
                    module=self.module,
                )
                replacement.skip_target = _BranchTarget(skip_symbol, 0, None)
            delta += replacement.delta

    @staticmethod
    def _add_replacement_symbolic_expressions(interval: gtirb.ByteInterval,
                                              replacements: List[_Replacement]) -> List[int]:
        added_offsets = []
        delta = 0
        for replacement in replacements:
            if replacement.symbolic_expressions is None:
                assert replacement.skip_target is not None
                assert replacement.target is not None
                symbolic_expressions = (
                    (0, replacement.skip_target, set()),
                    (4, replacement.target, set()),
                )
            else:
                symbolic_expressions = replacement.symbolic_expressions

            for relative_offset, target, attributes in symbolic_expressions:
                offset = replacement.offset + delta + relative_offset
                interval.symbolic_expressions[offset] = gtirb.SymAddrConst(
                    offset=target.addend,
                    symbol=target.symbol,
                    attributes=attributes,
                )
                added_offsets.append(offset)
            delta += replacement.delta
        return added_offsets

    def _rewrite_symbolic_expression_sizes(self, interval: gtirb.ByteInterval, replacements: List[_Replacement],
                                           added_offsets: List[int]) -> None:
        sizes = self.module.aux_data.get("symbolicExpressionSizes")
        if sizes is None:
            self.module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData(
                type_name="mapping<Offset,uint64_t>",
                data={},
            )
            sizes = self.module.aux_data["symbolicExpressionSizes"]

        new_sizes = {}
        replacement_idx = 0
        delta = 0
        for key, size in sizes.data.items():
            if key.element_id is not interval:
                new_sizes[key] = size
                continue

            offset = key.displacement
            while (replacement_idx < len(replacements) and
                   offset >= replacements[replacement_idx].offset + 4):
                delta += replacements[replacement_idx].delta
                replacement_idx += 1

            if (replacement_idx < len(replacements) and
                    replacements[replacement_idx].offset <= offset < replacements[replacement_idx].offset + 4):
                continue

            new_sizes[gtirb.Offset(element_id=interval, displacement=offset + delta)] = size

        for offset in added_offsets:
            new_sizes[gtirb.Offset(element_id=interval, displacement=offset)] = 4

        sizes.data = new_sizes
