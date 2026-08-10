"""Temporary RISC-V compatibility shims for GTIRB rewriting.

Keep this module isolated from normal architecture snippets. It patches
gtirb-capstone and gtirb-rewriting gaps for RV64 modules described through
archInfo, and should disappear once upstream RISC-V support covers these paths.
"""

import os
import re
import sys
from bisect import bisect_left

import capstone
import capstone.riscv
import gtirb
from gtirb_capstone import instructions
from gtirb_capstone.instructions import MemoryAccess


def _module_is_riscv64(module: gtirb.Module) -> bool:
    if module is None or "archInfo" not in module.aux_data:
        return False

    arch_info = module.aux_data["archInfo"].data
    return isinstance(arch_info, dict) and str(arch_info.get("ISA", "")).upper() == "RISCV64"


def install_riscv64_decoder_compat() -> None:
    decoder_cls = instructions.GtirbInstructionDecoder
    if getattr(decoder_cls, "_teapot_riscv64_compat", False):
        return

    original_get_block_decoder = decoder_cls._get_block_decoder
    original_get_memory_accesses = decoder_cls.get_memory_accesses

    def get_block_decoder(self, block: gtirb.CodeBlock, opts: int = 0):
        if self._arch == gtirb.Module.ISA.ValidButUnsupported and _module_is_riscv64(block.module):
            if block.module and block.module.byte_order == gtirb.Module.ByteOrder.Big:
                endian = capstone.CS_MODE_BIG_ENDIAN
            else:
                endian = capstone.CS_MODE_LITTLE_ENDIAN

            mode = capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC | endian | opts
            key = ("teapot-riscv64", mode)
            if key not in self._cs:
                self._cs[key] = cs = capstone.Cs(capstone.CS_ARCH_RISCV, mode)
                cs.detail = True
            return self._cs[key]

        return original_get_block_decoder(self, block, opts)

    def get_memory_accesses(self, block: gtirb.CodeBlock):
        if self._arch != gtirb.Module.ISA.ValidButUnsupported or not _module_is_riscv64(block.module):
            return original_get_memory_accesses(self, block)

        memory_accesses = []
        for insn in self.get_instructions(block):
            for op in insn.operands:
                if op.type == capstone.riscv.RISCV_OP_MEM:
                    memory_accesses.append(
                        MemoryAccess(
                            addr=insn.address,
                            type=self.get_access_type(op),
                            op_mem=op.mem,
                        )
                    )
        return memory_accesses

    decoder_cls._get_block_decoder = get_block_decoder
    decoder_cls.get_memory_accesses = get_memory_accesses
    decoder_cls._teapot_riscv64_compat = True


def install_riscv64_rewriting_compat() -> None:
    import gtirb_rewriting.assembler._mc_utils as mc_utils
    import gtirb_rewriting.assembler.assembler as assembler
    import gtirb_rewriting.rewriting as rewriting
    import gtirb_rewriting.utils as rewriting_utils
    import mcasm

    if getattr(rewriting_utils, "_teapot_riscv64_compat", False):
        return

    riscv_asm_lines = []
    original_target_triple = rewriting_utils._target_triple
    original_assemble = assembler.Assembler.assemble
    original_fixup_to_symbolic_operand = assembler._Streamer._fixup_to_symbolic_operand
    original_apply = rewriting.RewritingContext.apply
    original_insert_at = rewriting.RewritingContext.insert_at
    # Insertions are registered before apply; discard the interval index when
    # rewriting begins so later pass managers observe relocated expressions.
    relocation_offsets_cache = {}

    def target_triple(isa: gtirb.Module.ISA, file_format: gtirb.Module.FileFormat) -> str:
        if isa == gtirb.Module.ISA.ValidButUnsupported and file_format == gtirb.Module.FileFormat.ELF:
            return "riscv64-pc-linux"
        return original_target_triple(isa, file_format)

    def assemble(self, asm, *args, **kwargs):
        nonlocal riscv_asm_lines
        old_lines = riscv_asm_lines
        riscv_asm_lines = asm.splitlines()
        try:
            return original_assemble(self, asm, *args, **kwargs)
        finally:
            riscv_asm_lines = old_lines

    def symbol_from_line(lineno: int):
        if lineno <= 0 or lineno > len(riscv_asm_lines):
            return None

        search_order = [lineno - 1]
        for distance in range(1, 5):
            search_order.extend((lineno - 1 - distance, lineno - 1 + distance))

        for idx in search_order:
            if idx < 0 or idx >= len(riscv_asm_lines):
                continue

            line = riscv_asm_lines[idx]
            match = re.search(r"%[A-Za-z0-9_]+\(([^)]+)\)", line)
            if match:
                return match.group(1).strip()
            match = re.search(r"\b(?:call|tail)\s+([^\s,#]+)", line)
            if match:
                return match.group(1).strip()
        return None

    def split_symbol_addend(symbol_ref: str):
        match = re.match(r"^(.+?)([+-](?:0x[0-9A-Fa-f]+|\d+))$", symbol_ref.strip())
        if match is None:
            return symbol_ref.strip(), 0
        return match.group(1).strip(), int(match.group(2), 0)

    def normalize_symbol_ref(symbol_name: str):
        if symbol_name.endswith("@plt"):
            return symbol_name[:-4], {assembler.compat_proto.PLT}
        return symbol_name, set()

    def resolve_symbol(self, symbol_name: str, loc, allow_proxy: bool = False):
        sym = self._symbol_lookup(symbol_name)
        if sym is not None:
            return sym

        if not allow_proxy and not self._state.allow_undef_symbols:
            raise assembler.UndefSymbolError._make(
                f"{symbol_name} is an undefined symbol reference",
                loc,
            )

        proxy = gtirb.ProxyBlock()
        sym = gtirb.Symbol(symbol_name, payload=proxy)
        self._state.local_symbols[symbol_name] = sym
        self._state.proxies.add(proxy)
        return sym

    def fixup_to_symbolic_operand(self, fixup, data, is_branch, loc):
        if (self._state.target.isa == gtirb.Module.ISA.ValidButUnsupported and
                isinstance(fixup.value, mcasm.mc.TargetExpr)):
            attrs = set()
            kind_name = fixup.kind_info.name
            if kind_name == "fixup_riscv_hi20":
                attrs.add(assembler.compat_proto.HI)
            elif kind_name in ("fixup_riscv_lo12_i", "fixup_riscv_lo12_s"):
                attrs.add(assembler.compat_proto.LO)
            elif kind_name == "fixup_riscv_pcrel_hi20":
                attrs.update({assembler.compat_proto.PCREL, assembler.compat_proto.HI})
            elif kind_name in ("fixup_riscv_pcrel_lo12_i", "fixup_riscv_pcrel_lo12_s"):
                attrs.update({assembler.compat_proto.PCREL, assembler.compat_proto.LO})
            elif kind_name == "fixup_riscv_got_hi20":
                attrs.update({assembler.compat_proto.GOT, assembler.compat_proto.PCREL, assembler.compat_proto.HI})
            elif kind_name == "fixup_riscv_call":
                pass
            elif kind_name == "fixup_riscv_call_plt":
                attrs.add(assembler.compat_proto.PLT)
                pass
            else:
                if os.environ.get("TEAPOT_DEBUG_RISCV_FIXUPS"):
                    lineno = loc.lineno if loc is not None else 0
                    print(
                        "riscv unhandled target fixup:",
                        f"kind={kind_name}",
                        f"value={fixup.value!r}",
                        f"is_branch={is_branch}",
                        f"loc={loc}",
                        f"line={riscv_asm_lines[lineno - 1] if 0 < lineno <= len(riscv_asm_lines) else None!r}",
                        file=sys.stderr,
                    )
                return original_fixup_to_symbolic_operand(self, fixup, data, is_branch, loc)

            symbol_ref = symbol_from_line(loc.lineno if loc is not None else 0)
            if symbol_ref is None:
                if os.environ.get("TEAPOT_DEBUG_RISCV_FIXUPS"):
                    print(
                        "riscv fixup missing symbol:",
                        f"kind={kind_name}",
                        f"value={fixup.value!r}",
                        f"loc={loc}",
                        f"line={riscv_asm_lines[loc.lineno - 1] if loc is not None and 0 < loc.lineno <= len(riscv_asm_lines) else None!r}",
                        file=sys.stderr,
                    )
                return original_fixup_to_symbolic_operand(self, fixup, data, is_branch, loc)
            symbol_name, addend = split_symbol_addend(symbol_ref)
            symbol_name, extra_attrs = normalize_symbol_ref(symbol_name)
            attrs.update(extra_attrs)
            allow_proxy = assembler.compat_proto.PLT in attrs
            return gtirb.SymAddrConst(addend, resolve_symbol(self, symbol_name, loc, allow_proxy), attrs)

        try:
            return original_fixup_to_symbolic_operand(self, fixup, data, is_branch, loc)
        except assembler.UnsupportedAssemblyError:
            if (self._state.target.isa == gtirb.Module.ISA.ValidButUnsupported and
                    os.environ.get("TEAPOT_DEBUG_RISCV_FIXUPS")):
                lineno = loc.lineno if loc is not None else 0
                print(
                    "riscv unsupported fixup:",
                    f"kind={fixup.kind_info.name}",
                    f"value_type={type(fixup.value).__name__}",
                    f"value={fixup.value!r}",
                    f"is_branch={is_branch}",
                    f"loc={loc}",
                    f"line={riscv_asm_lines[lineno - 1] if 0 < lineno <= len(riscv_asm_lines) else None!r}",
                    file=sys.stderr,
                )
            raise

    def is_riscv_hi_relocation(symbolic) -> bool:
        if not isinstance(symbolic, gtirb.SymAddrConst):
            return False

        return (
            gtirb.SymbolicExpression.Attribute.HI in symbolic.attributes or
            gtirb.SymbolicExpression.Attribute.GOT in symbolic.attributes or
            gtirb.SymbolicExpression.Attribute.TLSGD in symbolic.attributes
        )

    def is_riscv_insert_protected_hi_relocation(symbolic) -> bool:
        if not is_riscv_hi_relocation(symbolic):
            return False

        return (
            gtirb.SymbolicExpression.Attribute.PCREL in symbolic.attributes or
            gtirb.SymbolicExpression.Attribute.GOT in symbolic.attributes or
            gtirb.SymbolicExpression.Attribute.TLSGD in symbolic.attributes
        )

    def is_riscv_lo_relocation(symbolic) -> bool:
        return (
            isinstance(symbolic, gtirb.SymAddrConst) and
            gtirb.SymbolicExpression.Attribute.LO in symbolic.attributes
        )

    def is_riscv_call_relocation(symbolic) -> bool:
        if not isinstance(symbolic, gtirb.SymAddrConst):
            return False

        return (
            gtirb.SymbolicExpression.Attribute.PLT in symbolic.attributes or
            not any(
                attr in symbolic.attributes
                for attr in (
                    gtirb.SymbolicExpression.Attribute.HI,
                    gtirb.SymbolicExpression.Attribute.LO,
                    gtirb.SymbolicExpression.Attribute.GOT,
                    gtirb.SymbolicExpression.Attribute.PCREL,
                    gtirb.SymbolicExpression.Attribute.TLSGD,
                )
            )
        )

    def riscv_instruction_size(block: gtirb.ByteBlock, byte_interval_offset: int) -> int:
        contents = block.byte_interval.contents
        if byte_interval_offset < 0 or byte_interval_offset >= len(contents):
            return 4

        first_byte = contents[byte_interval_offset]
        return 2 if (first_byte & 0x3) != 0x3 else 4

    def is_riscv_auipc_jalr_pair(block: gtirb.ByteBlock, byte_interval_offset: int) -> bool:
        contents = block.byte_interval.contents
        if byte_interval_offset < 0 or byte_interval_offset + 8 > len(contents):
            return False

        first = int.from_bytes(contents[byte_interval_offset:byte_interval_offset + 4], "little")
        second = int.from_bytes(contents[byte_interval_offset + 4:byte_interval_offset + 8], "little")
        if (first & 0x7f) != 0x17 or (second & 0x7f) != 0x67:
            return False

        auipc_rd = (first >> 7) & 0x1f
        jalr_rs1 = (second >> 15) & 0x1f
        return auipc_rd != 0 and auipc_rd == jalr_rs1

    def riscv_relocation_offsets(block: gtirb.ByteBlock):
        byte_interval = block.byte_interval
        offsets = relocation_offsets_cache.get(byte_interval)
        if offsets is None:
            offsets = tuple(sorted(byte_interval.symbolic_expressions))
            relocation_offsets_cache[byte_interval] = offsets

        block_start = block.offset
        block_end = block.offset + block.size
        start_idx = bisect_left(offsets, block_start)
        end_idx = bisect_left(offsets, block_end, start_idx)
        return offsets[start_idx:end_idx]

    def safe_riscv64_insert_offset(block: gtirb.ByteBlock, offset: int) -> int:
        if not isinstance(block, gtirb.CodeBlock) or not _module_is_riscv64(block.module):
            return offset
        if offset < 0 or offset > block.size:
            return offset

        block_start = block.offset
        block_end = block.offset + block.size
        insert_offset = block_start + offset
        symbolic_expressions = block.byte_interval.symbolic_expressions
        relocation_offsets = riscv_relocation_offsets(block)

        for call_offset in relocation_offsets:
            if not is_riscv_call_relocation(symbolic_expressions[call_offset]):
                continue
            if not is_riscv_auipc_jalr_pair(block, call_offset):
                continue
            after_call_offset = call_offset + 8
            if call_offset <= insert_offset < after_call_offset:
                return min(after_call_offset, block_end) - block_start

        for idx, hi_offset in enumerate(relocation_offsets):
            if not is_riscv_insert_protected_hi_relocation(symbolic_expressions[hi_offset]):
                continue

            lo_offset = None
            for expr_offset in relocation_offsets[idx + 1:]:
                symbolic = symbolic_expressions[expr_offset]
                if is_riscv_insert_protected_hi_relocation(symbolic):
                    break
                if is_riscv_lo_relocation(symbolic):
                    lo_offset = expr_offset
                    break

            if lo_offset is None:
                continue
            if hi_offset <= insert_offset <= lo_offset:
                after_lo_offset = lo_offset + riscv_instruction_size(block, lo_offset)
                return min(after_lo_offset, block_end) - block_start

        return offset

    def apply(self) -> None:
        relocation_offsets_cache.clear()
        return original_apply(self)

    def insert_at(self, *args, **kwargs) -> None:
        if len(args) == 3 and not kwargs:
            block, offset, patch = args
            return original_insert_at(self, block, safe_riscv64_insert_offset(block, offset), patch)
        elif len(args) == 4 and not kwargs:
            function, block, offset, patch = args
            return original_insert_at(self, function, block, safe_riscv64_insert_offset(block, offset), patch)

        return original_insert_at(self, *args, **kwargs)

    original_emit_instruction = assembler._Streamer.emit_instruction

    def emit_instruction(self, state, inst, data, fixups):
        if (self._state.target.isa == gtirb.Module.ISA.ValidButUnsupported and
                inst.name == "JAL" and inst.desc.is_call and not inst.desc.is_branch and
                len(data) >= 4 and ((int.from_bytes(data[:4], "little") >> 7) & 0x1f) == 0):
            for fixup in fixups:
                pos = len(self._state.current_section.data) + fixup.offset
                self._state.current_section.symbolic_expressions[pos] = (
                    self._fixup_to_symbolic_operand(fixup, data, True, state.loc)
                )
                self._state.current_section.symbolic_expression_sizes[pos] = fixup.kind_info.bit_size // 8

            self._append_data(data, state.loc)
            self._state.blocks_with_code.add(self._state.current_block)
            direct, target = self._resolve_instruction_target(data, inst, fixups, state.loc)
            self._state.cfg.add(gtirb.Edge(
                source=self._state.current_block,
                target=target,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Branch, conditional=False, direct=direct),
            ))
            self._split_block()
            return

        return original_emit_instruction(self, state, inst, data, fixups)

    rewriting_utils._target_triple = target_triple
    assembler._target_triple = target_triple
    assembler.Assembler.assemble = assemble
    assembler._Streamer._fixup_to_symbolic_operand = fixup_to_symbolic_operand
    assembler._Streamer.emit_instruction = emit_instruction
    rewriting.RewritingContext.apply = apply
    rewriting.RewritingContext.insert_at = insert_at
    mc_utils._INDIRECT_CALL_INSTRS[gtirb.Module.ISA.ValidButUnsupported] = {"JALR"}
    rewriting_utils._teapot_riscv64_compat = True
