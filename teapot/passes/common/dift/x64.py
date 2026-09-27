from dataclasses import dataclass
from typing import Optional, Set

import gtirb
from capstone import CS_OP_MEM, CS_OP_REG, CsInsn
from gtirb_rewriting import Patch, patch_constraints
from gtirb_rewriting.assembly import Register, X86Syntax

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import ScratchpadSlots
from teapot.configs.tags import TAG_SECRET, TAG_SECRET_INDIRECT
from teapot.passes.common.dift.base import DiftPassBase


@dataclass(frozen=True)
class X64DiftInstructionEffects:
    regs_read: Set[Register]
    regs_write: Set[Register]
    clear_dest_tags: bool
    conditional: Optional[str] = None
    mem_read_operand_str: Optional[str] = None
    mem_write_operand_str: Optional[str] = None
    mem_write_size: int = 0


@dataclass(frozen=True)
class X64RepStringEffects:
    kind: str
    width: int
    address_size: int
    source_segment: Optional[str]


class X64DiftOperandHelpers(DiftPassBase):
    EXPECTED_ARCH = "x64"
    section: gtirb.Section

    def _rep_string_effects(self, inst: CsInsn) -> Optional[X64RepStringEffects]:
        kind = self.arch.rep_string_kind(inst)
        if kind is None:
            return None
        memory = [op for op in inst.operands if op.type == CS_OP_MEM]
        segment = next((inst.reg_name(op.mem.segment) for op in memory
                        if inst.reg_name(op.mem.base) in {"rsi", "esi"}
                        and inst.reg_name(op.mem.segment) in {"fs", "gs"}), None)
        return X64RepStringEffects(kind, memory[0].size, inst.addr_size, segment)

    def _insert_rep_dift(self, effects, inst, inst_idx, inst_offset, block, function):
        self.reg_manager.add_live_registers(function, block, inst_idx, {
            self.arch.abi.get_register(name) for name in ("rsi", "rdi", "rcx")})
        self.reg_manager.add_live_registers(function, block, inst_idx + 1, {
            self.arch.abi.get_register(name) for name in ("rsi", "rcx")})
        self.insert_at(block, inst_offset, Patch.from_function(
            self.allocate_registers(function, block, inst_idx)(
                self._build_rep_capture_patch(effects))))
        # Use the post-instruction liveness boundary: RCX and LODS' RAX have
        # changed. The original REP stays intact, including fault/restart state.
        self.insert_at(block, inst_offset + inst.size, Patch.from_function(
            self.allocate_registers(function, block, inst_idx + 1)(
                self._build_rep_tags_patch(effects))))

    def _build_rep_capture_patch(self, effects):
        state = ScratchpadSlots.X64_REP_STATE

        @patch_constraints(x86_syntax=X86Syntax.INTEL,
                           scratch_registers=1 if effects.source_segment else 0,
                           reads_registers={"rsi", "rdi", "rcx"})
        def patch(ctx):
            asm = f"""
                mov qword ptr scratchpad+{state}, rsi
                mov qword ptr scratchpad+{state+8}, rdi
                mov qword ptr scratchpad+{state+16}, rcx
                {self._rep_flags_snippet()}
            """
            if effects.source_segment:
                tmp = ctx.scratch_registers[0]
                asm += f"rd{effects.source_segment}base {tmp}\n"
                asm += f"mov qword ptr scratchpad+{state+40}, {tmp}\n"
            return asm

        return patch

    @staticmethod
    def _rep_flags_snippet(*, restore=False):
        # PUSHFQ/POPFQ use a private slot, never the application's red zone.
        # Unlike LAHF, this captures DF as well as the arithmetic flags.
        state = ScratchpadSlots.X64_REP_STATE
        return f"""
            mov qword ptr scratchpad+{state+32}, rsp
            lea rsp, [rip+scratchpad+{state+24 if restore else state+32}]
            {'popfq' if restore else 'pushfq'}
            mov rsp, qword ptr scratchpad+{state+32}
        """

    def _build_rep_tags_patch(self, effects, *, extra_tag_operand=None, report_comparison=False,
                              propagate_tags=True, partial_accumulator_tag_operand=None):
        state = ScratchpadSlots.X64_REP_STATE

        @patch_constraints(x86_syntax=X86Syntax.INTEL,
                           scratch_registers=7 if self.insert_memlog else 5,
                           reads_registers={"rcx", "rsi"}, clobbers_flags=True)
        def patch(ctx):
            count, source, destination, addr, tag = ctx.scratch_registers[:5]
            if self.insert_memlog:
                history, tmp = ctx.scratch_registers[5:]
            bits = effects.address_size * 8
            count_name = "ecx" if bits == 32 else "rcx"
            pointer_size = "dword" if bits == 32 else "qword"
            label = f".L__rep_dift{SYMBOL_SUFFIX}"
            asm = f"""
                mov {count:{bits}}, {pointer_size} ptr scratchpad+{state+16}
                sub {count:{bits}}, {count_name}
                test {count}, {count}
                jz {label}_done
                mov {source:{bits}}, {pointer_size} ptr scratchpad+{state}
                mov {destination:{bits}}, {pointer_size} ptr scratchpad+{state+8}
                xor {tag:32}, {tag:32}
            """
            base_registers = {"rcx"}
            if effects.kind in {"movs", "lods", "cmps"}:
                base_registers.add("rsi")
            if effects.kind in {"movs", "stos", "cmps", "scas"}:
                base_registers.add("rdi")
            if effects.kind in {"stos", "scas"}:
                base_registers.add("rax")
            for name in sorted(base_registers):
                asm += self.arch.dift_or_reg_tag_snippet(tag, None, self.arch.abi.get_register(name))
            asm += f"mov byte ptr scratchpad+{state+48}, {tag:8l}\n"

            if effects.kind == "lods":
                # Only the last completed load determines the accumulator.
                asm += f"""
                    mov {source:{bits}}, {'esi' if bits == 32 else 'rsi'}
                    test qword ptr scratchpad+{state+24}, 0x400
                    jnz {label}_lods_backward
                    sub {source:{bits}}, {effects.width}
                    jmp {label}_loop
                {label}_lods_backward:
                    add {source:{bits}}, {effects.width}
                """

            asm += f"{label}_loop:\nmovzx {tag:32}, byte ptr scratchpad+{state+48}\n"
            if extra_tag_operand is not None:
                asm += f"or {tag:8l}, {extra_tag_operand}\n"
            read_pointers = []
            if effects.kind in {"movs", "lods", "cmps"}:
                read_pointers.append((source, effects.source_segment))
            if effects.kind in {"cmps", "scas"}:
                read_pointers.append((destination, None))
            for pointer, segment in read_pointers:
                for offset in range(effects.width):
                    asm += f"lea {addr}, [{pointer}+{offset}]\n"
                    if segment:
                        asm += f"add {addr}, qword ptr scratchpad+{state+40}\n"
                    asm += self.arch.dift_shadow_addr_snippet(addr, None, self.dift_layout.xor_mask)
                    asm += f"or {tag:8l}, byte ptr [{addr}]\n"

            if effects.kind in {"movs", "stos"}:
                # Copy one element at a time in hardware iteration order. A
                # bulk memmove of tags would be wrong for overlapping MOVS.
                for offset in range(effects.width):
                    asm += f"lea {addr}, [{destination}+{offset}]\n"
                    asm += self.arch.dift_shadow_addr_snippet(addr, None, self.dift_layout.xor_mask)
                    if self.insert_memlog:
                        asm += self.arch.memlog_snippet(addr, history, tmp, 1, no_clobber_addr=True)
                    asm += f"mov byte ptr [{addr}], {tag:8l}\n"
            elif effects.kind == "lods":
                if effects.width < 4:
                    if partial_accumulator_tag_operand is None:
                        asm += self.arch.dift_or_reg_tag_snippet(tag, None, self.arch.abi.get_register("rax"))
                    else:
                        asm += f"or {tag:8l}, {partial_accumulator_tag_operand}\n"
                asm += self.arch.dift_store_reg_tag_snippet(tag, None, self.arch.abi.get_register("rax"))
                asm += f"jmp {label}_indices\n"
            else:
                # Early termination makes the final count/indices depend on
                # every comparison actually executed, not the unvisited suffix.
                asm += f"mov byte ptr scratchpad+{state+48}, {tag:8l}\n"

            asm += f"""
                dec {count}
                jz {label}_indices
                test qword ptr scratchpad+{state+24}, 0x400
                jnz {label}_backward
                add {source:{bits}}, {effects.width}
                add {destination:{bits}}, {effects.width}
                jmp {label}_loop
            {label}_backward:
                sub {source:{bits}}, {effects.width}
                sub {destination:{bits}}, {effects.width}
                jmp {label}_loop
            {label}_indices:
            """
            if effects.kind in {"cmps", "scas"}:
                if report_comparison:
                    asm += f"test {tag:8l}, {TAG_SECRET | TAG_SECRET_INDIRECT}\n"
                    asm += f"jz {label}_port_done\n"
                    asm += self.arch.report_gadget_snippet("KASPER_PORT", tag_reg=tag)
                    asm += f"{label}_port_done:\n"
                if propagate_tags:
                    for name in sorted(base_registers - {"rax"}):
                        asm += self.arch.dift_store_reg_tag_snippet(tag, None, self.arch.abi.get_register(name))
            else:
                asm += f"xor {tag:32}, {tag:32}\n"
                asm += self.arch.dift_or_reg_tag_snippet(tag, None, self.arch.abi.get_register("rcx"))
                for name in sorted(base_registers & {"rsi", "rdi"}):
                    index = self.arch.dift_register_id(self.arch.abi.get_register(name))
                    asm += f"or byte ptr dift_reg_tags+{index}, {tag:8l}\n"
            asm += f"{label}_done:\nnop\n"
            return asm

        return patch

    def _x64_instruction_effects(self, block: gtirb.CodeBlock, inst: CsInsn) -> Optional[X64DiftInstructionEffects]:
        if inst.mnemonic.startswith("rep"):
            print("Warning: DIFT Propagation does not support non-string REP form", inst)
            return None

        if inst.mnemonic in ("push", "pop"):
            reg_operand_set = set()
            mem_operand = None
            if inst.operands[0].type == CS_OP_MEM:
                mem_operand = inst.operands[0]
            elif inst.operands[0].type == CS_OP_REG:
                reg_operand_set = {self.reg_manager.abi.get_register(inst.reg_name(inst.operands[0].reg))}

            if inst.mnemonic == "push":
                regs_read = reg_operand_set
                regs_write = set()
                mem_operand_read_str = self.arch.mem_operand_to_str(block, inst, mem_operand) if mem_operand else None
                mem_operand_write_str, mem_operand_write_size = self.arch.implicit_memory_write(inst)
            else:  # pop
                regs_read = set()
                regs_write = reg_operand_set
                mem_operand_read_str = "[rsp]"
                mem_operand_write_str = self.arch.mem_operand_to_str(block, inst, mem_operand) if mem_operand else None
                mem_operand_write_size = mem_operand.size if mem_operand else 0
        else:
            regs_read = self.arch.access_registers(self.reg_manager.abi, inst, 0)
            regs_write = self.arch.access_registers(self.reg_manager.abi, inst, 1)

            mem_operand_str, mem_operand_read_str, mem_operand_write_str, mem_operand_write_size = None, None, None, None

            mem_operand = self.arch.memory_operand(inst) if inst.mnemonic != "lea" else None
            if mem_operand is not None:
                mem_operand_str = self.arch.mem_operand_to_str(block, inst, mem_operand)
                mem_operand_read_str = mem_operand_str if self.arch.mem_operand_is_read(inst, mem_operand) else None
                mem_operand_write_str = mem_operand_str if self.arch.mem_operand_is_write(inst, mem_operand) else None
                mem_operand_write_size = self.arch.mem_operand_size(inst, mem_operand) \
                    if self.arch.mem_operand_is_write(inst, mem_operand) else None

        # Handle special instructions
        clear_dest_tags = self.arch.dift_clears_destination_tags(inst)

        # Handle conditional moves
        return X64DiftInstructionEffects(
            regs_read=regs_read,
            regs_write=regs_write,
            clear_dest_tags=clear_dest_tags,
            conditional=self.arch.conditional_move_suffix(inst),
            mem_read_operand_str=mem_operand_read_str,
            mem_write_operand_str=mem_operand_write_str,
            mem_write_size=mem_operand_write_size or 0)
