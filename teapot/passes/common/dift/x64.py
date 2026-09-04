from dataclasses import dataclass
from typing import Optional, Set

import gtirb
from capstone_gt import CS_AC_READ, CS_OP_MEM, CS_OP_REG, CsInsn
from gtirb_functions import Function
from gtirb_rewriting import InsertionContext, Patch, patch_constraints
from gtirb_rewriting.assembly import Register, X86Syntax

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.passes.common.dift.base import DiftPropagationBase


@dataclass(frozen=True)
class X64DiftInstructionEffects:
    regs_read: Set[Register]
    regs_write: Set[Register]
    clear_dest_tags: bool
    conditional: Optional[str] = None
    mem_read_operand_str: Optional[str] = None
    mem_write_operand_str: Optional[str] = None
    mem_write_size: int = 0


class X64DiftPropagationPass(DiftPropagationBase):
    EXPECTED_ARCH = "x64"
    section: gtirb.Section

    def _x64_instruction_effects(self, block: gtirb.CodeBlock, inst: CsInsn) -> Optional[X64DiftInstructionEffects]:
        if inst.mnemonic.startswith("rep"):
            # FIXME: support rep
            print(f"Warning: DIFT Propagation does not support ", inst)
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
                mem_operand_write_str = "[rsp-8]"
                mem_operand_write_size = 8
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
                mem_operand_read_str = mem_operand_str if mem_operand.access & CS_AC_READ else None
                mem_operand_write_str = mem_operand_str if self.arch.mem_operand_is_write(inst, mem_operand) else None
                mem_operand_write_size = mem_operand.size if self.arch.mem_operand_is_write(inst, mem_operand) else None

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

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if self.arch.dift_should_skip_instruction(inst):
            return

        effects = self._x64_instruction_effects(block, inst)
        if effects is None:
            return

        if len(effects.regs_write) > 0 or effects.mem_write_operand_str:
            if not effects.clear_dest_tags:
                if effects.regs_read == effects.regs_write and not effects.mem_read_operand_str and not effects.mem_write_operand_str:
                    # Reg instruction that does not involve tag propagation
                    return
                if (effects.mem_read_operand_str == effects.mem_write_operand_str
                        and len(effects.regs_read) == 0 and len(effects.regs_write) == 0):
                    # Mem instruction that does not involve tag propagation
                    return

            self.insert_at(block, inst_offset, Patch.from_function(
                self.reg_manager.allocate_registers(function, block, inst_idx)(
                    self._build_dift_patch(effects.regs_read, effects.regs_write,
                                           conditional=effects.conditional,
                                           clear_dest_tags=effects.clear_dest_tags,
                                           mem_read_operand_str=effects.mem_read_operand_str,
                                           mem_write_operand_str=effects.mem_write_operand_str,
                                           mem_write_size=effects.mem_write_size)
                )
            ))

    def _build_dift_patch(self, regs_read: Set[Register], regs_write: Set[Register], *,
                          conditional: Optional[str] = None,
                          clear_dest_tags: bool = False,  # Ignore tag propagation and zero out the tags
                          mem_read_operand_str: Optional[str] = None,
                          mem_write_operand_str: Optional[str] = None,
                          mem_write_size: Optional[int] = None):
        if self.insert_memlog and mem_write_operand_str:
            scratch_registers = 4
        elif mem_read_operand_str or mem_write_operand_str:
            scratch_registers = 3
        else:
            scratch_registers = 2

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            # FIXME: refactor please

            if self.insert_memlog and mem_write_operand_str:
                r1, r2, r3, r4 = ctx.scratch_registers
            elif mem_read_operand_str or mem_write_operand_str:
                r2, r3, r4 = ctx.scratch_registers
                r1 = None
            else:
                r3, r4, = ctx.scratch_registers
                r1, r2 = None, None

            dift_done_label = f".L__dift_done{SYMBOL_SUFFIX}"

            asm = ""

            if mem_read_operand_str:
                asm += self.arch.effective_address_snippet(
                    r2, mem_read_operand_str, r3)
                asm += self.arch.dift_shadow_addr_snippet(
                    r2, None, self.dift_layout.xor_mask)

            asm += self.arch.clear_register_snippet(r4)

            if not clear_dest_tags:
                for reg in regs_read:
                    asm += self.arch.dift_or_reg_tag_snippet(r4, None, reg)

                if mem_read_operand_str:
                    asm += f"or {r4:8l}, [{r2}]\n"

            for reg in regs_write:
                asm += self.arch.dift_store_reg_tag_snippet(r4, None, reg)

            if mem_write_operand_str:
                if mem_write_operand_str != mem_read_operand_str:
                    asm += self.arch.effective_address_snippet(
                        r2, mem_write_operand_str, r3)
                    asm += self.arch.dift_shadow_addr_snippet(
                        r2, None, self.dift_layout.xor_mask)

                extended_size = min(mem_write_size, 8)
                r4_ext = r4.sizes["8l" if extended_size == 1 else str(extended_size * 8)]
                if extended_size > 1:
                    asm += f"""
                        mov {r3}, 0x{"01" * extended_size}
                        imul {r4}, {r3}
                    """

                for i in range(0, mem_write_size, 8):
                    if self.insert_memlog:
                        asm += self.arch.memlog_snippet(
                            r2, r1, r3, 1, no_clobber_addr=True)
                    asm += f"""
                        mov [{r2}], {r4_ext}
                        add {r2}, 8
                    """

            # Check if the memory operand policy pass requests a tag update
            if mem_read_operand_str:
                asm += self.arch.dift_apply_queued_tag_snippet(r4, r3, None, dift_done_label)

            asm += f"""
            {dift_done_label}:
                nop
            """

            asm = self.arch.conditional_patch_wrapper(
                asm, conditional, label_key="dift",
                skip_label_name=dift_done_label, insert_skip_label=False)

            return asm

        return patch
