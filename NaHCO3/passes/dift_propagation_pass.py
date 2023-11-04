import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints, InsertionContext)
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from gtirb_live_register_analysis import LiveRegisterManager
from capstone_gt import CsInsn, CS_OP_MEM, CS_OP_REG, CS_AC_READ, CS_AC_WRITE
from capstone_gt.x86 import X86_REG_EFLAGS
from typing import List, Set, Optional

from NaHCO3.config import BLACKLIST_FUNCTION_NAMES, SYMBOL_SUFFIX
from NaHCO3.patch_helpers import dift_add_reg_tag_snippet
from NaHCO3.utils.dift import reg_to_dift_reg_id
from NaHCO3.utils.rewriting import mem_access_to_symbolic_str
from NaHCO3.passes.mixins import InstVisitorPassMixin
from NaHCO3.patch_helpers import conditional_patch_wrapper, memlog_snippet


class DiftPropagationPass(InstVisitorPassMixin):
    section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, section: gtirb.Section, decoder: GtirbInstructionDecoder,
                 insert_memlog: bool):
        super().__init__(reg_manager, decoder)
        self.section = section
        self.insert_memlog = insert_memlog

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)

        self.visit_functions(functions, self.section)

    def visit_function(self, function: Function):
        if function.get_name() in BLACKLIST_FUNCTION_NAMES:
            return

        super().visit_function(function)

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if inst.mnemonic in ("nop", "ret", "call") or inst.mnemonic.startswith("j"):
            return

        if inst.mnemonic in ("push", "pop"):
            if inst.operands[0].type == CS_OP_MEM:
                print(f"Warning: {inst.mnemonic} with memory operand is not supported by DIFT pass")
                return
            elif inst.operands[0].type == CS_OP_REG:
                reg_operand_set = {self.reg_manager.abi.get_register(inst.reg_name(inst.operands[0].reg))}
            else:  # either constant or unsupported stuff
                reg_operand_set = {}

            if inst.mnemonic == "push":
                regs_read = reg_operand_set
                regs_write = {}
                mem_operand_str = "[rsp-8]"
                mem_operand_read, mem_operand_write = False, True
            else:  # pop
                regs_read = {}
                regs_write = reg_operand_set
                mem_operand_str = "[rsp]"
                mem_operand_read, mem_operand_write = True, False
        else:
            regs_read = self.__access_regs_to_register_set(inst, 0)
            regs_write = self.__access_regs_to_register_set(inst, 1)

            mem_operand_str, mem_operand_read, mem_operand_write = None, False, False

            mem_operand = next(iter(x for x in inst.operands if x.type == CS_OP_MEM), None) \
                if inst.mnemonic != "lea" else None
            if mem_operand is not None:
                mem_operand_str = mem_access_to_symbolic_str(block, inst, mem_operand)
                mem_operand_read = mem_operand.access & CS_AC_READ
                mem_operand_write = mem_operand.access & CS_AC_WRITE

        # Handle special instructions
        if inst.mnemonic == "xor" and regs_read == regs_write and not mem_operand_str:
            # xor rax, rax clears the target register
            clear_dest_tags = True
        elif (inst.mnemonic in ("mov", "push") or inst.mnemonic.startswith("cmov")) and len(regs_read) == 0:
            # is mov/push from a constant
            clear_dest_tags = True
        else:
            clear_dest_tags = False

        # Handle conditional moves
        conditional = inst.mnemonic[4:] if inst.mnemonic.startswith("cmov") else None

        if len(regs_write) > 0 or mem_operand_write:
            if not clear_dest_tags and (len(regs_read) == 0 or regs_read == regs_write) and not mem_operand_str:
                # Instruction does not involve tag propagation
                return

            self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
                self.reg_manager.allocate_registers(function, block, inst_idx)(
                    self.__build_dift_patch(regs_read, regs_write,
                                            conditional=conditional,
                                            clear_dest_tags=clear_dest_tags,
                                            mem_operand_str=mem_operand_str,
                                            mem_operand_read=mem_operand_read,
                                            mem_operand_write=mem_operand_write)
                )
            ))

    def __access_regs_to_register_set(self, inst: CsInsn, acc_type: int) -> Set[Register]:
        return {self.reg_manager.abi.get_register(inst.reg_name(r)) for r in inst.regs_access()[acc_type]
                if r != X86_REG_EFLAGS and inst.reg_name(r).lower() in self.reg_manager.abi._register_map}

    def __build_dift_patch(self, regs_read: Set[Register], regs_write: Set[Register], *,
                           conditional: Optional[str] = None,
                           clear_dest_tags: bool = False,  # Ignore tag propagation and zero out the tags
                           mem_operand_str: Optional[str] = None,
                           mem_operand_read: bool = False,
                           mem_operand_write: bool = False):
        if mem_operand_str is not None:
            assert mem_operand_read or mem_operand_write

        if self.insert_memlog and mem_operand_write:
            scratch_registers = 4
        elif mem_operand_str:
            scratch_registers = 2
        else:
            scratch_registers = 1

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            if self.insert_memlog and mem_operand_write:
                r1, r2, r3, r4 = ctx.scratch_registers
            elif mem_operand_str:
                r2, r4 = ctx.scratch_registers
                r1, r3 = None, None
            else:
                r4, = ctx.scratch_registers
                r1, r2, r3 = None, None, None

            asm = ""

            if mem_operand_str:
                asm += f"""
                    lea {r2}, {mem_operand_str}
                    btc {r2}, 45
                """

            asm += f"xor {r4:8l}, {r4:8l}\n"

            if not clear_dest_tags:
                for reg in regs_read:
                    asm += dift_add_reg_tag_snippet(r4, reg_add=reg)

                if mem_operand_read:
                    asm += f"or {r4:8l}, [{r2}]\n"

            for reg in regs_write:
                asm += f"mov dift_reg_tags+{reg_to_dift_reg_id(reg)}, {r4:8l}\n"

            if mem_operand_write:
                if self.insert_memlog:
                    asm += memlog_snippet(r2, 1, r1=r1, r2=r3, no_clobber_addr=True)
                asm += f"mov [{r2}], {r4:8l}\n"

            asm = conditional_patch_wrapper(asm, conditional, label_key="dift")

            return asm

        return patch
