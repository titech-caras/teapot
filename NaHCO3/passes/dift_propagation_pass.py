import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from gtirb_live_register_analysis import LiveRegisterManager
from capstone_gt import CsInsn, CS_OP_MEM, CS_AC_READ, CS_AC_WRITE
from capstone_gt.x86 import X86_REG_EFLAGS
from typing import List, Set, Optional
from dataclasses import dataclass

from NaHCO3.config import BLACKLIST_FUNCTION_NAMES
from NaHCO3.passes.mixins import InstVisitorPassMixin


class DiftPropagationPass(InstVisitorPassMixin):
    section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, section: gtirb.Section, decoder: GtirbInstructionDecoder):
        super().__init__(reg_manager, decoder)
        self.section = section

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

        # TODO: deal with push/pop properly

        regs_read = {self.reg_manager.abi.get_register(inst.reg_name(r))
                     for r in inst.regs_access()[0] if r != X86_REG_EFLAGS and inst.reg_name(r).lower() in self.reg_manager.abi._register_map}
        regs_write = {self.reg_manager.abi.get_register(inst.reg_name(r))
                      for r in inst.regs_access()[1] if r != X86_REG_EFLAGS and inst.reg_name(r).lower() in self.reg_manager.abi._register_map}

        mem_operand_str, mem_operand_read, mem_operand_write = None, False, False

        mem_operand = next(iter(x for x in inst.operands if x.type == CS_OP_MEM), None) \
            if inst.mnemonic != "lea" else None
        if mem_operand is not None:
            mem_operand_read = mem_operand.access & CS_AC_READ
            mem_operand_write = mem_operand.access & CS_AC_WRITE

            symexp = operand_symbolic_expression(block, inst, mem_operand)
            try:
                mem_operand_str = mem_access_to_str(inst, mem_operand.mem, symexp)
            except NotImplementedError:
                print(f"Warning: unsupported symexp at {inst}")
                mem_operand_str = mem_access_to_str(inst, mem_operand.mem, None)

        if regs_read == regs_write and not mem_operand:
            return

        if len(regs_write) > 0 or mem_operand_write:
            self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
                self.reg_manager.allocate_registers(function, block, inst_idx)(
                    self.__build_dift_patch(regs_read, regs_write,
                                            mem_operand_str=mem_operand_str,
                                            mem_operand_read=mem_operand_read,
                                            mem_operand_write=mem_operand_write)
                )
            ))

    @staticmethod
    def __reg_to_dift_reg_id(reg: Register) -> int:
        if reg.name.startswith("xmm"):  # xmm0~xmm31 -> 16~47
            return int(reg.name.replace("xmm", "")) + 16
        else:
            # rax~r15 -> 0~15
            mapping = {k: v for v, k in enumerate([
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"])}
            return mapping[reg.name]

    def __build_dift_patch(self, regs_read: Set[Register], regs_write: Set[Register], *,
                           mem_operand_str: Optional[str] = None,
                           mem_operand_read: bool = False, mem_operand_write: bool = False):
        if mem_operand_str is not None:
            assert mem_operand_read or mem_operand_write

        dift_reg_ids_read = [self.__reg_to_dift_reg_id(reg) for reg in regs_read]
        dift_reg_ids_write = [self.__reg_to_dift_reg_id(reg) for reg in regs_write]

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=2, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            r1, r2 = ctx.scratch_registers
            asm = ""

            if mem_operand_str:
                asm += f"""
                    lea {r2}, {mem_operand_str}
                    btc {r2}, 45
                """

            asm += f"xor {r1}, {r1}\n"

            for reg_id in dift_reg_ids_read:
                asm += f"or {r1}, dift_reg_tags+{reg_id}\n"

            if mem_operand_read:
                asm += f"or {r1}, [{r2}]\n"

            for reg_id in dift_reg_ids_write:
                asm += f"mov dift_reg_tags+{reg_id}, {r1}\n"

            if mem_operand_write:
                asm += f"mov [{r2}], {r1}\n"

            return asm

        return patch
