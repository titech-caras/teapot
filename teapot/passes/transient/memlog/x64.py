import gtirb
from gtirb_functions import Function
from gtirb_rewriting import InsertionContext, Patch, patch_constraints
from gtirb_rewriting.assembly import Register, X86Syntax
from capstone_gt import CsInsn
from typing import Optional, Set

from teapot.passes.transient.memlog.base import TransientMemlogPassBase


class X64TransientMemlogPass(TransientMemlogPassBase):
    EXPECTED_ARCH = "x64"

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if inst.mnemonic in ("lea", "nop", "ret") or inst.mnemonic.startswith("j"):
            return

        mem_operand = self.arch.memory_operand(inst)
        if inst.mnemonic == "push" or inst.mnemonic == "call":
            mem_operand_str = "[rsp-8]"
            access_size = 8
        elif mem_operand is not None and self.arch.mem_operand_is_write(inst, mem_operand):
            mem_operand_str = self.arch.mem_operand_to_str(block, inst, mem_operand)
            access_size = mem_operand.size
        else:
            return

        self.insert_at(block, inst_offset, Patch.from_function(
            self.reg_manager.allocate_registers(function, block, inst_idx)(
                self._build_memlog_patch(inst, mem_operand_str, access_size,
                                         conditional=self.arch.conditional_move_suffix(inst)))))

    def _build_memlog_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                            conditional: Optional[str] = None):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3)
        def patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers

            asm = f"""
                lea {r2}, {mem_operand_str}
                {self.arch.memlog_snippet(r2, r1, r3, access_size)}
            """

            asm = self.arch.conditional_patch_wrapper(asm, conditional, label_key="memlog")
            return asm

        return patch
