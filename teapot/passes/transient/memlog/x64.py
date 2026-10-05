import gtirb
from gtirb_functions import Function
from gtirb_rewriting import InsertionContext, Patch, patch_constraints
from gtirb_rewriting.assembly import Register, X86Syntax
from capstone import CsInsn
from capstone.x86 import X86_REG_FS, X86_REG_GS, X86_REG_RIP
from typing import Optional, Set

from teapot.passes.transient.memlog.base import TransientMemlogPassBase


class X64TransientMemlogPass(TransientMemlogPassBase):
    EXPECTED_ARCH = "x64"

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if self.arch.rep_string_kind(inst) is not None:
            # The bounded REP loop logs each element, including backward copies.
            return
        if self.arch.instruction_must_rollback(inst):
            # Unsupported state-image stores are preceded by a restore point;
            # do not misleadingly log the decoder's nominal eight-byte operand.
            return
        if inst.mnemonic in ("lea", "nop", "ret") or inst.mnemonic.startswith("j"):
            return

        mem_operand = self.arch.memory_operand(inst)
        implicit = self.arch.implicit_memory_write(inst)
        if implicit is not None:
            mem_operand_str, access_size = implicit
        elif mem_operand is not None and self.arch.mem_operand_is_write(inst, mem_operand):
            mem_operand_str = self.arch.mem_operand_to_str(block, inst, mem_operand)
            access_size = self.arch.mem_operand_size(inst, mem_operand)
        else:
            return

        self.insert_at(block, inst_offset, Patch.from_function(
            self.allocate_registers(function, block, inst_idx)(
                self._build_memlog_patch(
                    inst, mem_operand_str, access_size,
                    conditional=self.arch.conditional_move_suffix(inst),
                    reuse_address=self.one_entry_scalar_store(
                        inst, None if implicit is not None else mem_operand, mem_operand_str, access_size)))))

    # Implicit stores whose address is the stack pointer less the width.
    IMPLICIT_STACK_STORES = frozenset(("push", "pushf", "pushfq", "call"))

    def one_entry_scalar_store(self, inst: CsInsn, mem_operand, mem_operand_str: str, access_size: int) -> bool:
        """A store the two-register entry covers: one load of 1, 2, 4 or 8 bytes at an ordinary address.

        mem_operand is the explicit operand, or None for an implicit store.
        Everything else keeps the three-register form: wider and odd-sized
        stores (several entries, or several loads), FS/GS (the segment base needs
        the third register), RIP-relative operands, and the other implicit
        stores (ENTER, MASKMOV*).
        """
        if access_size not in (1, 2, 4, 8):
            return False
        if self.arch.mem_operand_segment(mem_operand_str) is not None:
            return False
        if mem_operand is None:
            return inst.mnemonic.lower().split()[-1] in self.IMPLICIT_STACK_STORES
        return (mem_operand.mem.segment not in (X86_REG_FS, X86_REG_GS) and
                X86_REG_RIP not in (mem_operand.mem.base, mem_operand.mem.index))

    def _build_memlog_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                            conditional: Optional[str] = None, reuse_address: bool = False):
        if reuse_address:
            # The old bytes go to the address register once the address is in
            # the entry: one scratch register fewer.
            @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=2)
            def patch(ctx: InsertionContext):
                top, address = ctx.scratch_registers

                asm = self.arch.effective_address_snippet(address, mem_operand_str)
                asm += self.arch.address_reusing_memlog_snippet(address, top, access_size)

                return self.arch.conditional_patch_wrapper(asm, conditional, label_key="memlog")

            return patch

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3)
        def patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers

            asm = self.arch.effective_address_snippet(
                r2, mem_operand_str, r3)
            asm += self.arch.memlog_snippet(r2, r1, r3, access_size)

            asm = self.arch.conditional_patch_wrapper(asm, conditional, label_key="memlog")
            return asm

        return patch
