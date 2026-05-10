from typing import List, Optional, Set, Tuple

import gtirb
from capstone_gt import CS_OP_MEM, CS_OP_REG
from gtirb_rewriting import InsertionContext
from gtirb_rewriting.assembly import Register

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import AARCH64_SHADOW_STACK_DIFT_OFFSET
from teapot.passes.common.dift.base import DiftPropagationBase


class AArch64DiftPropagationPass(DiftPropagationBase):
    EXPECTED_ARCH = "aarch64"
    _PAIR_LOAD_PREFIXES = ("ldp", "ldnp")
    _PAIR_STORE_PREFIXES = ("stp", "stnp")

    def _pair_register_accesses(self, inst, registers: Set[Register], mem_operand) \
            -> List[Tuple[Register, int, int]]:
        if mem_operand is None:
            return []

        register_names = {
            self.arch.x_register_name(reg): reg
            for reg in registers
        }
        accesses = []
        offset = 0
        for operand in inst.operands:
            if operand is mem_operand or operand.type == CS_OP_MEM:
                break
            if operand.type != CS_OP_REG:
                continue

            reg_name = self.arch.x_register_name(inst.reg_name(operand.reg))
            reg = register_names.get(reg_name)
            if reg is None:
                continue

            size = self._pair_element_size(inst, operand)
            if size == 0:
                return []
            accesses.append((reg, offset, size))
            offset += size
            if len(accesses) == 2:
                break

        return accesses if len(accesses) == 2 else []

    @staticmethod
    def _pair_element_size(inst, operand) -> int:
        mnemonic = inst.mnemonic.lower()
        if mnemonic.startswith("ldpsw"):
            return 4

        size = getattr(operand, "size", 0)
        if size in (1, 2, 4, 8):
            return size

        name = inst.reg_name(operand.reg).lower()
        if name.startswith("w"):
            return 4
        if name.startswith("x") or name in {"fp", "lr"}:
            return 8
        return 0

    def _build_patch(self, inst, regs_read: Set[Register], regs_write: Set[Register], *,
                     clear_dest_tags: bool, mem_read, mem_write, mem_write_size: int,
                     mem_symexpr: Optional[gtirb.SymbolicExpression] = None):
        fixed_regs = self.arch.fixed_spill_registers(self.reg_manager.abi, 4 if self.insert_memlog else 3)
        frame_offset = AARCH64_SHADOW_STACK_DIFT_OFFSET
        saved_reg_offsets = self.arch.fixed_scratch_offsets(fixed_regs, frame_offset)
        mnemonic = inst.mnemonic.lower()
        address_tag_regs = self._filter_ignored_registers(
            self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_read or mem_write))
        pair_loads = self._pair_register_accesses(inst, regs_write, mem_read) \
            if mnemonic.startswith(self._PAIR_LOAD_PREFIXES) else []
        pair_stores = self._pair_register_accesses(inst, regs_read, mem_write) \
            if mnemonic.startswith(self._PAIR_STORE_PREFIXES) else []

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            tag_reg, addr_reg, tmp_reg = fixed_regs[:3]
            memlog_data_reg = fixed_regs[3] if self.insert_memlog else None
            done_label = f".L__dift_done{SYMBOL_SUFFIX}"

            def load_mem_address(memory_operand, offset: int = 0) -> str:
                asm = self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi, inst, addr_reg, tmp_reg, memory_operand,
                    ctx.stack_adjustment,
                    mem_symexpr=mem_symexpr, saved_reg_offsets=saved_reg_offsets,
                    saved_reg_base="shadow_sp")
                asm += self.arch.dift_shadow_addr_snippet(addr_reg, tmp_reg, self.dift_layout.xor_mask)
                if offset:
                    asm += self.arch.add_sub_constant_from_base("add", addr_reg, addr_reg, tmp_reg, offset)
                return asm

            def or_memory_tag(size: int) -> str:
                asm = ""
                for idx in range(size):
                    if idx:
                        asm += "add {0}, {0}, #1\n".format(addr_reg)
                    asm += f"""
                        ldrb {tmp_reg:32}, [{addr_reg}]
                        orr {tag_reg:32}, {tag_reg:32}, {tmp_reg:32}
                    """
                return asm

            def store_memory_tag(size: int) -> str:
                asm = ""
                for idx in range(size):
                    if idx:
                        asm += f"add {addr_reg}, {addr_reg}, #1\n"
                    if self.insert_memlog:
                        asm += self.arch.memlog_snippet(addr_reg, tmp_reg, memlog_data_reg, 1)
                    asm += f"strb {tag_reg:32}, [{addr_reg}]\n"
                return asm

            def build_base_tag(regs) -> str:
                asm = self.arch.clear_register_snippet(tag_reg)
                if not clear_dest_tags:
                    for reg in regs:
                        asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)
                return asm

            asm = self.arch.save_regs_to_shadow_stack(
                fixed_regs, save_flags=True, frame_offset=frame_offset, preserve_sp=True)
            if pair_loads:
                pair_load_regs = {reg for reg, _, _ in pair_loads}
                for reg, offset, size in pair_loads:
                    asm += "\n" + build_base_tag(address_tag_regs)
                    if not clear_dest_tags:
                        asm += load_mem_address(mem_read, offset)
                        asm += or_memory_tag(size)
                    asm += self.arch.dift_store_reg_tag_snippet(tag_reg, tmp_reg, reg)

                for reg in regs_write - pair_load_regs:
                    asm += "\n" + build_base_tag(address_tag_regs)
                    asm += self.arch.dift_store_reg_tag_snippet(tag_reg, tmp_reg, reg)
            elif pair_stores:
                for reg, offset, size in pair_stores:
                    asm += "\n" + build_base_tag(address_tag_regs)
                    if not clear_dest_tags:
                        asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)
                    asm += load_mem_address(mem_write, offset)
                    asm += store_memory_tag(size)

                for reg in regs_write:
                    asm += "\n" + build_base_tag(address_tag_regs)
                    asm += self.arch.dift_store_reg_tag_snippet(tag_reg, tmp_reg, reg)
            else:
                asm += "\n" + self.arch.clear_register_snippet(tag_reg)
                if not clear_dest_tags:
                    for reg in regs_read:
                        asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)

                    if mem_read is not None:
                        asm += self.arch.mem_operand_address_snippet(
                            self.reg_manager.abi, inst, addr_reg, tmp_reg, mem_read,
                            ctx.stack_adjustment,
                            mem_symexpr=mem_symexpr, saved_reg_offsets=saved_reg_offsets,
                            saved_reg_base="shadow_sp")
                        asm += self.arch.dift_shadow_addr_snippet(addr_reg, tmp_reg, self.dift_layout.xor_mask)
                        asm += f"""
                            ldrb {tmp_reg:32}, [{addr_reg}]
                            orr {tag_reg:32}, {tag_reg:32}, {tmp_reg:32}
                        """

                for reg in regs_write:
                    asm += self.arch.dift_store_reg_tag_snippet(tag_reg, tmp_reg, reg)

                if mem_write is not None:
                    if mem_read is None or mem_write != mem_read:
                        asm += self.arch.mem_operand_address_snippet(
                            self.reg_manager.abi, inst, addr_reg, tmp_reg, mem_write,
                            ctx.stack_adjustment,
                            mem_symexpr=mem_symexpr, saved_reg_offsets=saved_reg_offsets,
                            saved_reg_base="shadow_sp")
                        asm += self.arch.dift_shadow_addr_snippet(addr_reg, tmp_reg, self.dift_layout.xor_mask)
                    for idx in range(mem_write_size):
                        if idx:
                            asm += f"add {addr_reg}, {addr_reg}, #1\n"
                        if self.insert_memlog:
                            asm += self.arch.memlog_snippet(addr_reg, tmp_reg, memlog_data_reg, 1)
                        asm += f"strb {tag_reg:32}, [{addr_reg}]\n"

            if mem_read is not None:
                asm += self.arch.dift_apply_queued_tag_snippet(tag_reg, addr_reg, tmp_reg, done_label)

            asm += f"""
            {done_label}:
                nop
            """
            asm += self.arch.restore_regs_from_shadow_stack(
                fixed_regs, save_flags=True, frame_offset=frame_offset, preserve_sp=True)
            return asm

        return patch
