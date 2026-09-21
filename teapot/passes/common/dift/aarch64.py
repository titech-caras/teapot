from typing import Optional, Set, Tuple

import gtirb
from capstone_gt import CS_OP_MEM, CS_OP_REG
from gtirb_rewriting import InsertionContext
from gtirb_rewriting.assembly import Register

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import AARCH64_SHADOW_STACK_DIFT_OFFSET
from teapot.passes.common.dift.base import DiftMemoryElement, DiftPropagationBase


class AArch64DiftPropagationPass(DiftPropagationBase):
    EXPECTED_ARCH = "aarch64"
    _PAIR_LOAD_PREFIXES = ("ldp", "ldnp")
    _PAIR_STORE_PREFIXES = ("stp", "stnp")

    def _memory_elements(self, inst, registers: Set[Register], mem_operand) \
            -> Tuple[DiftMemoryElement, ...]:
        if mem_operand is None:
            return ()
        mnemonic = inst.mnemonic.lower()
        pair = mnemonic.startswith(self._PAIR_LOAD_PREFIXES + self._PAIR_STORE_PREFIXES)
        if not pair and not (inst.writeback and mnemonic.startswith(("ldr", "str"))):
            return ()
        count = 2 if pair else 1

        register_names = {
            self.arch.x_register_name(reg): reg
            for reg in registers
        }
        accesses = []
        size = self.arch.mem_operand_size(inst, mem_operand) // count
        for operand in inst.operands:
            if operand is mem_operand or operand.type == CS_OP_MEM:
                break
            if operand.type != CS_OP_REG:
                continue

            operand_name = inst.reg_name(operand.reg)
            reg_name = self.arch.x_register_name(operand_name)
            reg = register_names.get(reg_name)
            if size <= 0 or (pair and (
                    size not in (4, 8) or
                    (reg is None and operand_name not in self.arch.zero_register_names()))):
                return ()
            # A zero-register transfer still occupies an element. None means
            # no tracked data tag, not an absent access. The scalar path also
            # leaves untracked FP/SIMD data out of the writeback base's tag.
            accesses.append(DiftMemoryElement(
                reg, len(accesses) * size, size, read_tag_size=size if pair else 1))
            if len(accesses) == count:
                break

        return tuple(accesses) if len(accesses) == count else ()

    def _build_patch(self, inst, regs_read: Set[Register], regs_write: Set[Register], *,
                     clear_dest_tags: bool, mem_read, mem_write, mem_write_size: int,
                     mem_symexpr: Optional[gtirb.SymbolicExpression] = None,
                     live_registers=None):
        load_elements = self._memory_elements(inst, regs_write, mem_read)
        store_elements = self._memory_elements(inst, regs_read, mem_write)
        scratch_plan = self._plan_scratch_registers(
            4 if self.insert_memlog or load_elements else 3, live_registers)
        save_flags = self.reg_manager.abi.flag_register() in scratch_plan.live_registers
        frame_offset = AARCH64_SHADOW_STACK_DIFT_OFFSET
        saved_reg_offsets = self.arch.fixed_scratch_offsets(scratch_plan.saved_regs, frame_offset)
        address_tag_regs = self._filter_ignored_registers(
            self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_read or mem_write))

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            tag_reg, addr_reg, tmp_reg = scratch_plan.registers[:3]
            memlog_data_reg = scratch_plan.registers[3] if self.insert_memlog else None
            done_label = f".L__dift_done{SYMBOL_SUFFIX}"

            def load_mem_address(memory_operand, offset: int = 0) -> str:
                asm = self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi, inst, addr_reg, tmp_reg, memory_operand,
                    ctx.stack_adjustment,
                    mem_symexpr=mem_symexpr, saved_reg_offsets=saved_reg_offsets,
                    saved_reg_base="shadow_sp")
                if offset:
                    asm += self.arch.add_sub_constant_from_base("add", addr_reg, addr_reg, tmp_reg, offset)
                asm += self.arch.dift_shadow_addr_snippet(addr_reg, tmp_reg, self.dift_layout.xor_mask)
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
                for shift in (8, 16, 32):
                    if size > shift // 8:
                        reg = f"{tag_reg}" if shift == 32 else f"{tag_reg:32}"
                        asm += f"orr {reg}, {reg}, {reg}, lsl #{shift}\n"
                for idx in range(0, size, 8):
                    if idx:
                        asm += f"add {addr_reg}, {addr_reg}, #8\n"
                    chunk_size = min(8, size - idx)
                    if self.insert_memlog:
                        asm += self.arch.memlog_snippet(
                            addr_reg, tmp_reg, memlog_data_reg, chunk_size,
                            no_clobber_addr=True)
                    offset = 0
                    for width, suffix, register_size in (
                            (8, "", "64"), (4, "", "32"), (2, "h", "32"), (1, "b", "32")):
                        if chunk_size & width:
                            asm += f"str{suffix} {tag_reg:{register_size}}, [{addr_reg}, #{offset}]\n"
                            offset += width
                return asm

            def build_base_tag(regs) -> str:
                asm = self.arch.clear_register_snippet(tag_reg)
                if not clear_dest_tags:
                    for reg in regs:
                        asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)
                return asm

            asm = self.arch.save_regs_to_shadow_stack(
                scratch_plan.saved_regs, save_flags=save_flags, flag_reg=tmp_reg,
                frame_offset=frame_offset, preserve_sp=True)
            if load_elements:
                loaded_registers = {element.register for element in load_elements}
                # Capture address tags before a destination aliases the base.
                base_tag_reg = scratch_plan.registers[3]
                asm += build_base_tag(address_tag_regs)
                asm += f"mov {base_tag_reg:32}, {tag_reg:32}\n"
                for element in load_elements:
                    if element.register is None:
                        continue
                    asm += f"mov {tag_reg:32}, {base_tag_reg:32}\n"
                    if not clear_dest_tags:
                        asm += load_mem_address(mem_read, element.offset)
                        asm += or_memory_tag(element.read_tag_size)
                    asm += self.arch.dift_store_reg_tag_snippet(tag_reg, tmp_reg, element.register)

                for reg in regs_write - loaded_registers:
                    asm += f"mov {tag_reg:32}, {base_tag_reg:32}\n"
                    asm += self.arch.dift_store_reg_tag_snippet(tag_reg, tmp_reg, reg)
            elif store_elements:
                for element in store_elements:
                    asm += "\n" + build_base_tag(address_tag_regs)
                    if not clear_dest_tags and element.register is not None:
                        asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, element.register)
                    asm += load_mem_address(mem_write, element.offset)
                    asm += store_memory_tag(element.size)

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
                    asm += store_memory_tag(mem_write_size)

            if mem_read is not None:
                asm += self.arch.dift_apply_queued_tag_snippet(tag_reg, addr_reg, tmp_reg, done_label)

            asm += f"""
            {done_label}:
                nop
            """
            asm += self.arch.restore_regs_from_shadow_stack(
                scratch_plan.saved_regs, save_flags=save_flags, flag_reg=tmp_reg,
                frame_offset=frame_offset, preserve_sp=True)
            return asm

        return patch
