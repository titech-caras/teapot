from typing import Optional

from teapot.arch.aarch64.assembly import AArch64AssemblyMixin
from teapot.configs.slots import AARCH64_SHADOW_STACK_SIZE


class AArch64ShadowStackMixin:
    @staticmethod
    def shadow_stack_adjust_reg(op: str, reg: str) -> str:
        encoded = AArch64AssemblyMixin.add_sub_immediate(op, reg, reg, AARCH64_SHADOW_STACK_SIZE)
        if encoded is not None:
            return encoded
        raise ValueError("AARCH64_SHADOW_STACK_SIZE is not encodable as an add/sub immediate")

    @staticmethod
    def is_shadow_stack_adjust_instruction(inst, mnemonic: Optional[str] = None) -> bool:
        inst_mnemonic = inst.mnemonic.lower()
        if mnemonic is not None and inst_mnemonic != mnemonic:
            return False
        if inst_mnemonic not in {"add", "sub"}:
            return False

        operands = inst.op_str.replace(" ", "").lower()
        if AARCH64_SHADOW_STACK_SIZE % 4096 == 0:
            pages = AARCH64_SHADOW_STACK_SIZE // 4096
            if operands in {
                f"sp,sp,#{pages},lsl#12",
                f"sp,sp,#0x{pages:x},lsl#12",
            }:
                return True
        return operands in {
            f"sp,sp,#{AARCH64_SHADOW_STACK_SIZE}",
            f"sp,sp,#0x{AARCH64_SHADOW_STACK_SIZE:x}",
        }

    @classmethod
    def is_instrumentation_helper_instruction(cls, inst, inst_idx: int, instructions) -> bool:
        if cls.is_shadow_stack_adjust_instruction(inst):
            return True
        if inst_idx <= 0 or instructions is None:
            return False

        # Instrumentation helpers use a fixed, rollback-exempt frame below the
        # application stack.  Later passes must not instrument any instruction
        # while SP is shifted into that helper frame, otherwise nested helpers
        # spill relative to the wrong stack base and can overwrite each other.
        for prev_inst in reversed(instructions[:inst_idx]):
            if cls.is_shadow_stack_adjust_instruction(prev_inst, "add"):
                return False
            if cls.is_shadow_stack_adjust_instruction(prev_inst, "sub"):
                return True
        return False

    @classmethod
    def save_regs_to_shadow_stack(cls, registers, *, save_flags: bool = False,
                                  frame_offset: int = 0, preserve_sp: bool = False) -> str:
        saved_registers = list(registers)
        if save_flags and not saved_registers:
            saved_registers.append("x17")
        lines = [cls.shadow_stack_adjust_reg("sub", "sp")]
        for idx, reg in enumerate(saved_registers):
            lines.append(f"str {reg}, [sp, #{frame_offset + idx * 8}]")
        if save_flags:
            flag_reg = saved_registers[-1]
            lines.extend([
                f"mrs {flag_reg}, nzcv",
                f"str {flag_reg}, [sp, #{frame_offset + len(saved_registers) * 8}]",
            ])
        if preserve_sp:
            lines.append(cls.shadow_stack_adjust_reg("add", "sp"))
        return "\n".join(lines) + "\n"

    @classmethod
    def restore_regs_from_shadow_stack(cls, registers, *, save_flags: bool = False,
                                       frame_offset: int = 0, preserve_sp: bool = False) -> str:
        saved_registers = list(registers)
        if save_flags and not saved_registers:
            saved_registers.append("x17")
        lines = []
        if preserve_sp:
            lines.append(cls.shadow_stack_adjust_reg("sub", "sp"))
        if save_flags:
            flag_reg = saved_registers[-1]
            lines.extend([
                f"ldr {flag_reg}, [sp, #{frame_offset + len(saved_registers) * 8}]",
                f"msr nzcv, {flag_reg}",
            ])
        for idx, reg in reversed(list(enumerate(saved_registers))):
            lines.append(f"ldr {reg}, [sp, #{frame_offset + idx * 8}]")
        lines.append(cls.shadow_stack_adjust_reg("add", "sp"))
        return "\n".join(lines) + "\n"
