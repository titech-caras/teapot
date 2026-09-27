from typing import Set, Tuple

from capstone import CS_OP_MEM, CS_OP_REG
from gtirb_rewriting.assembly import Register

from teapot.passes.common.dift.base import DiftMemoryElement, DiftPassBase


class AArch64DiftOperandHelpers(DiftPassBase):
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
