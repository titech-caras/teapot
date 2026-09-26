from abc import ABC
from typing import Optional

import gtirb
from capstone import CS_AC_READ, CS_AC_WRITE, CS_OP_MEM


class ArchitectureOperandMixin(ABC):
    def saved_return_registers(self):
        """SP, frame pointer and link register for explicit return-slot saves."""
        raise NotImplementedError(self.name)

    def stack_register_assignment(self, inst):
        """An affine register assignment (destination, source, displacement)."""
        raise NotImplementedError(self.name)

    def stack_memory_access(self, inst):
        raise NotImplementedError(self.name)

    @staticmethod
    def memory_operand(inst):
        return next(iter(op for op in inst.operands if op.type == CS_OP_MEM), None)

    def mem_operand_address_snippet(self, abi, inst, addr_reg, tmp_reg, mem_operand,
                                    stack_adjustment: int = 0, **kwargs) -> str:
        raise NotImplementedError(f"{self.name} does not define memory operand address snippets")

    def operand_symbolic_expression(self, block: gtirb.CodeBlock, inst, operand,
                                    inst_offset: Optional[int] = None) -> Optional[gtirb.SymbolicExpression]:
        return None

    def mem_operand_address_expression(self, block, inst, operand, inst_offset=None):
        """Capture address metadata before deferred patch emission mutates IR."""
        return self.operand_symbolic_expression(block, inst, operand, inst_offset)

    @staticmethod
    def mem_operand_is_read(inst, operand) -> bool:
        access = getattr(operand, "access", 0)
        if access & CS_AC_READ:
            return True
        if access:
            return False
        return False

    @staticmethod
    def mem_operand_is_write(inst, operand) -> bool:
        access = getattr(operand, "access", 0)
        if access & CS_AC_WRITE:
            return True
        if access:
            return False
        return False

    @staticmethod
    def mem_operand_size(inst, operand) -> int:
        if operand is None:
            return 0
        return getattr(operand, "size", 0)

    def mem_operand_registers(self, abi, inst, operand, flag_name: Optional[str] = None):
        if flag_name is None:
            flag_register = abi.flag_register()
            flag_name = flag_register.name if flag_register is not None else None

        if operand is None or getattr(operand, "mem", None) is None:
            return set()

        regs = set()
        for reg_id in (getattr(operand.mem, "base", 0), getattr(operand.mem, "index", 0)):
            if not reg_id:
                continue
            reg = self.register_from_name(abi, inst.reg_name(reg_id), flag_name)
            if reg is not None:
                regs.add(reg)
        return regs

    def mem_operand_address_tag_registers(self, abi, inst, operand, *,
                                          block: Optional[gtirb.CodeBlock] = None,
                                          inst_offset: Optional[int] = None,
                                          flag_name: Optional[str] = None):
        return self.mem_operand_registers(abi, inst, operand, flag_name)
