import capstone_gt.x86
import gtirb
from capstone_gt import CS_AC_WRITE
from capstone_gt.x86 import X86_REG_INVALID, X86_REG_RIP
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression


class X64OperandMixin:
    @staticmethod
    def operand_symbolic_expression(block: gtirb.CodeBlock, inst, operand, inst_offset=None):
        if not hasattr(operand, "type"):
            return None
        return operand_symbolic_expression(block, inst, operand)

    def mem_operand_to_str(self, block: gtirb.CodeBlock, inst, mem_operand) -> str:
        try:
            symexpr = self.operand_symbolic_expression(block, inst, mem_operand)
            return mem_access_to_str(inst, mem_operand.mem, symexpr)
        except NotImplementedError:
            print(f"Warning: unsupported symexp at {inst}")
            return mem_access_to_str(inst, mem_operand.mem, None)

    @staticmethod
    def mem_operand_is_write(inst, operand) -> bool:
        # Capstone misses write accesses for some vector instructions. Treat a
        # first wide memory operand as a write, matching the legacy x64 logic.
        return bool(
            operand.access & CS_AC_WRITE or
            (inst.operands[0] == operand and inst.operands[0].size > 8)
        )

    @staticmethod
    def mem_operand_uses_dynamic_address(mem_operand) -> bool:
        return not (
            mem_operand.mem.base in (X86_REG_INVALID, X86_REG_RIP) and
            mem_operand.mem.index == capstone_gt.x86.X86_REG_INVALID
        )
