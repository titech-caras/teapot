from typing import Iterable, List, Optional, Tuple

from gtirb_live_register_analysis.abi import _RISCV64_ELF as _RISCV64_ELF_BASE
from gtirb_rewriting.abi import _PatchRegisterAllocation
from gtirb_rewriting.assembly import Constraints, Register, _AsmSnippet

from teapot.arch.abi import ConservativeRegisterAllocationMixin
from teapot.arch.riscv64.assembly import RISCV64AssemblyMixin
from teapot.configs.slots import RISCV64_ORIGINAL_TP_OFFSET, SCRATCHPAD_FIRST_SPILL_OFFSET
from teapot.utils.registers import get_register, registers_in_abi_order


class _RISCV64_ELF(ConservativeRegisterAllocationMixin, _RISCV64_ELF_BASE):
    def normalize_register_name(self, name):
        if name is None:
            return None
        return get_register(self, name).name

    def register_from_name(self, name):
        return get_register(self, name)

    def sort_registers(self, registers):
        return registers_in_abi_order(self, registers)

    def _scratch_registers(self):
        return [
            self.get_register(name)
            for name in ("t0", "t1", "t2", "t3", "t4", "t5", "t6")
        ]

    def caller_saved_registers(self):
        # Keep all GPRs live across calls until Teapot has a more precise
        # cross-call analysis. RISC-V has no flag register to invalidate here.
        return set()

    def is_call_instruction(self, instruction):
        return instruction.mnemonic in ("call", "jal", "jalr", "c.jal", "c.jalr")

    @staticmethod
    def _load_address(reg: Register, symbol: str) -> str:
        return RISCV64AssemblyMixin.load_address(reg, symbol)

    def _create_prologue_and_epilogue(
            self,
            constraints: Constraints,
            register_use: _PatchRegisterAllocation,
            is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        if constraints.clobbers_flags:
            constraints.clobbers_flags = False

        if not register_use.clobbered_registers:
            return [], [], 0

        scratchpad_offset = SCRATCHPAD_FIRST_SPILL_OFFSET
        saved_registers = [
            reg for reg in register_use.clobbered_registers
            if reg.name != "tp"
        ]
        if not saved_registers:
            return [], [], 0

        prologue_lines = [
            self._load_address(self.get_register("tp"), f"scratchpad+{scratchpad_offset}"),
        ]
        for idx, reg in enumerate(saved_registers):
            prologue_lines.append(f"sd {reg}, {idx * 8}(tp)")
        prologue_lines.extend([
            self._load_address(self.get_register("tp"), f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}"),
            "ld tp, 0(tp)",
        ])

        epilogue_lines = [
            self._load_address(self.get_register("tp"), f"scratchpad+{scratchpad_offset}"),
        ]
        for idx, reg in reversed(list(enumerate(saved_registers))):
            epilogue_lines.append(f"ld {reg}, {idx * 8}(tp)")
        epilogue_lines.extend([
            self._load_address(self.get_register("tp"), f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}"),
            "ld tp, 0(tp)",
        ])

        return [_AsmSnippet("\n".join(prologue_lines))], [_AsmSnippet("\n".join(epilogue_lines))], 0
