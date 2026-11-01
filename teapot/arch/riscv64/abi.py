from typing import Iterable, Optional, Tuple

from gtirb_rewriting.abi import ABI, CallingConventionDesc, _PatchRegisterAllocation
from gtirb_rewriting.assembly import Constraints, Register, _AsmSnippet

from teapot.arch.abi import ConservativeRegisterAllocationMixin
from teapot.arch.riscv64.assembly import RISCV64AssemblyMixin
from teapot.arch.riscv64.instructions import riscv64_is_call
from teapot.configs.slots import RISCV64_ORIGINAL_TP_OFFSET, SCRATCHPAD_FIRST_SPILL_OFFSET
from teapot.utils.registers import get_register, registers_in_abi_order


class _RISCV64_ELF(ConservativeRegisterAllocationMixin, ABI):
    def all_registers(self):
        names = (
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
            "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            "t3", "t4", "t5", "t6",
        )
        return [Register({"64": name, "64_alt": f"x{idx}"}, "64")
                for idx, name in enumerate(names)]

    def nop(self) -> bytes:
        return b"\x13\x00\x00\x00"

    def pointer_size(self) -> int:
        return 8

    def calling_convention(self) -> CallingConventionDesc:
        return CallingConventionDesc(
            registers=("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
            stack_alignment=16,
            caller_cleanup=True,
        )

    def stack_register(self) -> Register:
        return self.get_register("sp")

    def temporary_label_prefix(self) -> str:
        return ".L"

    def default_dwarf_eh_return_column(self) -> int:
        return 1

    def flag_register(self) -> Optional[Register]:
        return None

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
        return riscv64_is_call(instruction)

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
