from typing import Iterable, List, Optional, Set, Tuple

from gtirb_live_register_analysis.abi import _ARM64_ELF as _ARM64_ELF_BASE
from gtirb_rewriting.abi import _PatchRegisterAllocation
from gtirb_rewriting.assembly import Constraints, Register, _AsmSnippet

from teapot.arch.aarch64.assembly import AArch64AssemblyMixin
from teapot.arch.abi import ConservativeRegisterAllocationMixin
from teapot.configs.slots import (
    AARCH64_SHADOW_STACK_ABI_OFFSET,
    AARCH64_SHADOW_STACK_SIZE,
    SCRATCHPAD_FIRST_SPILL_OFFSET,
)


class _ARM64_ELF(ConservativeRegisterAllocationMixin, _ARM64_ELF_BASE):
    def caller_saved_registers(self) -> Set[Register]:
        # Compilers do not always leave binary-level call sites matching the
        # source ABI contract after optimization. Keep GPRs live across calls
        # until Teapot has a more precise cross-call analysis.
        return {self.get_register("nzcv")}

    @staticmethod
    def _load_address(reg: Register, symbol: str) -> str:
        return AArch64AssemblyMixin.load_address(reg, symbol)

    @staticmethod
    def _shadow_stack_adjust(op: str) -> str:
        encoded = AArch64AssemblyMixin.add_sub_immediate(op, "sp", "sp", AARCH64_SHADOW_STACK_SIZE)
        if encoded is not None:
            return encoded
        raise ValueError("AARCH64_SHADOW_STACK_SIZE is not encodable as an add/sub immediate")

    def _create_prologue_and_epilogue(
            self,
            constraints: Constraints,
            register_use: _PatchRegisterAllocation,
            is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        save_flags = constraints.clobbers_flags or any(
            reg.name == "nzcv" for reg in register_use.clobbered_registers)
        clobbered_registers = [
            reg for reg in register_use.clobbered_registers
            if reg.name != "nzcv"
        ]
        if not clobbered_registers and not save_flags:
            return [], [], 0

        prologue: List[_AsmSnippet] = []
        epilogue: List[_AsmSnippet] = []

        scratchpad_offset = SCRATCHPAD_FIRST_SPILL_OFFSET
        saved_registers = [
            reg for reg in clobbered_registers
            if reg.name not in ("x16", "x17")
        ]
        clobbered_names = {reg.name for reg in clobbered_registers}

        prologue_lines = [
            self._shadow_stack_adjust("sub"),
            f"stp x16, x17, [sp, #{AARCH64_SHADOW_STACK_ABI_OFFSET}]",
            self._load_address(self.get_register("x16"), f"scratchpad+{scratchpad_offset}"),
            f"ldr x17, [sp, #{AARCH64_SHADOW_STACK_ABI_OFFSET}]",
            "str x17, [x16]",
            f"ldr x17, [sp, #{AARCH64_SHADOW_STACK_ABI_OFFSET + 8}]",
            "str x17, [x16, #8]",
        ]
        for idx, reg in enumerate(saved_registers, start=2):
            prologue_lines.append(f"str {reg}, [x16, #{idx * 8}]")

        if save_flags:
            prologue_lines.extend([
                "mrs x17, nzcv",
                f"str x17, [x16, #{(len(saved_registers) + 2) * 8}]",
            ])

        if "x17" not in clobbered_names:
            prologue_lines.append("ldr x17, [x16, #8]")
        if "x16" not in clobbered_names:
            prologue_lines.append("ldr x16, [x16]")
        prologue_lines.append(self._shadow_stack_adjust("add"))
        prologue.append(_AsmSnippet("\n".join(prologue_lines)))

        epilogue_lines = [
            self._load_address(self.get_register("x16"), f"scratchpad+{scratchpad_offset}"),
        ]
        if save_flags:
            epilogue_lines.extend([
                f"ldr x17, [x16, #{(len(saved_registers) + 2) * 8}]",
                "msr nzcv, x17",
            ])
        for idx, reg in reversed(list(enumerate(saved_registers, start=2))):
            epilogue_lines.append(f"ldr {reg}, [x16, #{idx * 8}]")
        epilogue_lines.extend([
            "ldr x17, [x16, #8]",
            "ldr x16, [x16]",
        ])
        epilogue.append(_AsmSnippet("\n".join(epilogue_lines)))

        return prologue, reversed(epilogue), 0


_AARCH64_ELF = _ARM64_ELF
