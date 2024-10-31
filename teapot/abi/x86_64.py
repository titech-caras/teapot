from gtirb_live_register_analysis.abi import _X86_64_ELF as _X86_64_ELF_BASE
from gtirb_rewriting.abi import _PatchRegisterAllocation
from gtirb_rewriting.assembly import Constraints, Register, _AsmSnippet

from teapot.config import SCRATCHPAD_SIZE

from typing import Tuple, Iterable, Optional, List, Set
import copy
import pprint


class _X86_64_ELF(_X86_64_ELF_BASE):
    def caller_saved_registers(self) -> Set[Register]:
        return {self.get_register("RFLAGS")}

    def _scratch_registers(self) -> List[Register]:
        return super()._scratch_registers() + [self.get_register("rbp")]

    def _allocate_patch_registers(
        self, constraints: Constraints
    ) -> _PatchRegisterAllocation:
        """
        Allocates registers to satisfy a patch's constraints.
        """
        available_scratch_registers = list(self._scratch_registers())
        clobbered_registers: Set[Register] = set()

        for clobber in constraints.clobbers_registers:
            try:
                reg = self.get_register(clobber)
            except KeyError:
                continue
            if reg in available_scratch_registers:
                available_scratch_registers.remove(reg)
            clobbered_registers.add(reg)

        for read in constraints.reads_registers:
            try:
                reg = self.get_register(read)
            except KeyError:
                continue
            if reg in available_scratch_registers:
                available_scratch_registers.remove(reg)

        if constraints.scratch_registers > len(available_scratch_registers):
            raise ValueError("unable to allocate enough scratch registers")

        scratch_registers = available_scratch_registers[
            : constraints.scratch_registers
        ]
        clobbered_registers.update(scratch_registers)

        if constraints.preserve_caller_saved_registers:
            clobbered_registers.update(self.caller_saved_registers())

        # We want deterministic register order out of this function, so we'll
        # sort it by the order the ABI class gave them out. This avoids
        # silliness like x1, x10, x2 that we'd get sorting by name.
        registers_indices = {
            reg: i for i, reg in enumerate(self.all_registers())
        }
        return _PatchRegisterAllocation(
            sorted(clobbered_registers, key=lambda r: registers_indices[r]),
            scratch_registers,
            available_scratch_registers,
        )

    def _create_prologue_and_epilogue(
            self,
            constraints: Constraints,
            register_use: _PatchRegisterAllocation,
            is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        prologue: List[_AsmSnippet] = []
        epilogue: List[_AsmSnippet] = []

        scratchpad_offset = SCRATCHPAD_SIZE // 2
        for reg in register_use.clobbered_registers:
            if reg.name == "rflags":
                continue

            prologue.append(_AsmSnippet(f"mov %{reg}, scratchpad+{scratchpad_offset}"))
            epilogue.append(_AsmSnippet(f"mov scratchpad+{scratchpad_offset}, %{reg}"))
            scratchpad_offset += 8

        if constraints.clobbers_flags:
            prologue.append(_AsmSnippet(f"""
                mov %rax, scratchpad+{scratchpad_offset+8}
                lahf
                seto %al
                mov %rax, scratchpad+{scratchpad_offset}
                mov scratchpad+{scratchpad_offset+8}, %rax
            """))
            epilogue.append(_AsmSnippet(f"""
                mov %rax, scratchpad+{scratchpad_offset+8}
                mov scratchpad+{scratchpad_offset}, %rax
                add $0x7f, %al
                sahf
                mov scratchpad+{scratchpad_offset+8}, %rax
            """))
            scratchpad_offset += 16

        return prologue, reversed(epilogue), None
