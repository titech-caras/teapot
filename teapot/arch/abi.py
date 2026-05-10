from typing import Set

from gtirb_rewriting.abi import _PatchRegisterAllocation
from gtirb_rewriting.assembly import Constraints, Register


class ConservativeRegisterAllocationMixin:
    def _allocate_patch_registers(self, constraints: Constraints) -> _PatchRegisterAllocation:
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

        scratch_registers = available_scratch_registers[:constraints.scratch_registers]
        clobbered_registers.update(scratch_registers)

        if constraints.preserve_caller_saved_registers:
            clobbered_registers.update(self.caller_saved_registers())

        register_indices = {
            reg: idx for idx, reg in enumerate(self.all_registers())
        }
        return _PatchRegisterAllocation(
            sorted(clobbered_registers, key=lambda reg: register_indices[reg]),
            scratch_registers,
            available_scratch_registers,
        )
