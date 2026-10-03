from dataclasses import dataclass
from typing import FrozenSet, Optional, Set, Tuple

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import RewritingContext
from gtirb_rewriting.assembly import Register

from teapot.arch.architecture import Architecture
from teapot.configs.blacklist import is_blacklisted_function
from teapot.passes.mixins import ArchSpecificPassMixin, InstVisitorPassMixin


@dataclass(frozen=True)
class DiftMemoryElement:
    register: Optional[Register]
    offset: int
    size: int
    # Scalar loads retain first-byte sampling; pair elements merge their bytes.
    read_tag_size: int = 1


@dataclass(frozen=True)
class DiftScratchPlan:
    registers: Tuple[Register, ...]
    saved_regs: Tuple[Register, ...]
    live_registers: FrozenSet[Register]


class DiftPassBase(ArchSpecificPassMixin, InstVisitorPassMixin):
    section: gtirb.Section

    @staticmethod
    def _ordered_registers(registers):
        # Register hashes include their names. Never let hash-seed-dependent
        # set order become instruction order or LLVM temporary numbering.
        return sorted(registers, key=lambda reg: reg.name)

    def __init__(self, reg_manager: LiveRegisterManager, section: gtirb.Section, decoder: GtirbInstructionDecoder,
                 arch: Architecture, *, dift_layout, insert_memlog: bool = False):
        self.check_expected_arch(arch)
        super().__init__(reg_manager, decoder)
        self.section = section
        self.arch = arch
        self.dift_layout = dift_layout
        self.insert_memlog = insert_memlog

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.visit_functions(functions, self.section)

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        super().visit_function(function)

    def _insertion_live_registers(self, function, block, inst_idx):
        if function is None or block is None:
            return frozenset(self.reg_manager.abi.all_registers())
        adjusted_block, adjusted_idx = self.insertion_register_location(block, inst_idx)
        # RISC-V placement can move across an AUIPC/LO pair. Preserve both the
        # actual insertion state and the original operand/capture requirements.
        return frozenset(
            self.reg_manager.live_registers(function, block, inst_idx) |
            self.reg_manager.live_registers(function, adjusted_block, adjusted_idx))

    def _plan_scratch_registers(self, count: int, live_registers=None):
        if live_registers is None:
            live_registers = self.reg_manager.abi.all_registers()
        live_registers = frozenset(live_registers)
        candidates = list(self.reg_manager.abi._scratch_registers())
        registers = tuple(
            [reg for reg in candidates if reg not in live_registers] +
            [reg for reg in candidates if reg in live_registers])[:count]
        if len(registers) != count:
            raise ValueError("DIFT needs more scratch registers than the ABI provides")
        # DIFT owns separate spill slots: later memlog patches must not overwrite
        # these saves. LRA changes which values need saving, not their lifetime.
        return DiftScratchPlan(registers, tuple(
            reg for reg in registers if reg in live_registers), live_registers)

    def _filter_ignored_registers(self, regs: Set[Register]) -> Set[Register]:
        ignored = self.arch.dift_ignored_register_names()
        return {reg for reg in regs if reg.name.lower() not in ignored}

    def _memory_elements(self, inst, registers: Set[Register], mem_operand) -> Tuple[DiftMemoryElement, ...]:
        """Independent transfers, or empty for the aggregate instruction rule."""
        return ()
