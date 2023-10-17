from gtirb_live_register_analysis.abi import _X86_64_ELF as _X86_64_ELF_BASE
from gtirb_rewriting.abi import _PatchRegisterAllocation
from gtirb_rewriting.assembly import Constraints, Register, _AsmSnippet

from NaHCO3.config import SCRATCHPAD_SIZE

from typing import Tuple, Iterable, Optional, List
import copy
import pprint


class _X86_64_ELF(_X86_64_ELF_BASE):
    def _create_prologue_and_epilogue(
            self,
            constraints: Constraints,
            register_use: _PatchRegisterAllocation,
            is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        switch_to_scratchpad_stack_snippet = _AsmSnippet(f"""
            mov %rsp, old_rsp
            mov scratchpad+{SCRATCHPAD_SIZE - 8}, %rsp
        """)
        switch_to_original_stack_snippet = _AsmSnippet(f"""
            mov old_rsp, %rsp
        """)

        if constraints.clobbers_flags:
            # Use switch-stack implementation.
            new_constraints = copy.copy(constraints)
            new_constraints.align_stack = False

            new_register_use = copy.copy(register_use)
            new_register_use.clobbered_registers = [x for x in new_register_use.clobbered_registers
                                                    if x.name != "rflags"]

            prologue, epilogue, _ = super()._create_prologue_and_epilogue(
                new_constraints, new_register_use, False)
            epilogue = list(reversed(list(epilogue)))

            # FIXME: actually should use scratchpad, but maybe only in transient?
            #prologue.insert(0, switch_to_scratchpad_stack_snippet)
            #prologue.append(switch_to_original_stack_snippet)
            #epilogue.insert(0, switch_to_original_stack_snippet)
            #epilogue.append(switch_to_scratchpad_stack_snippet)
        else:
            prologue: List[_AsmSnippet] = []
            epilogue: List[_AsmSnippet] = []

            scratchpad_offset = 0
            for reg in register_use.clobbered_registers:
                if reg.name == "rflags":
                    continue

                prologue.append(_AsmSnippet(f"mov %{reg}, scratchpad+{scratchpad_offset}"))
                epilogue.append(_AsmSnippet(f"mov scratchpad+{scratchpad_offset}, %{reg}"))
                scratchpad_offset += 8

        return prologue, reversed(epilogue), None
