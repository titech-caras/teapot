from typing import Iterable, List, Optional, Set, Tuple

from gtirb_rewriting.abi import CallingConventionDesc, _PatchRegisterAllocation, _X86_64_ELF as _X86_64_ELF_BASE
from gtirb_rewriting.assembly import Constraints, Register, _AsmSnippet

from teapot.arch.abi import ConservativeRegisterAllocationMixin
from teapot.configs.slots import SCRATCHPAD_FIRST_SPILL_OFFSET, ScratchpadSlots

# The area of the scratchpad that holds a patch's saved registers and flags:
# the wrapper below writes and reads nothing else, and nothing else uses the
# area, so its traffic is recognizable (teapot/passes/transient/x64_wrapper_coalescing.py).
X64_WRAPPER_AREA = range(SCRATCHPAD_FIRST_SPILL_OFFSET, SCRATCHPAD_FIRST_SPILL_OFFSET + 4096)
if any(isinstance(value, int) and value in X64_WRAPPER_AREA
       for name, value in vars(ScratchpadSlots).items() if name != "FIRST_SPILL"):
    raise AssertionError("a scratchpad slot lies in the x64 wrapper's spill area")


class _X86_64_ELF(ConservativeRegisterAllocationMixin, _X86_64_ELF_BASE):
    def all_registers(self) -> List[Register]:
        registers = super().all_registers() + [
            Register({"8l": "bpl", "16": "bp", "32": "ebp", "64": "rbp"}, "64"),
            Register({"8l": "spl", "16": "sp", "32": "esp", "64": "rsp"}, "64"),
            Register({"64": "rflags"}, "64"),
        ]
        for i in range(32):
            registers.append(Register({
                "128": f"xmm{i}", "256": f"ymm{i}", "512": f"zmm{i}"
            }, default_size="128"))
        registers.extend(Register({"64": f"k{i}"}, "64") for i in range(8))
        return registers

    def calling_convention(self) -> CallingConventionDesc:
        calling_convention = super().calling_convention()
        calling_convention.registers += tuple(f"xmm{i}" for i in range(8))
        return calling_convention

    def flag_register(self) -> Register:
        return self.get_register("RFLAGS")

    def is_call_instruction(self, instruction) -> bool:
        return instruction.mnemonic == "call"

    def caller_saved_registers(self) -> Set[Register]:
        return {self.get_register("RFLAGS")}

    def _scratch_registers(self) -> List[Register]:
        return super().all_registers() + [self.get_register("rbp")]

    def _create_prologue_and_epilogue(
            self,
            constraints: Constraints,
            register_use: _PatchRegisterAllocation,
            is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        prologue: List[_AsmSnippet] = []
        epilogue: List[_AsmSnippet] = []

        scratchpad_offset = SCRATCHPAD_FIRST_SPILL_OFFSET
        for reg in register_use.clobbered_registers:
            if reg.name == "rflags":
                continue

            prologue.append(_AsmSnippet(f"mov %{reg}, scratchpad+{scratchpad_offset}"))
            epilogue.append(_AsmSnippet(f"mov scratchpad+{scratchpad_offset}, %{reg}"))
            scratchpad_offset += 8

        if constraints.clobbers_flags:
            # The liveness flags bit covers CF/PF/AF/ZF/SF/OF. This wrapper does not
            # modify DF; patches that do (REP reporting) preserve it separately.
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

        assert scratchpad_offset <= X64_WRAPPER_AREA.stop, "the wrapper's spills overflow its area"
        return prologue, reversed(epilogue), None
