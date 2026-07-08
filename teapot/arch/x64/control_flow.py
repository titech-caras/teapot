from typing import Optional

import gtirb
from capstone_gt import CS_OP_MEM

from teapot.configs.runtime import SYMBOL_SUFFIX


class X64ControlFlowPatchesMixin:
    @staticmethod
    def conditional_patch_wrapper(asm: str, conditional: Optional[str], *,
                                  label_key: str = "conditional",
                                  doit_label_name: Optional[str] = None,
                                  skip_label_name: Optional[str] = None,
                                  insert_skip_label: bool = True):
        if conditional is None:
            return asm

        if doit_label_name is None:
            doit_label_name = f".L__{label_key}_doit" + SYMBOL_SUFFIX

        if skip_label_name is None:
            skip_label_name = f".L__{label_key}_skip" + SYMBOL_SUFFIX

        wrapped_asm = f"""
                j{conditional} {doit_label_name}
                jmp {skip_label_name}
            {doit_label_name}:
                {asm}
        """

        if insert_skip_label:
            wrapped_asm += f"""
                {skip_label_name}:
                    nop
            """

        return wrapped_asm

    @staticmethod
    def conditional_move_suffix(instruction) -> Optional[str]:
        return instruction.mnemonic[4:] if instruction.mnemonic.startswith("cmov") else None

    def indirect_branch_target_patch(self, target_symbol: gtirb.Symbol, *, use_scratch_registers: bool = False):
        return self.constraints()(lambda ctx: f"""
            .long 0x{self.MAGIC_WORDS[0]:08x} # xchg rbx, rbx; nop
            .long 0x{self.MAGIC_WORDS[1]:08x} # xchg rdx, rdx; nop
            mov qword ptr indirect_branch_flags_scratch, rax
            seto al
            lahf
            cmp qword ptr checkpoint_cnt, 0
            je 1f
            add al, 0x7f
            sahf
            mov rax, qword ptr indirect_branch_flags_scratch
            jmp {target_symbol.name}
        1:
            add al, 0x7f
            sahf
            mov rax, qword ptr indirect_branch_flags_scratch
        """)

    def indirect_branch_operand(self, edge_type, last_inst, block: gtirb.CodeBlock = None):
        if edge_type == gtirb.cfg.Edge.Type.Return:
            return "[rsp]"

        dest_operand = last_inst.operands[0]
        if dest_operand.type != CS_OP_MEM:
            return last_inst.op_str

        return self.mem_operand_to_str(block, last_inst, dest_operand)

    def indirect_branch_check_patch(self, operand_str: str, transient_start_symbol: gtirb.Symbol,
                                    transient_end_symbol: gtirb.Symbol, text_start_symbol: gtirb.Symbol,
                                    text_end_symbol: gtirb.Symbol, reads_registers=None):
        @self.constraints(scratch_registers=2, reads_registers=reads_registers or set())
        def patch(ctx):
            r1, r2 = ctx.scratch_registers
            return f"""
                mov {r1}, {operand_str}
                lea {r2}, [rip+{transient_start_symbol.name}]
                cmp {r1}, {r2}
                jb .L__indbr_check_text_marker{SYMBOL_SUFFIX}
                lea {r2}, [rip+{transient_end_symbol.name}]
                cmp {r1}, {r2}
                jb .L__indbr_check_skip{SYMBOL_SUFFIX}
            .L__indbr_check_text_marker{SYMBOL_SUFFIX}:
                lea {r2}, [rip+{text_start_symbol.name}]
                cmp {r1}, {r2}
                jb restore_checkpoint_MALFORMED_INDIRECT_BR
                lea {r2}, [rip+{text_end_symbol.name}]
                cmp {r1}, {r2}
                jae restore_checkpoint_MALFORMED_INDIRECT_BR
                cmp dword ptr [{r1}], 0x{self.MAGIC_WORDS[0]:08x}
                jne restore_checkpoint_MALFORMED_INDIRECT_BR
                cmp dword ptr [{r1} + 4], 0x{self.MAGIC_WORDS[1]:08x}
                jne restore_checkpoint_MALFORMED_INDIRECT_BR
            .L__indbr_check_skip{SYMBOL_SUFFIX}:
                nop
            """

        return patch

    @staticmethod
    def instruction_must_rollback(instruction) -> bool:
        if instruction.mnemonic in {
            "lfence", "mfence", "sfence", "serialize", "cpuid",
            "syscall", "sysenter",
        }:
            return True

        return instruction.mnemonic.startswith("rep")

    @staticmethod
    def is_control_transfer_instruction(instruction) -> bool:
        mnemonic = instruction.mnemonic
        return mnemonic in {"call", "jmp", "ret"} or mnemonic.startswith("j")
