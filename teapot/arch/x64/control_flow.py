from typing import Optional

import gtirb
from capstone import CS_OP_MEM

from teapot.configs.runtime import SYMBOL_SUFFIX


class X64ControlFlowPatchesMixin:
    def skipped_text_restore_guard_patch(self):
        """Guard untransformed text while preserving the SysV red zone."""
        return self.constraints()(lambda ctx: """
            lea rsp, [rsp-160]
            mov qword ptr [rsp], rax
            seto al
            lahf
            mov qword ptr [rsp+8], rax
            cmp qword ptr checkpoint_cnt, 0
            je 1f
            jmp restore_checkpoint_EXT_LIB
        1:
            mov rax, qword ptr [rsp+8]
            add al, 0x7f
            sahf
            mov rax, qword ptr [rsp]
            lea rsp, [rsp+160]
        """)

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

    def transient_pad_words(self):
        """The marker pair this mode places at the copy's reachable targets."""
        return tuple(self.MAGIC_WORDS)

    def transient_pad_passes(self, transient_section, decoder):
        """Design step 5: marker pads at the copy's reachable indirect targets."""
        from teapot.passes.transient.pad_transient_targets_pass import PadTransientTargetsPass

        return [PadTransientTargetsPass(transient_section, decoder, self.transient_pad_words(),
                                        directive=".long", arch=self)]

    def transient_anchor_passes(self, transient_section):
        """Design step 5: pads displaced by later passes move back to block starts."""
        from teapot.passes.transient.pad_transient_targets_pass import AnchorTransientPadsPass

        return [AnchorTransientPadsPass(transient_section, self.transient_pad_words(),
                                        directive=".long")]

    def indirect_branch_check_options(self, instruction):
        # Returns keep the copy sub-range clause: the return address after a
        # call need not carry a pad, while normal text still needs the pair.
        # `rep ret` reaches here as a two-word mnemonic.
        return ({"ret_clause": True}
                if instruction.mnemonic.split()[-1] in {"ret", "retf"} else {})

    def indirect_branch_check_patch(self, operand_str: str, transient_start_symbol: gtirb.Symbol,
                                    transient_end_symbol: gtirb.Symbol, text_start_symbol: gtirb.Symbol,
                                    text_end_symbol: gtirb.Symbol, reads_registers=None, *, ret_clause=False):
        @self.constraints(scratch_registers=2, clobbers_flags=True,
                          reads_registers=reads_registers or set())
        def patch(ctx):
            r1, r2 = ctx.scratch_registers
            # One window from normal text to the copy's end; the copy follows
            # normal text in the link. In-window branch targets need the pair,
            # and returns optionally keep the copy sub-range clause.
            ret_accept = f"""
                lea {r2}, [rip+{transient_start_symbol.name}]
                cmp {r1}, {r2}
                jae .L__indbr_check_skip{SYMBOL_SUFFIX}
            """ if ret_clause else ""
            return f"""
                mov {r1}, {operand_str}
                lea {r2}, [rip+{text_start_symbol.name}]
                cmp {r1}, {r2}
                jb restore_checkpoint_MALFORMED_INDIRECT_BR
                lea {r2}, [rip+{transient_end_symbol.name}]
                cmp {r1}, {r2}
                jae restore_checkpoint_MALFORMED_INDIRECT_BR
                {ret_accept}
                cmp dword ptr [{r1}], 0x{self.MAGIC_WORDS[0]:08x}
                jne restore_checkpoint_MALFORMED_INDIRECT_BR
                cmp dword ptr [{r1} + 4], 0x{self.MAGIC_WORDS[1]:08x}
                jne restore_checkpoint_MALFORMED_INDIRECT_BR
            .L__indbr_check_skip{SYMBOL_SUFFIX}:
                nop
            """

        return patch

    def instruction_must_rollback(self, instruction) -> bool:
        if instruction.mnemonic.lower().split()[-1] in self._UNSUPPORTED_STATE_SAVE_MNEMONICS:
            # Capstone reports these as eight-byte writes. FXSAVE writes a
            # 512-byte image; XSAVE's size depends on the enabled processor
            # state. Neither can use that nominal width for rollback logging.
            return True
        if instruction.mnemonic in {
            "lfence", "mfence", "sfence", "serialize", "cpuid",
            "syscall", "sysenter", "int3", "int1", "int",
        }:
            return True

        kind = self.rep_string_kind(instruction)
        if kind is not None:
            # REPNE is only documented for comparisons. Decode the raw prefix:
            # Capstone drops F2 on some string forms, including their REP name.
            return kind not in {"cmps", "scas"} and 0xf2 in instruction.bytes[:-1]
        # REP RET is a branch-prediction hint, not a string operation. BND and
        # NOTRACK also qualify control transfers without changing their kind.
        return (instruction.mnemonic.startswith("rep")
                and not self.is_control_transfer_instruction(instruction))

    @staticmethod
    def is_control_transfer_instruction(instruction) -> bool:
        mnemonic = instruction.mnemonic.split()[-1]
        return mnemonic in {"call", "jmp", "ret"} or mnemonic.startswith(("j", "loop"))

    @staticmethod
    def is_direct_transfer_instruction(instruction) -> bool:
        """A symbolic jmp/call/loop operand is an immediate, direct target."""
        mnemonic = instruction.mnemonic.split()[-1].lower()
        return mnemonic in {"call", "jmp"} or mnemonic.startswith(("j", "loop"))
