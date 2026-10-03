from typing import Optional
from uuid import UUID

import gtirb

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import AARCH64_SHADOW_STACK_INDIRECT_TARGET_OFFSET
from teapot.arch.aarch64.operands import aarch64_register_number
from teapot.utils.misc import generate_distinct_label_name


AARCH64_CALL_MNEMONICS = frozenset(("bl", "blr", "blraa", "blrab", "blraaz", "blrabz"))
AARCH64_DIRECT_TRANSFER_MNEMONICS = frozenset(("b", "bl", "cbz", "cbnz", "tbz", "tbnz"))
AARCH64_PAC_BRANCHES = frozenset(("braa", "brab", "braaz", "brabz", "blraa", "blrab",
                                "blraaz", "blrabz", "retaa", "retab"))
AARCH64_PAC_AUTH_WORDS = frozenset((0xd50323bf, 0xd50323ff, 0xd65f0bff, 0xd65f0fff))
AARCH64_PAC_WORD_BASES = frozenset((0xdac10000, 0xdac12000, 0xdac11000, 0xdac13000))
AARCH64_PAC_HINT_WORDS = frozenset((0xd503233f, 0xd503237f))


class AArch64ControlFlowPatchesMixin:
    def skipped_text_restore_guard_patch(self):
        """Guard untransformed text without relying on initialized scratch state."""
        return self.constraints()(lambda ctx: f"""
            sub sp, sp, #32
            stp x16, x17, [sp]
            mrs x16, nzcv
            str x16, [sp, #16]
            {self.load_address("x16", "checkpoint_cnt")}
            ldr x16, [x16]
            cbz x16, 1f
            b restore_checkpoint_EXT_LIB
        1:
            ldr x16, [sp, #16]
            msr nzcv, x16
            ldp x16, x17, [sp]
            add sp, sp, #32
        """)

    @staticmethod
    def retarget_last_operand(mnemonic: str, op_str: str, target_symbol_name: str) -> str:
        operands = [operand.strip() for operand in op_str.split(",") if operand.strip()]
        if not operands:
            return f"{mnemonic} {target_symbol_name}"

        operands[-1] = target_symbol_name
        return f"{mnemonic} {', '.join(operands)}"

    @classmethod
    def invert_conditional_branch(cls, mnemonic: str, op_str: str, target_symbol_name: str) -> Optional[str]:
        mnemonic = mnemonic.lower()
        if mnemonic == "cbz":
            return cls.retarget_last_operand("cbnz", op_str, target_symbol_name)
        if mnemonic == "cbnz":
            return cls.retarget_last_operand("cbz", op_str, target_symbol_name)
        if mnemonic == "tbz":
            return cls.retarget_last_operand("tbnz", op_str, target_symbol_name)
        if mnemonic == "tbnz":
            return cls.retarget_last_operand("tbz", op_str, target_symbol_name)
        if mnemonic.startswith("b."):
            inverse = cls.INVERSE_CONDITIONS.get(mnemonic[2:])
            if inverse is not None:
                return cls.retarget_last_operand(f"b.{inverse}", op_str, target_symbol_name)
        return None

    @classmethod
    def _long_jump(cls, target_symbol_name: str, jump_register: str) -> str:
        return f"""
            {cls.load_address(jump_register, target_symbol_name)}
            br {jump_register}
        """

    def trampoline_patch(self, block_uuid: UUID, transient_block_uuid: UUID, mnemonic: str, op_str: str,
                         conditional_target_symbol_name: str, non_conditional_target_symbol_name: str,
                         use_long_jumps: bool = False, jump_register: str = None,
                         conditional_jump_register: str = None, non_conditional_jump_register: str = None,
                         conditional_use_long_jump: bool = None, non_conditional_use_long_jump: bool = None,
                         checkpoint_spare_registers=()):
        fallthrough_label = generate_distinct_label_name(".__trampoline_fallthrough_", block_uuid)
        inverse_branch = self.invert_conditional_branch(mnemonic, op_str, fallthrough_label)
        conditional_use_long_jump = use_long_jumps if conditional_use_long_jump is None else conditional_use_long_jump
        non_conditional_use_long_jump = (
            use_long_jumps if non_conditional_use_long_jump is None else non_conditional_use_long_jump)
        conditional_reg = conditional_jump_register or jump_register or "x16"
        non_conditional_reg = non_conditional_jump_register or jump_register or conditional_reg
        conditional_jump = self._long_jump(conditional_target_symbol_name, conditional_reg) \
            if conditional_use_long_jump else f"b {conditional_target_symbol_name}"
        non_conditional_jump = self._long_jump(non_conditional_target_symbol_name, non_conditional_reg) \
            if non_conditional_use_long_jump else f"b {non_conditional_target_symbol_name}"
        if inverse_branch is None:
            trampoline_body = f"""
                {self.retarget_last_operand(mnemonic, op_str, conditional_target_symbol_name)}
                {non_conditional_jump}
            """
        else:
            trampoline_body = f"""
                {inverse_branch}
                {conditional_jump}
            {fallthrough_label}:
                {non_conditional_jump}
            """
        checkpoint_restore = "\n".join(
            f"mov {fixed}, {spare}"
            for fixed, spare in zip(self.CHECKPOINT_FIXED_REGISTERS, checkpoint_spare_registers)
        )
        return self.constraints()(lambda ctx: f"""
        {generate_distinct_label_name(".__trampoline_landing_", block_uuid)}:
        {generate_distinct_label_name(".__trampoline_landing_", transient_block_uuid)}:
            {self.load_address("x16", "checkpoint_target_metadata")}
            ldr x16, [x16, #{self.CHECKPOINT_TARGET_SCRATCH_REG_ADDR}]
            {checkpoint_restore}
        {generate_distinct_label_name(".__trampoline_", block_uuid)}:
        {generate_distinct_label_name(".__trampoline_", transient_block_uuid)}:
            {trampoline_body}
        """)

    def indirect_branch_target_patch(self, target_symbol: gtirb.Symbol, *, use_scratch_registers: bool = False):
        @self.constraints(scratch_registers=1 if use_scratch_registers else 0)
        def patch(ctx):
            if use_scratch_registers:
                counter_reg = ctx.scratch_registers[0]
                prologue = ""
                checkpoint_epilogue = ""
                done_epilogue = ""
            else:
                counter_reg = "x16"
                prologue = self.save_regs_to_shadow_stack(
                    ("x16", "x17"), save_flags=True,
                    frame_offset=AARCH64_SHADOW_STACK_INDIRECT_TARGET_OFFSET, preserve_sp=True)
                checkpoint_epilogue = self.restore_regs_from_shadow_stack(
                    ("x16", "x17"), save_flags=True,
                    frame_offset=AARCH64_SHADOW_STACK_INDIRECT_TARGET_OFFSET, preserve_sp=True)
                done_epilogue = checkpoint_epilogue
            return f"""
                .word 0x{self.MAGIC_WORDS[0]:08x}
                .word 0x{self.MAGIC_WORDS[1]:08x}
                {prologue}
                {self.load_address(counter_reg, "checkpoint_cnt")}
                ldr {counter_reg}, [{counter_reg}]
                cbz {counter_reg}, .L__indbr_transform_done{SYMBOL_SUFFIX}
                {checkpoint_epilogue}
                b {target_symbol.name}
            .L__indbr_transform_done{SYMBOL_SUFFIX}:
                {done_epilogue}
            """

        return patch

    def indirect_transform_uses_live_registers(self) -> bool:
        return True

    def transient_pad_words(self):
        """The marker pair this mode places at the copy's reachable targets."""
        return ((0xd50324df, self.MAGIC_WORDS[1])
                if self.uses_bti_landing_checks else tuple(self.MAGIC_WORDS))

    def transient_pad_passes(self, transient_section, decoder, state):
        """Design step 5: marker pads at the copy's reachable indirect targets."""
        from teapot.passes.transient.pad_transient_targets_pass import PadTransientTargetsPass

        # The combined mode keeps the copy's return range clause.
        return [PadTransientTargetsPass(
            transient_section, decoder, self.transient_pad_words(), arch=self,
            pad_return_sites=not self.uses_bti_landing_checks, state=state)]

    def transient_anchor_passes(self, transient_section, state):
        """Design step 5: pads displaced by later passes move back to block starts."""
        from teapot.passes.transient.pad_transient_targets_pass import AnchorTransientPadsPass

        pads = state.pads.require("the transient anchor pass")

        return [AnchorTransientPadsPass(transient_section, self.transient_pad_words(),
                                        padded=pads.padded_blocks, originals=pads.copy_blocks)]

    def indirect_branch_operand(self, edge_type, last_inst, block: gtirb.CodeBlock = None) -> Optional[str]:
        if edge_type == gtirb.cfg.Edge.Type.Return:
            return last_inst.op_str.strip() or "x30"
        # PAC modifiers are not part of the target address operand.
        return last_inst.op_str.split(",", 1)[0].strip() or None

    def indirect_branch_check_options(self, instruction):
        options = {"strip_pac": True} if instruction.mnemonic in AARCH64_PAC_BRANCHES else {}
        # Software mode checks the marker pair alone. The combined mode keeps
        # the window, since BTI enforces landings only on guarded pages, and
        # returns keep the copy sub-range clause there.
        if self.uses_bti_landing_checks:
            options["window"] = True
            if instruction.mnemonic in ("ret", "retaa", "retab"):
                options["ret_clause"] = True
        return options

    def instruction_must_rollback(self, instruction) -> bool:
        return (instruction.mnemonic in {
            "dmb", "dsb", "isb", "sb", "csdb", "ssbb", "pssbb",
            "svc", "hvc", "smc", "brk",
        } or (instruction.mnemonic == "dc" and
              instruction.op_str.split(",", 1)[0].strip() in {"zva", "gva", "gzva"}))

    def is_control_transfer_instruction(self, instruction) -> bool:
        return instruction.mnemonic in {"b", "bl", "blr", "br", "ret"} | AARCH64_PAC_BRANCHES

    def is_direct_transfer_instruction(self, instruction) -> bool:
        """A direct branch or call takes its target as an immediate operand."""
        mnemonic = instruction.mnemonic.lower()
        return mnemonic in AARCH64_DIRECT_TRANSFER_MNEMONICS or mnemonic.startswith("b.")

    @staticmethod
    def is_pac_word(word: int) -> bool:
        """True for PAC signing, authentication and authenticated-return words."""
        if word in AARCH64_PAC_AUTH_WORDS or word in AARCH64_PAC_HINT_WORDS:
            return True
        return (word & 0xffffd800) in AARCH64_PAC_WORD_BASES

    def indirect_branch_check_patch(self, operand_str: str, transient_start_symbol: gtirb.Symbol,
                                    transient_end_symbol: gtirb.Symbol, text_start_symbol: gtirb.Symbol,
                                    text_end_symbol: gtirb.Symbol, reads_registers=None, *, strip_pac=False,
                                    window=False, ret_clause=False):
        @self.constraints(scratch_registers=3,
                          clobbers_flags=True,
                          reads_registers=reads_registers or set())
        def patch(ctx):
            target_reg, temp_reg, magic_reg = ctx.scratch_registers[:3]
            # Strip only the scratch copy used for address/marker checks. The
            # original BRA*/BLRA*/RETAA/B still authenticates its untouched
            # source and modifier, so this does not bypass authentication.
            # Emit XPACI by encoding: the patch assembler need not enable PAC
            # globally for ordinary AArch64 input that contains no PAC forms.
            normalize = (f".inst {0xdac143e0 | aarch64_register_number(getattr(target_reg, 'name', target_reg)):#x}"
                         if strip_pac else "")
            # Combined mode: one window, normal text immediately preceding the
            # copy, and returns inside the copy accepted by range. Software
            # mode: every target carries the marker pair, return sites
            # included; a wild target faults on the load, which rolls back.
            ret_accept = f"""
                {self.load_address(temp_reg, transient_start_symbol.name)}
                cmp {target_reg}, {temp_reg}
                b.hs 1f
            """ if ret_clause else ""
            window_test = f"""
                {self.load_address(temp_reg, text_start_symbol.name)}
                cmp {target_reg}, {temp_reg}
                b.lo 2f
                {self.load_address(temp_reg, transient_end_symbol.name)}
                cmp {target_reg}, {temp_reg}
                b.hs 2f
                {ret_accept}
            """ if window else ""
            return f"""
                mov {target_reg}, {operand_str}
                {normalize}
                {window_test}
                ldr {self.w_reg(temp_reg)}, [{target_reg}]
                {self.mov_w_imm32(self.w_reg(magic_reg), self.MAGIC_WORDS[0])}
                cmp {self.w_reg(temp_reg)}, {self.w_reg(magic_reg)}
                b.ne 2f
                ldr {self.w_reg(temp_reg)}, [{target_reg}, #4]
                {self.mov_w_imm32(self.w_reg(magic_reg), self.MAGIC_WORDS[1])}
                cmp {self.w_reg(temp_reg)}, {self.w_reg(magic_reg)}
                b.ne 2f
            1:
                b 3f
            2:
                b restore_checkpoint_MALFORMED_INDIRECT_BR
            3:
                nop
            """

        return patch
