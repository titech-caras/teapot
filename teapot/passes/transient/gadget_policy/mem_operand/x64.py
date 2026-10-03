from types import SimpleNamespace
from typing import Optional

import gtirb
from capstone import CS_AC_WRITE, CsInsn
from gtirb_functions import Function
from gtirb_rewriting import InsertionContext, patch_constraints
from gtirb_rewriting.assembly import Register, X86Syntax

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import ScratchpadSlots
from teapot.configs.tags import (
    TAG_ATTACKER,
    TAG_ATTACKER_INDIRECT,
    TAG_SECRET,
    TAG_SECRET_INDIRECT,
)
from teapot.passes.transient.gadget_policy.mem_operand.base import (
    MemOperandPolicyPatch,
    TransientMemOperandPoliciesPassBase,
)

# Tags that make the policy report or queue even for an in-bounds access. A
# pure attacker tag does neither unless the access fails the ASan check.
FAST_PATH_TAG_MASK = TAG_SECRET | TAG_SECRET_INDIRECT | TAG_ATTACKER_INDIRECT
# The fast path's cold path takes its four extra registers from those the
# report snippet itself saves around its runtime call.
COLD_PATH_REGISTERS = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10")


class X64TransientMemOperandPoliciesPass(TransientMemOperandPoliciesPassBase):
    EXPECTED_ARCH = "x64"

    def _build_policy_patch(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                            block: gtirb.CodeBlock, function: Function = None):
        if self.arch.rep_string_kind(inst) is not None:
            return None
        if inst.mnemonic in ("lea", "nop", "push", "pop") or self.arch.is_control_transfer_instruction(inst):
            return None

        mem_operand = self.arch.memory_operand(inst)
        if mem_operand is None:
            return None

        write_operand = next(iter(x for x in inst.operands if x.access & CS_AC_WRITE), None)
        if write_operand is None or write_operand == mem_operand:
            return None

        if not self.arch.mem_operand_uses_dynamic_address(mem_operand):
            return None

        write_reg = self.arch.register_from_name(
            self.reg_manager.abi, inst.reg_name(write_operand.reg))
        if write_reg is None:
            # The x64 ABI/DIFT register map intentionally covers GPRs and XMM
            # registers, but not AVX-512 mask registers such as k0.  The main
            # DIFT pass already omits such unsupported destinations; keep the
            # memory-operand policy consistent instead of failing the rewrite.
            return None

        mem_operand_str = self.arch.mem_operand_to_str(block, inst, mem_operand)
        conditional = self.arch.conditional_move_suffix(inst)
        build = (self._build_fast_patch
                 if self._fast_path_eligible(mem_operand_str, mem_operand.size, function, block, inst_idx)
                 else self._build_patch)
        patch = build(inst, mem_operand_str, mem_operand.size, conditional=conditional,
                      mem_operand=mem_operand, write_reg=write_reg)
        return MemOperandPolicyPatch(
            patch, set(), self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand))

    def _fast_path_eligible(self, mem_operand_str: str, access_size: int, function, block, inst_idx) -> bool:
        """An ordinary 8-byte load with a dead GPR at the instruction. The allocator hands
        that register to the patch, so the common case runs without spills."""
        if not self.enable_asan_check or access_size != 8 or function is None:
            return False
        if self.arch.mem_operand_segment(mem_operand_str) is not None:
            return False
        # The shadow compare's displacement is a sign-extended 32-bit value.
        if not -(1 << 31) <= self.dift_layout.asan_shadow_offset < (1 << 31):
            return False
        return bool(self.reg_manager.free_registers(function, block, inst_idx))

    def _build_fast_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                          conditional: Optional[str], mem_operand, write_reg: Optional[Register] = None):
        """The full policy behind a one-register fast path.

        The fast path takes an access whose address registers carry no reporting tag, which is
        8-aligned, and whose shadow byte is zero: exactly the accesses the full policy passes
        without a report or a queued tag. Any other access runs the full policy
        (`_build_patch`), which recomputes the address and the tags. Its four extra registers
        are saved in a dedicated slot, after the branch.
        """
        assert access_size == 8
        addr_regs = sorted(self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand),
                           key=lambda reg: reg.name)
        full = self._build_patch(inst, mem_operand_str, access_size, conditional=conditional,
                                 mem_operand=mem_operand, write_reg=write_reg,
                                 label_key="mem_operand_policy_slow", capture_condition=False)
        condition_slot = f"byte ptr scratchpad+{ScratchpadSlots.X64_MEM_POLICY_CONDITION}"
        cold = ScratchpadSlots.X64_MEM_POLICY_COLD_SPILL
        shadow_offset = self.dift_layout.asan_shadow_offset

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=1, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            r = ctx.scratch_registers[0]
            excluded = {r.name} | {reg.name for reg in addr_regs}
            spill = [self.reg_manager.abi.get_register(name) for name in COLD_PATH_REGISTERS
                     if name not in excluded][:4]
            assert len(spill) == 4 and len({reg.name for reg in spill}) == 4
            label = f".L__mem_operand_policy_fast{SYMBOL_SUFFIX}"
            # CMOV reads memory even when the assignment is skipped: capture its
            # condition before the tests below clobber the flags.
            asm = f"set{conditional} {condition_slot}\n" if conditional is not None else ""
            for reg in addr_regs:
                asm += f"""
                    test byte ptr dift_reg_tags+{self.arch.dift_register_id(reg)}, {FAST_PATH_TAG_MASK}
                    jnz {label}_slow
                """
            asm += self.arch.effective_address_snippet(r, mem_operand_str)
            asm += f"""
                test {r:8l}, 7
                jnz {label}_slow
                shr {r}, 3
                cmp byte ptr [{r} + {shadow_offset}], 0
                je {label}_done
            {label}_slow:
            """
            asm += "".join(f"mov qword ptr scratchpad+{cold + 8 * index}, {reg}\n"
                           for index, reg in enumerate(spill))
            asm += full(SimpleNamespace(scratch_registers=(r, *spill)))
            asm += "".join(f"mov {reg}, qword ptr scratchpad+{cold + 8 * index}\n"
                           for index, reg in enumerate(spill))
            asm += f"""
            {label}_done:
                nop
            """
            return asm

        return patch

    def _build_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                     conditional: Optional[str], mem_operand, write_reg: Optional[Register] = None,
                     queued_tag_operand=None, label_key="mem_operand_policy", capture_condition=True):
        scratch_registers = (5 if access_size > 1 else 4) if self.enable_asan_check else 3
        addr_regs = self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand)
        # A string load can feed memory or a comparison instead of a GPR. Its
        # per-element queue is consumed by the REP propagation kernel.
        queue_tags = {
            tag: (self.arch.dift_queue_reg_tag_snippet(None, None, tag, write_reg)
                  if write_reg is not None else f"or byte ptr {queued_tag_operand}, {tag}\n")
            for tag in (TAG_SECRET_INDIRECT, TAG_SECRET, TAG_ATTACKER_INDIRECT)
        }
        condition_slot = f"byte ptr scratchpad+{ScratchpadSlots.X64_MEM_POLICY_CONDITION}"
        if conditional is not None:
            # CMOV reads memory even when the register assignment is skipped.
            # Capture the original flags before the checks clobber them, and
            # predicate only destination-tag updates. This dedicated byte is
            # also safe across report callbacks, which may clobber GPRs.
            queue_tags = {tag: f"""
                cmp {condition_slot}, 0
                je .L__{label_key}_skip_tag_{tag}{SYMBOL_SUFFIX}
                {snippet}
            .L__{label_key}_skip_tag_{tag}{SYMBOL_SUFFIX}:
            """ for tag, snippet in queue_tags.items()}

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers[:3]
            r4 = ctx.scratch_registers[3] if scratch_registers > 3 else None
            r5 = ctx.scratch_registers[4] if scratch_registers > 4 else None

            asm = (f"set{conditional} {condition_slot}\n"
                   if conditional is not None and capture_condition else "")
            asm += self.arch.effective_address_snippet(r2, mem_operand_str, r3)
            asm += self.arch.clear_register_snippet(r1)

            for reg in sorted(addr_regs, key=lambda reg: reg.name):
                asm += self.arch.dift_or_reg_tag_snippet(r1, None, reg)

            label = f".L__{label_key}{SYMBOL_SUFFIX}"
            done_label = f"{label}_done"
            asm += f"""
                test {r1:8l}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                jz {label}_attacker_tags_check
                {self.arch.report_gadget_snippet("KASPER_CACHE", addr_reg=r2, tag_reg=r1)}

            {label}_attacker_tags_check:
                test {r1:8l}, {TAG_ATTACKER_INDIRECT}
                jz {label}_asan_check
                {self.arch.report_gadget_snippet("KASPER_MDS", addr_reg=r2, tag_reg=r1)}
                {queue_tags[TAG_SECRET_INDIRECT]}

            {label}_asan_check:
                {self.arch.asan_check_snippet(
                    r2, access_size, done_label,
                    shadow_offset=self.dift_layout.asan_shadow_offset,
                    shadow_reg=r3, scratch_reg=r4, end_reg=r5)
                 if self.enable_asan_check else f"jmp {done_label}"}
            {label}_asan_check_fail:
                test {r1:8l}, {TAG_ATTACKER}
                jz {label}_asan_check_fail_non_attacker
            {label}_asan_check_fail_attacker:
                {self.arch.report_gadget_snippet("KASPER_MDS", addr_reg=r2, tag_reg=r1)}
                {queue_tags[TAG_SECRET]}
                jmp {done_label}
            {label}_asan_check_fail_non_attacker:
                {queue_tags[TAG_ATTACKER_INDIRECT]}
            {done_label}:
                nop
            """

            return asm

        return patch
