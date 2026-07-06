import gtirb
from capstone_gt import CsInsn
from gtirb_functions import Function
from gtirb_rewriting import InsertionContext
from gtirb_rewriting.assembly import Register

from teapot.configs.runtime import SYMBOL_SUFFIX
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


class RISCV64TransientMemOperandPoliciesPass(TransientMemOperandPoliciesPassBase):
    EXPECTED_ARCH = "riscv64"

    def __init__(self, reg_manager, transient_section, decoder, arch, *, dift_layout=None,
                 enable_asan_check: bool = True):
        super().__init__(
            reg_manager, transient_section, decoder, arch,
            dift_layout=dift_layout, enable_asan_check=enable_asan_check)
        self.save_float_state = False

    def _build_policy_patch(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                            block: gtirb.CodeBlock, function: Function = None):
        if inst.mnemonic in ("nop", "ret", "call", "jr", "jalr") or inst.mnemonic.startswith("j"):
            return None

        mem_operand = self.arch.memory_operand(inst)
        access_size = self.arch.mem_operand_size(inst, mem_operand)
        if mem_operand is None or access_size == 0 or not self.arch.mem_operand_is_read(inst, mem_operand):
            return None

        address_regs = list(self.arch.mem_operand_address_tag_registers(
            self.reg_manager.abi, inst, mem_operand,
            block=block, inst_offset=inst_offset))
        if not address_regs:
            return None

        regs_write = self.arch.access_registers(self.reg_manager.abi, inst, 1)
        write_regs = self._load_destination_registers(
            inst, regs_write, stop_operand=mem_operand, fallback_to_all_writes=True)
        if not write_regs:
            return None

        regs_read = self.arch.access_registers(self.reg_manager.abi, inst, 0)
        regs_read.update(self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand))

        patch = self._build_patch(
            inst, mem_operand, access_size, write_regs, address_regs,
            reads_registers={reg.name for reg in regs_read.union(regs_write)})
        return MemOperandPolicyPatch(patch, regs_read.union(regs_write))

    def _build_patch(self, inst: CsInsn, mem_operand, access_size: int, write_regs,
                     address_regs, *, reads_registers=None):

        @self.arch.constraints(scratch_registers=4, reads_registers=reads_registers or set())
        def patch(ctx: InsertionContext):
            tag_reg, addr_reg, tmp_reg, shadow_reg = ctx.scratch_registers[:4]
            done_label = f".L__mem_operand_policy_done{SYMBOL_SUFFIX}"

            asm = ""
            asm += "\n" + self.arch.clear_register_snippet(tag_reg)
            for reg in address_regs:
                asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)

            asm += self.arch.mem_operand_address_snippet(
                self.reg_manager.abi, inst, addr_reg, tmp_reg, mem_operand, ctx.stack_adjustment)
            asm += f"""
                andi {tmp_reg}, {tag_reg}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                beqz {tmp_reg}, .L__attacker_tags_check{SYMBOL_SUFFIX}
                {self.arch.report_gadget_snippet(
                    "KASPER_CACHE", addr_reg, tag_reg, shadow_reg, save_float_state=self.save_float_state)}

            .L__attacker_tags_check{SYMBOL_SUFFIX}:
                andi {tmp_reg}, {tag_reg}, {TAG_ATTACKER_INDIRECT}
                beqz {tmp_reg}, .L__asan_check{SYMBOL_SUFFIX}
                {self.arch.report_gadget_snippet(
                    "KASPER_MDS", addr_reg, tag_reg, shadow_reg, save_float_state=self.save_float_state)}
                {self.arch.dift_queue_reg_tag_snippet(tmp_reg, shadow_reg, TAG_SECRET_INDIRECT, write_regs)}

            .L__asan_check{SYMBOL_SUFFIX}:
                {self.arch.asan_check_snippet(
                    addr_reg, access_size, done_label,
                    shadow_offset=self.dift_layout.asan_shadow_offset,
                    scratch_reg=tmp_reg, shadow_reg=shadow_reg)
                 if self.enable_asan_check else f"j {done_label}"}
            .L__asan_check_fail{SYMBOL_SUFFIX}:
                andi {tmp_reg}, {tag_reg}, {TAG_ATTACKER}
                beqz {tmp_reg}, .L__asan_check_fail_non_attacker{SYMBOL_SUFFIX}
            .L__asan_check_fail_attacker{SYMBOL_SUFFIX}:
                {self.arch.report_gadget_snippet(
                    "KASPER_MDS", addr_reg, tag_reg, shadow_reg, save_float_state=self.save_float_state)}
                {self.arch.dift_queue_reg_tag_snippet(tmp_reg, shadow_reg, TAG_SECRET, write_regs)}
                j {done_label}
            .L__asan_check_fail_non_attacker{SYMBOL_SUFFIX}:
                {self.arch.dift_queue_reg_tag_snippet(tmp_reg, shadow_reg, TAG_ATTACKER_INDIRECT, write_regs)}
            {done_label}:
                nop
            """
            return asm

        return patch
