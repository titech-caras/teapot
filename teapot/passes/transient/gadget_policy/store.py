"""Store address checks use the same address tags and exemptions as loads."""
from teapot.configs.tags import TAG_SECRET, TAG_SECRET_INDIRECT
from teapot.passes.transient.gadget_policy.mem_operand.base import (
    MemOperandPolicyPatch, TransientMemOperandPoliciesPassBase,
)


def tagged_report(arch, kind, address, tag, temp, extra=None, *, mask=255):
    """Report without changing the checked value or its tag."""
    if arch.name == 'x64':
        return f'''test {tag:8l}, {mask}
            jz 1f
            {arch.report_gadget_snippet(kind, addr_reg=address, tag_reg=tag)}
        1: nop
        '''
    if arch.name == 'aarch64':
        return f'''mov {temp:32}, #{mask}
            and {temp:32}, {tag:32}, {temp:32}
            cbz {temp:32}, 1f
            {arch.report_gadget_snippet(kind, address, tag, extra, temp)}
        1: nop
        '''
    return f'''andi {temp}, {tag}, {mask}
        beqz {temp}, 1f
        {arch.report_gadget_snippet(kind, address, tag, temp, save_float_state=True)}
    1: nop
    '''


class TransientStorePolicyPass(TransientMemOperandPoliciesPassBase):
    def _build_policy_patch(self, inst, inst_idx, inst_offset, block, function=None):
        arch, abi = self.arch, self.reg_manager.abi
        if arch.instruction_must_rollback(inst) or arch.is_instrumentation_helper_instruction(
                inst, inst_idx, getattr(self, '_current_instructions', None)):
            return None
        mem = arch.memory_operand(inst)
        operand = None
        if arch.name == 'x64':
            if arch.rep_string_kind(inst) is not None:
                return None  # The bounded loop checks each executed store.
            implicit = arch.implicit_memory_write(inst)
            if implicit is not None:
                operand, _ = implicit
                registers = arch.registers_in_operand_string(abi, operand)
            elif mem is not None and arch.mem_operand_is_write(inst, mem):
                if not arch.mem_operand_uses_dynamic_address(mem):
                    return None
                operand = arch.mem_operand_to_str(block, inst, mem)
                registers = arch.mem_operand_registers(abi, inst, mem)
            else:
                return None
        else:
            if mem is None or not arch.mem_operand_is_write(inst, mem) or not arch.mem_operand_size(inst, mem):
                return None
            if arch.name == 'aarch64' and not arch.mem_operand_uses_dynamic_address(inst, mem):
                return None
            registers = arch.mem_operand_address_tag_registers(
                abi, inst, mem, block=block, inst_offset=inst_offset)
        if not registers:
            return None
        expression = arch.mem_operand_address_expression(block, inst, mem, inst_offset) if operand is None else None
        patch = self.build_store_patch(inst, mem, registers, operand=operand, expression=expression)
        return MemOperandPolicyPatch(patch, registers, registers, queues_tags=False)

    def build_store_patch(self, inst, mem, registers, *, operand=None, expression=None):
        arch = self.arch
        @arch.constraints(scratch_registers=4 if arch.name == 'aarch64' else 3,
                          clobbers_flags=True, reads_registers={r.name for r in registers})
        def patch(ctx):
            tag, address, temp = ctx.scratch_registers[:3]
            extra = ctx.scratch_registers[3] if arch.name == 'aarch64' else None
            asm = arch.clear_register_snippet(tag)
            for reg in sorted(registers, key=lambda r: r.name):
                asm += arch.dift_or_reg_tag_snippet(tag, temp, reg)
            if arch.name == 'x64':
                asm += arch.effective_address_snippet(address, operand, temp)
            else:
                asm += arch.mem_operand_address_snippet(
                    self.reg_manager.abi, inst, address, temp, mem, ctx.stack_adjustment,
                    mem_symexpr=expression)
            return asm + tagged_report(arch, 'KASPER_CACHE_STORE', address, tag, temp, extra,
                                       mask=TAG_SECRET | TAG_SECRET_INDIRECT)
        return patch
