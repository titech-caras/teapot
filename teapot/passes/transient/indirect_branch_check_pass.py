import gtirb
from capstone import CS_OP_MEM, CS_OP_REG
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from teapot.liveness import LiveRegisterManager
from gtirb_rewriting import Patch, RewritingContext

from teapot.arch.architecture import Architecture
from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.passes.mixins import ArchSpecificPassMixin, RegInstAwarePassMixin, VisitorPassMixin
from teapot.utils.misc import distinguish_edges
from teapot.passes.transient.gadget_policy.mem_operand.base import MemOperandPolicyPatch
from teapot.passes.transient.gadget_policy.store import tagged_report


class TransientIndirectBranchCheckDestPass(ArchSpecificPassMixin, VisitorPassMixin, RegInstAwarePassMixin):
    transient_section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder,
                 transient_section_start_symbol: gtirb.Symbol, transient_section_end_symbol: gtirb.Symbol,
                 text_section_start_symbol: gtirb.Symbol, text_section_end_symbol: gtirb.Symbol,
                 arch: Architecture):
        self.check_expected_arch(arch)
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.transient_section = transient_section
        self.transient_section_start_symbol = transient_section_start_symbol
        self.transient_section_end_symbol = transient_section_end_symbol
        self.text_section_start_symbol = text_section_start_symbol
        self.text_section_end_symbol = text_section_end_symbol
        self.arch = arch

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.transient_section)

    def visit_function(self, function: Function):
        if self.reg_manager is not None:
            self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        edge = non_fallthrough_edges[0]
        if not self._must_check_edge(edge, function):
            return

        instructions = list(self.decoder.get_instructions(block))
        # A RISC-V AUIPC+JALR pair whose relocation names its target is a
        # direct transfer, even when the lift adds an indirect edge to it. A
        # check would also land before the AUIPC (the rewriter keeps the pair
        # whole) and test a stale base and displacement.
        if self.arch.direct_transfer_expression(block, instructions) is not None:
            return
        last_inst = instructions[-1]
        operand_str = self.arch.indirect_branch_operand(edge.label.type, last_inst, block)
        operand_registers = set()
        if self.reg_manager is not None:
            operand_registers = self.arch.registers_in_operand_string(self.reg_manager.abi, operand_str)
        if self.reg_manager is not None:
            self.reg_manager.add_live_registers(function, block, len(instructions) - 1, operand_registers)

        checker = self.arch.indirect_branch_check_patch
        options = self.arch.indirect_branch_check_options(last_inst)
        if (self.arch.uses_bti_landing_checks and
                last_inst.mnemonic.lower() in ("br", "blr") and
                edge.label.type != gtirb.cfg.Edge.Type.Return):
            checker = self.arch.indirect_branch_hardware_check_patch
            options = {}
        # RET and any instruction not proved to set BTYPE retain the complete
        # software predicate. Hardware landing checks do not protect returns.
        patch = checker(
            operand_str, self.transient_section_start_symbol, self.transient_section_end_symbol,
            self.text_section_start_symbol, self.text_section_end_symbol,
            reads_registers={reg.name for reg in operand_registers},
            **options)
        if self.reg_manager is not None:
            patch = self.allocate_registers(
                function, block, len(instructions) - 1)(patch)
        self.insert_at(block, sum(inst.size for inst in instructions[:-1]), Patch.from_function(patch))

    @staticmethod
    def _must_check_edge(edge: gtirb.Edge, function: Function) -> bool:
        return (
            edge.label.type == gtirb.cfg.Edge.Type.Return and function.get_name() != "main" + SYMBOL_SUFFIX
        ) or (
            edge.label.type in (gtirb.cfg.Edge.Type.Call, gtirb.cfg.Edge.Type.Branch) and
            not edge.label.direct
        )


class TransientIndirectTargetPolicyPass(TransientIndirectBranchCheckDestPass):
    """Read the target tag before JALR/BLR overwrites its link register."""

    def __init__(self, reg_manager, transient_section, decoder, arch, *, dift_layout):
        super().__init__(reg_manager, transient_section, decoder, None, None, None, None, arch)
        self.dift_layout = dift_layout

    def visit_code_block(self, block, function=None):
        instructions = list(self.decoder.get_instructions(block))
        if not instructions:
            return
        index = len(instructions) - 1
        offset = sum(i.size for i in instructions[:-1])
        info = self._build_policy_patch(instructions[-1], index, offset, block, function)
        if info is not None:
            self.reg_manager.add_live_registers(function, block, index, info.live_registers)
            patch = self.allocate_registers(function, block, index)(info.patch)
            self.insert_at(block, offset, Patch.from_function(patch))

    def _build_policy_patch(self, inst, inst_idx, inst_offset, block, function=None):
        if inst_offset + inst.size != block.size:
            return None
        edges, _ = distinguish_edges(block.outgoing_edges)
        if not edges or edges[0].label.type not in (gtirb.EdgeType.Call, gtirb.EdgeType.Branch):
            return None
        arch, abi = self.arch, self.reg_manager.abi
        instructions = list(self.decoder.get_instructions(block))
        if arch.direct_transfer_expression(block, instructions) is not None:
            return None
        mnemonic = inst.mnemonic.lower().split()[-1]
        if arch.name == 'riscv64' and (mnemonic != 'jalr' or arch.is_return_instruction(inst)):
            return None
        if arch.name == 'aarch64' and mnemonic not in ('br', 'blr'):
            return None
        if arch.name == 'x64' and (mnemonic not in ('jmp', 'call') or
                                   inst.operands[0].type not in (CS_OP_REG, CS_OP_MEM)):
            return None
        operand = arch.indirect_branch_operand(edges[0].label.type, inst, block)
        registers = arch.registers_in_operand_string(abi, operand)
        memory = arch.name == 'x64' and inst.operands[0].type == CS_OP_MEM
        @arch.constraints(scratch_registers=4 if arch.name == 'aarch64' else 3,
                          clobbers_flags=True, reads_registers={r.name for r in registers})
        def patch(ctx):
            tag, target, temp = ctx.scratch_registers[:3]
            extra = ctx.scratch_registers[3] if arch.name == 'aarch64' else None
            asm = arch.clear_register_snippet(tag)
            if memory:
                # Evaluate the implicit pointer load like scalar DIFT: merge
                # the memory value tag with its address dependencies.
                asm += arch.effective_address_snippet(target, operand, temp)
                asm += f'mov {temp}, [{target}]\n'
                asm += arch.dift_shadow_addr_snippet(target, None, self.dift_layout.xor_mask)
                asm += f'movzx {tag:32}, byte ptr [{target}]\nmov {target}, {temp}\n'
                for reg in sorted(registers, key=lambda r: r.name):
                    asm += arch.dift_or_reg_tag_snippet(tag, temp, reg)
            else:
                for reg in sorted(registers, key=lambda r: r.name):
                    asm += arch.dift_or_reg_tag_snippet(tag, temp, reg)
                if arch.name == 'riscv64':
                    asm += arch.materialize_target(target, operand)
                    asm += f'andi {target}, {target}, -2\n'
                else:
                    asm += f'mov {target}, {operand}\n'
            return asm + tagged_report(arch, 'TARGET', target, tag, temp, extra)
        return MemOperandPolicyPatch(patch, registers, registers,
                                     reads_memory_tags=memory, queues_tags=False)
