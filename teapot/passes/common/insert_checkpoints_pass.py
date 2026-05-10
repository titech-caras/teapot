import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.manager import NotEnoughFreeRegistersException
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from typing import List, Optional, Set
from uuid import UUID
import functools

from teapot.arch.architecture import Architecture
from teapot.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from teapot.utils.misc import distinguish_edges
from teapot.configs.blacklist import is_blacklisted_function


class InsertCheckpointsPass(VisitorPassMixin, RegInstAwarePassMixin):
    reg_manager: LiveRegisterManager
    text_section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, text_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder, arch: Architecture,
                 eligible_block_uuids: Optional[Set[UUID]] = None):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.text_section = text_section
        self.arch = arch
        self.eligible_block_uuids = eligible_block_uuids

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.text_section)

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        if self.reg_manager is not None and self.arch.checkpoint_patch_uses_live_registers():
            self.reg_manager.analyze(function)
        super().visit_function(function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        if self.eligible_block_uuids is not None and block.uuid not in self.eligible_block_uuids:
            return

        non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
        if len(non_fallthrough_edges) == 0:
            return

        if (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                non_fallthrough_edges[0].label.conditional):
            instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
            conditional_jump_offset = functools.reduce(lambda x, i: x + i.size, instructions[:-1], 0)
            if conditional_jump_offset > block.size:
                insts = ", ".join(
                    f"0x{inst.address:x}:{inst.mnemonic} {inst.op_str}({inst.size})"
                    for inst in instructions
                )
                fn_name = function.get_name() if function is not None else "<unknown>"
                raise ValueError(
                    f"checkpoint offset {conditional_jump_offset} exceeds block size {block.size} "
                    f"in {fn_name} block {block.uuid} at 0x{block.address:x}; instructions: {insts}"
                )

            if not self.arch.checkpoint_patch_uses_live_registers():
                self.insert_at(
                    block, conditional_jump_offset,
                    Patch.from_function(self.arch.checkpoint_patch(block.uuid, False)))
                return

            try:
                self.insert_at(block, conditional_jump_offset, Patch.from_function(
                    self.reg_manager.allocate_registers(
                        function, block, len(instructions) - 1, False)(
                        self.arch.checkpoint_patch(block.uuid))))
            except NotEnoughFreeRegistersException:
                self.insert_at(block, conditional_jump_offset, Patch.from_function(
                    self.arch.checkpoint_patch(block.uuid, False)))
