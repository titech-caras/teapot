import gtirb
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.manager import NotEnoughFreeRegistersException
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from typing import List
from uuid import UUID
import functools

from NaHCO3.utils.misc import distinguish_edges, generate_distinct_label_name
from NaHCO3.config import SYMBOL_SUFFIX


class TextInsertCheckpointsPass(Pass):
    reg_manager: LiveRegisterManager
    text_section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, text_section: gtirb.Section):
        self.reg_manager = reg_manager
        self.text_section = text_section
        self.decoder = GtirbInstructionDecoder(text_section.module.isa)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        rewriting_ctx.register_insert(AllFunctionsScope(FunctionPosition.ENTRY, BlockPosition.ENTRY, {"main"}), CallPatch(
            rewriting_ctx.get_or_insert_extern_symbol("libcheckpoint_enable", '')
        ))
        rewriting_ctx.register_insert(AllFunctionsScope(FunctionPosition.EXIT, BlockPosition.EXIT, {"main"}), CallPatch(
            rewriting_ctx.get_or_insert_extern_symbol("libcheckpoint_disable", '')
        ))

        for function in functions:
            if next(iter(function.get_entry_blocks())).section.name != self.text_section.name:
                continue

            self.reg_manager.analyze(function)
            for block in function.get_all_blocks():
                non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
                if len(non_fallthrough_edges) == 0:
                    continue

                if (non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                        non_fallthrough_edges[0].label.conditional):
                    instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
                    conditional_jump_offset = functools.reduce(lambda x, i: x + i.size, instructions[:-1], 0)

                    try:
                        rewriting_ctx.insert_at(block, conditional_jump_offset, Patch.from_function(
                            self.reg_manager.allocate_registers(
                                function, block, len(instructions) - 1, False)(
                                self.__build_checkpoint_patch(block.uuid))))
                    except NotEnoughFreeRegistersException:
                        rewriting_ctx.insert_at(block, conditional_jump_offset, Patch.from_function(
                            self.reg_manager.allocate_registers(
                                function, block, len(instructions) - 1, False)(
                                self.__build_checkpoint_patch(block.uuid, False))))

    @staticmethod
    def __build_checkpoint_patch(block_uuid: UUID, use_scratch_registers: bool = True):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=1 if use_scratch_registers else 0)
        def patch(ctx: InsertionContext):
            r = ctx.scratch_registers[0] if use_scratch_registers else "rax"
            prologue = "" if use_scratch_registers else "mov scratchpad, rax"
            epilogue = "" if use_scratch_registers else "mov rax, scratchpad"
            return f"""
                {prologue}
                lea {r}, [rip+{generate_distinct_label_name(".__trampoline_", block_uuid)}]
                mov checkpoint_target_metadata, {r}
                lea {r}, [rip+.L__after_checkpoint{SYMBOL_SUFFIX}]
                mov [checkpoint_target_metadata+8], {r}
                {epilogue}
                jmp make_checkpoint
            .L__after_checkpoint{SYMBOL_SUFFIX}:
            """

        return patch
