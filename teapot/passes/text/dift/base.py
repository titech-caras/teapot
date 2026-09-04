import functools
import re
from dataclasses import dataclass
from typing import Any, List, Optional, Set

import gtirb
import llvmlite.binding as llvm
from capstone_gt import CsInsn
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Patch
from gtirb_rewriting.assembly import Register

from teapot.arch.architecture import Architecture
from teapot.configs.runtime import SCRATCHPAD_SIZE
from teapot.configs.slots import ScratchpadSlots
from teapot.passes.common.dift.base import DiftPropagationBase


TEXT_DIFT_CAPTURE_SCRATCH_SAVE_OFFSET = ScratchpadSlots.TEXT_DIFT_CAPTURE_SCRATCH_SAVE
TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET = ScratchpadSlots.TEXT_DIFT_LLVM_SCRATCH_SAVE
TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT = ScratchpadSlots.TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT
TEXT_DIFT_LLVM_STACK_OFFSET = ScratchpadSlots.TEXT_DIFT_LLVM_STACK
TEXT_DIFT_LLVM_STACK_SIZE = ScratchpadSlots.TEXT_DIFT_LLVM_STACK_SIZE
TEXT_DIFT_LLVM_STACK_SP_OFFSET = ScratchpadSlots.TEXT_DIFT_LLVM_STACK_SP


@dataclass(frozen=True)
class TextDiftInstructionEffects:
    regs_read: Set[Register]
    regs_write: Set[Register]
    clear_dest_tags: bool
    mem_read: Any = None
    mem_write: Any = None
    mem_write_size: int = 0
    conditional: Optional[str] = None


class TextDiftLLVMBase(DiftPropagationBase):
    DIFT_REG_TAGS_TYPE = "[48 x i8]"
    SCRATCHPAD_ARR_TYPE = f"[{SCRATCHPAD_SIZE // 8} x i64]"
    TAG_TYPE = "i8"
    SCRATCHPAD_ELEM_TYPE = "i64"
    TARGET_TRIPLE = None
    NATIVE_TARGET_FEATURES = ""
    ALLOCATE_INST_PATCH_REGISTERS = False
    ALLOCATE_BLOCK_PATCH_REGISTERS = False

    def __init__(self, reg_manager: LiveRegisterManager, section: gtirb.Section, decoder: GtirbInstructionDecoder,
                 arch: Architecture, *, dift_layout=None, insert_memlog: bool = False):
        super().__init__(
            reg_manager, section, decoder, arch,
            dift_layout=dift_layout, insert_memlog=insert_memlog)
        if self.TARGET_TRIPLE is not None:
            self._init_llvm_target(self.TARGET_TRIPLE)

    def _init_llvm_native(self):
        llvm.initialize()
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        self._init_llvm_pass_manager()
        self.target_triple = None
        self.target_machine = llvm.Target.from_default_triple().create_target_machine(
            "", self.NATIVE_TARGET_FEATURES, 3, "static"
        )

    def _init_llvm_target(self, target_triple: str):
        llvm.initialize()
        llvm.initialize_all_targets()
        llvm.initialize_all_asmprinters()
        self._init_llvm_pass_manager()
        self.target_triple = target_triple
        self.target_machine = llvm.Target.from_triple(target_triple).create_target_machine(
            opt=3, codemodel="small"
        )

    def _init_llvm_pass_manager(self):
        pmb = llvm.create_pass_manager_builder()
        pmb.opt_level = 3
        self.pm = llvm.create_module_pass_manager()
        pmb.populate(self.pm)

    def _shutdown_llvm(self):
        llvm.shutdown()

    def _llvm_ir_template(self, *, target_triple=None, declare_memset: bool = False) -> str:
        target = f'target triple = "{target_triple}"\n\n' if target_triple else ""
        memset = ""
        if declare_memset:
            memset = """
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #2
attributes #2 = { argmemonly nofree nounwind willreturn writeonly }
"""
        return f"""
{target}@dift_reg_tags = dso_local local_unnamed_addr global {self.DIFT_REG_TAGS_TYPE} zeroinitializer, align 16
@scratchpad = dso_local local_unnamed_addr global {self.SCRATCHPAD_ARR_TYPE} zeroinitializer, align 16

define dso_local void @func() local_unnamed_addr #0 {{
__TEAPOT_LLVM_BODY__

ret void
}}
{memset}
!0 = !{{!1}}
!1 = distinct !{{!1, !3, !"teapot.dift.shadow"}}
!2 = !{{!4}}
!4 = distinct !{{!4, !3, !"teapot.runtime"}}
!3 = distinct !{{!3, !"teapot.dift.alias"}}
        """

    def _format_llvm_ir(self, body: str, *, target_triple=None, declare_memset: bool = False) -> str:
        return self._llvm_ir_template(
            target_triple=target_triple,
            declare_memset=declare_memset,
        ).replace("__TEAPOT_LLVM_BODY__", body)

    def _parse_and_optimize_llvm(self, ir: str):
        ir_parsed = llvm.parse_assembly(ir)
        self.pm.run(ir_parsed)
        return ir_parsed

    def _reset(self):
        self.scratchpad_offset = 0
        self.tempval_cnt = 0
        self.llvm_ir = []

    def _get_tempval(self):
        self.tempval_cnt += 1
        return f"%{self.tempval_cnt}"

    def _build_inst(self, inst):
        tempval = self._get_tempval()
        self.llvm_ir.append(f"{tempval} = {inst}")
        return tempval

    def _build_gep(self, type, ptr, offset, *, ptr_type=None):
        if ptr_type is None:
            ptr_type = type
        return f"getelementptr inbounds ({ptr_type}, {ptr_type}* @{ptr}, i64 0, i64 {offset})"

    def _alloca(self, type):
        return self._build_inst(f"alloca {type}")

    @staticmethod
    def _alias_metadata(dift_mem: bool = False) -> str:
        if dift_mem:
            return ", !alias.scope !0, !noalias !2"
        return ", !alias.scope !2, !noalias !0"

    def _load(self, type, v, *, dift_mem: bool = False):
        return self._build_inst(f"load {type}, {type}* {v}{self._alias_metadata(dift_mem)}")

    def _inttoptr(self, type, v, ptr_type):
        return self._build_inst(f"inttoptr {type} {v} to {ptr_type}*")

    def _icmp(self, opt, type, v1, v2):
        return self._build_inst(f"icmp {opt} {type} {v1}, {v2}")

    def _or(self, type, v1, v2):
        return self._build_inst(f"or {type} {v1}, {v2}")

    def _xor(self, type, v1, v2):
        return self._build_inst(f"xor {type} {v1}, {v2}")

    def _add(self, type, v1, v2):
        return self._build_inst(f"add {type} {v1}, {v2}")

    def _mul(self, type, v1, v2):
        return self._build_inst(f"mul {type} {v1}, {v2}")

    def _store(self, type, v, ptr, *, dift_mem: bool = False):
        self.llvm_ir.append(f"store {type} {v}, {type}* {ptr}{self._alias_metadata(dift_mem)}")

    def _br(self, l):
        self.llvm_ir.append(f"br label {l}")

    def _br_cond(self, cond_v, l1, l2):
        self.llvm_ir.append(f"br i1 {cond_v}, label {l1}, label {l2}")

    def _label(self, l):
        self.llvm_ir.append(f"{l}:")

    def _memset(self, type, ptr, val, len, *, dift_mem: bool = False):
        self.llvm_ir.append(
            f"call void @llvm.memset.p0i8.i64({type}* {ptr}, {type} {val}, i64 {len}, i1 false)"
            f"{self._alias_metadata(dift_mem)}")

    def _extract_function_asm(self, assembly: str) -> str:
        match = re.search(r"func:(.+)\.Lfunc_end0:", assembly, re.S)
        if match is None:
            raise ValueError("Could not find LLVM generated func body")
        body = match[1].strip()
        lines = []
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.endswith(":"):
                lines.append(line)
                continue
            if stripped.startswith("."):
                continue
            if stripped in ("ret", "retq"):
                continue
            lines.append(line)
        return "\n".join(lines)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        self._reset()

        super().visit_code_block(block, function)

        if len(self.llvm_ir) == 0:
            return

        ir_parsed = self._parse_and_optimize_llvm(
            self._format_llvm_ir("\n".join(self.llvm_ir), target_triple=self.target_triple))

        asm = self._extract_function_asm(self.target_machine.emit_assembly(ir_parsed))
        regs_usage = self._get_register_usage(asm)

        instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
        last_inst_offset = functools.reduce(lambda x, i: x + i.size, instructions[:-1], 0)

        inst_idx = len(instructions) - 1
        scratch_plan = self._scratch_plan(function, block, inst_idx)
        patch = self._build_optimized_dift_values_patch(
            asm, regs_usage, scratch_plan=scratch_plan)
        if self.ALLOCATE_BLOCK_PATCH_REGISTERS:
            patch = self.reg_manager.allocate_registers(function, block, inst_idx)(patch)
        self.insert_at(block, last_inst_offset, Patch.from_function(patch))

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if self.arch.dift_should_skip_instruction(inst):
            return
        if self.arch.is_instrumentation_helper_instruction(
                inst, inst_idx, getattr(self, "_current_instructions", None)):
            return

        effects = self._instruction_effects(block, inst)
        if effects is None:
            return

        regs_read = effects.regs_read
        regs_write = effects.regs_write
        mem_read = effects.mem_read
        mem_write = effects.mem_write
        mem_write_size = effects.mem_write_size
        clear_dest_tags = effects.clear_dest_tags
        conditional = effects.conditional

        if self._should_skip_effects(effects):
            return

        self.reg_manager.add_live_registers(function, block, inst_idx, regs_read.union(regs_write))

        capture_count = 1 if conditional else 0
        if mem_read is not None:
            capture_count += 1
        if mem_write is not None and mem_write != mem_read:
            capture_count += 1
        scratch_plan = None
        if capture_count:
            scratch_plan = self._scratch_plan(function, block, inst_idx)

        patch = self._build_dift_patch(block, inst, inst_offset, regs_read, regs_write,
                                       clear_dest_tags=clear_dest_tags,
                                       mem_read=mem_read, mem_write=mem_write,
                                       mem_write_size=mem_write_size,
                                       conditional=conditional,
                                       scratch_plan=scratch_plan)
        if self.ALLOCATE_INST_PATCH_REGISTERS:
            patch = self.reg_manager.allocate_registers(function, block, inst_idx)(patch)
        self.insert_at(block, inst_offset, Patch.from_function(patch))

    def _instruction_effects(self, block: gtirb.CodeBlock, inst: CsInsn):
        regs_read = self.arch.access_registers(self.reg_manager.abi, inst, 0)
        regs_write = self.arch.access_registers(self.reg_manager.abi, inst, 1)
        regs_read = self._filter_ignored_registers(regs_read)
        regs_write = self._filter_ignored_registers(regs_write)
        mem_operand = self.arch.memory_operand(inst)
        if mem_operand is not None:
            regs_read.update(self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand))
        mem_read = mem_operand if mem_operand is not None and self.arch.mem_operand_is_read(
            inst, mem_operand) else None
        mem_write = mem_operand if mem_operand is not None and self.arch.mem_operand_is_write(
            inst, mem_operand) else None
        mem_write_size = self.arch.mem_operand_size(inst, mem_write) if mem_write is not None else 0
        if mem_write is not None and mem_write_size == 0:
            mem_write = None

        clear_dest_tags = self.arch.dift_clears_destination_tags(inst)
        return TextDiftInstructionEffects(
            regs_read=regs_read,
            regs_write=regs_write,
            clear_dest_tags=clear_dest_tags,
            mem_read=mem_read,
            mem_write=mem_write,
            mem_write_size=mem_write_size)

    @staticmethod
    def _should_skip_effects(effects: TextDiftInstructionEffects) -> bool:
        if not effects.regs_write and effects.mem_write is None:
            return True
        return (
            not effects.clear_dest_tags
            and effects.regs_read == effects.regs_write
            and effects.mem_read is None
            and effects.mem_write is None
        )

    def _scratch_plan(self, function: Function, block: gtirb.CodeBlock, inst_idx: int):
        return None

    def _build_dift_patch(self, block: gtirb.CodeBlock, inst: CsInsn, inst_offset: int,
                          regs_read: Set[Register], regs_write: Set[Register], *,
                          clear_dest_tags: bool, mem_read, mem_write, mem_write_size: int,
                          conditional: Optional[str] = None, scratch_plan=None):
        capture_operands = []
        label_id = self.scratchpad_offset
        if conditional:
            conditional_value = self._load(
                self.SCRATCHPAD_ELEM_TYPE,
                self._build_gep(
                    self.SCRATCHPAD_ELEM_TYPE,
                    "scratchpad",
                    self.scratchpad_offset,
                    ptr_type=self.SCRATCHPAD_ARR_TYPE))
            self.scratchpad_offset += 1
            cmp_result = self._icmp("eq", self.SCRATCHPAD_ELEM_TYPE, conditional_value, "0")
            self._br_cond(cmp_result, f"%dift_skip_{label_id}", f"%dift_proceed_{label_id}")
            self._label(f"dift_proceed_{label_id}")

        tag = self._alloca(self.TAG_TYPE)
        self._store(self.TAG_TYPE, "0", tag)
        mem_read_addr = None

        if not clear_dest_tags:
            for reg in regs_read:
                self._store(self.TAG_TYPE, self._or(
                    self.TAG_TYPE,
                    self._load(self.TAG_TYPE, tag),
                    self._load(self.TAG_TYPE, self._build_gep(
                        self.TAG_TYPE, "dift_reg_tags", self.arch.dift_register_id(reg),
                        ptr_type=self.DIFT_REG_TAGS_TYPE))),
                    tag)

            if mem_read is not None:
                mem_read_addr = self._load_scratchpad_addr(capture_operands, block, inst, inst_offset, mem_read)
                self._or_shadow_mem_tag_into_tag(tag, mem_read_addr)

        loaded_tag = self._load(self.TAG_TYPE, tag)

        for reg in regs_write:
            self._store(self.TAG_TYPE, loaded_tag, self._build_gep(
                self.TAG_TYPE, "dift_reg_tags", self.arch.dift_register_id(reg),
                ptr_type=self.DIFT_REG_TAGS_TYPE))

        if mem_write is not None:
            mem_addr = mem_read_addr
            if mem_addr is None or mem_read is None or mem_write != mem_read:
                mem_addr = self._load_scratchpad_addr(capture_operands, block, inst, inst_offset, mem_write)
            for idx in range(mem_write_size):
                byte_addr = mem_addr if idx == 0 else self._add(self.SCRATCHPAD_ELEM_TYPE, mem_addr, idx)
                memtag_addr = self._inttoptr(self.SCRATCHPAD_ELEM_TYPE, self._xor(
                    self.SCRATCHPAD_ELEM_TYPE, byte_addr, self.dift_layout.xor_mask
                ), self.TAG_TYPE)
                self._store(self.TAG_TYPE, loaded_tag, memtag_addr, dift_mem=True)

        if conditional:
            self._br(f"%dift_skip_{label_id}")
            self._label(f"dift_skip_{label_id}")

        return self._build_store_values_patch(
            inst, capture_operands, scratch_plan=scratch_plan,
            conditional=conditional, conditional_slot=label_id)

    def _load_scratchpad_addr(self, capture_operands, block, inst, inst_offset, mem_operand):
        scratchpad_idx = self.scratchpad_offset
        mem_symexpr = self.arch.operand_symbolic_expression(block, inst, mem_operand, inst_offset)
        capture_operands.append((scratchpad_idx, mem_operand, mem_symexpr))
        mem_addr = self._load(self.SCRATCHPAD_ELEM_TYPE, self._build_gep(
            self.SCRATCHPAD_ELEM_TYPE, "scratchpad", scratchpad_idx, ptr_type=self.SCRATCHPAD_ARR_TYPE))
        self.scratchpad_offset += 1
        return mem_addr

    def _or_shadow_mem_tag_into_tag(self, tag, mem_addr):
        memtag_addr = self._inttoptr(self.SCRATCHPAD_ELEM_TYPE, self._xor(
            self.SCRATCHPAD_ELEM_TYPE, mem_addr, self.dift_layout.xor_mask
        ), self.TAG_TYPE)
        self._store(self.TAG_TYPE, self._or(self.TAG_TYPE, self._load(self.TAG_TYPE, tag),
                                            self._load(self.TAG_TYPE, memtag_addr, dift_mem=True)), tag)

    def _build_store_values_patch(self, inst: CsInsn, capture_operands, scratch_plan=None,
                                  conditional: Optional[str] = None, conditional_slot: Optional[int] = None):
        raise NotImplementedError(type(self).__name__)

    def _get_register_usage(self, asm: str):
        raise NotImplementedError(type(self).__name__)

    def _build_optimized_dift_values_patch(self, assembly: str, registers, *, scratch_plan=None):
        raise NotImplementedError(type(self).__name__)
