import re
from dataclasses import dataclass
from typing import Any, List, Optional, Set

import gtirb
import llvmlite.binding as llvm
from capstone import CsInsn
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from teapot.liveness import LiveRegisterManager
from gtirb_rewriting import Patch
from gtirb_rewriting.assembly import Register

from teapot.arch.architecture import Architecture
from teapot.configs.runtime import (
    DIFT_REG_TAGS_ALIGNMENT,
    DIFT_REG_TAGS_SIZE,
    SCRATCHPAD_ALIGNMENT,
    SCRATCHPAD_SIZE,
)
from teapot.configs.slots import ScratchpadSlots
from teapot.passes.common.dift.base import DiftPassBase


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


class TextDiftLLVMBase(DiftPassBase):
    DIFT_REG_TAGS_TYPE = f"[{DIFT_REG_TAGS_SIZE} x i8]"
    SCRATCHPAD_ARR_TYPE = f"[{SCRATCHPAD_SIZE // 8} x i64]"
    TAG_TYPE = "i8"
    SCRATCHPAD_ELEM_TYPE = "i64"
    TARGET_TRIPLE = None
    TARGET_FEATURES = ""
    ASM_RETURN_BRANCH = None
    ALLOCATE_INST_PATCH_REGISTERS = False
    ALLOCATE_BLOCK_PATCH_REGISTERS = False
    REPLAY_SYMBOLS = frozenset({"dift_reg_tags", "scratchpad"})

    def __init__(self, reg_manager: LiveRegisterManager, section: gtirb.Section, decoder: GtirbInstructionDecoder,
                 arch: Architecture, *, dift_layout, insert_memlog: bool = False):
        super().__init__(
            reg_manager, section, decoder, arch,
            dift_layout=dift_layout, insert_memlog=insert_memlog)
        if self.TARGET_TRIPLE is not None:
            self._init_llvm_target(self.TARGET_TRIPLE)

    def _init_llvm_native(self):
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        self.target_triple = None
        self.target_machine = llvm.Target.from_default_triple().create_target_machine(
            "", self.TARGET_FEATURES, 3, "static"
        )
        self._init_llvm_pass_manager()

    def _init_llvm_target(self, target_triple: str):
        llvm.initialize_all_targets()
        llvm.initialize_all_asmprinters()
        self.target_triple = target_triple
        self.target_machine = llvm.Target.from_triple(target_triple).create_target_machine(
            features=self.TARGET_FEATURES, opt=3, codemodel="small"
        )
        self._init_llvm_pass_manager()

    def _init_llvm_pass_manager(self):
        self.pipeline_options = llvm.create_pipeline_tuning_options(speed_level=3)

    def _format_llvm_ir(self, body: str, *, target_triple=None) -> str:
        target = f'target triple = "{target_triple}"\n\n' if target_triple else ""
        return f"""
{target}@dift_reg_tags = dso_local local_unnamed_addr global {self.DIFT_REG_TAGS_TYPE} zeroinitializer, align {DIFT_REG_TAGS_ALIGNMENT}
@scratchpad = dso_local local_unnamed_addr global {self.SCRATCHPAD_ARR_TYPE} zeroinitializer, align {SCRATCHPAD_ALIGNMENT}

define dso_local void @func() local_unnamed_addr #0 {{
{body}

ret void
}}

attributes #0 = {{ "no-builtins" }}

!0 = !{{!1}}
!1 = distinct !{{!1, !3, !"teapot.dift.shadow"}}
!2 = !{{!4}}
!4 = distinct !{{!4, !3, !"teapot.runtime"}}
!3 = distinct !{{!3, !"teapot.dift.alias"}}
        """

    def _parse_and_optimize_llvm(self, ir: str):
        ir_parsed = llvm.parse_assembly(ir)
        # Give optimization the same layout as cross-target code generation.
        ir_parsed.data_layout = str(self.target_machine.target_data)
        ir_parsed.verify()
        # llvmlite installs per-run instrumentation callbacks on the builder.
        # Reusing it for independent modules retains callbacks to dead analysis
        # managers (and crashes on the next batch). Keep both objects per batch.
        with llvm.create_pass_builder(self.target_machine, self.pipeline_options) as builder:
            with builder.getModulePassManager() as manager:
                manager.run(ir_parsed, builder)
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
        return f"getelementptr inbounds ({ptr_type}, ptr @{ptr}, i64 0, i64 {offset})"

    def _alloca(self, type):
        return self._build_inst(f"alloca {type}")

    @staticmethod
    def _alias_metadata(dift_mem: bool = False) -> str:
        if dift_mem:
            return ", !alias.scope !0, !noalias !2"
        return ", !alias.scope !2, !noalias !0"

    def _load(self, type, v, *, dift_mem: bool = False, volatile=False, align=None):
        alignment = f", align {align}" if align is not None else ""
        return self._build_inst(
            f"load {'volatile ' if volatile else ''}{type}, ptr {v}{alignment}{self._alias_metadata(dift_mem)}")

    def _inttoptr(self, type, v):
        return self._build_inst(f"inttoptr {type} {v} to ptr")

    def _icmp(self, opt, type, v1, v2):
        return self._build_inst(f"icmp {opt} {type} {v1}, {v2}")

    def _or(self, type, v1, v2):
        return self._build_inst(f"or {type} {v1}, {v2}")

    def _xor(self, type, v1, v2):
        return self._build_inst(f"xor {type} {v1}, {v2}")

    def _add(self, type, v1, v2):
        return self._build_inst(f"add {type} {v1}, {v2}")

    def _store(self, type, v, ptr, *, dift_mem: bool = False, volatile=False, align=None):
        alignment = f", align {align}" if align is not None else ""
        self.llvm_ir.append(
            f"store {'volatile ' if volatile else ''}{type} {v}, ptr {ptr}{alignment}{self._alias_metadata(dift_mem)}")

    def _br(self, l):
        self.llvm_ir.append(f"br label {l}")

    def _br_cond(self, cond_v, l1, l2):
        self.llvm_ir.append(f"br i1 {cond_v}, label {l1}, label {l2}")

    def _label(self, l):
        self.llvm_ir.append(f"{l}:")

    def _extract_function_asm(self, assembly: str) -> str:
        match = re.search(r"^func:[^\n]*\n(.*?)^\.Lfunc_end0:", assembly, re.S | re.M)
        if match is None:
            raise ValueError("Could not find LLVM generated func body")
        body = match[1].strip()
        lines = []
        for line in body.splitlines():
            # AArch64 '#' prefixes immediates; the other targets use it for
            # comments. Labels may carry LLVM basic-block comments too.
            stripped = line.split("//" if self.arch.name == "aarch64" else "#", 1)[0].strip()
            if not stripped:
                continue
            if stripped.endswith(":"):
                lines.append(stripped)
                continue
            if stripped.startswith("."):
                continue
            if stripped in ("ret", "retq"):
                # LLVM can put a return block before a cold tail and branch
                # back to it. Deleting that return creates a fallthrough (or
                # a loop). Inline it as a jump to the wrapper's restore path.
                assert self.ASM_RETURN_BRANCH is not None
                lines.append(f"{self.ASM_RETURN_BRANCH} .Lfunc_end0")
            else:
                lines.append(stripped)
        # Only the final return may become fallthrough to the patch epilogue.
        if lines and lines[-1] == f"{self.ASM_RETURN_BRANCH} .Lfunc_end0":
            lines.pop()
        lines.append(".Lfunc_end0:")
        self._validate_function_asm(lines)
        return "\n".join(lines)

    def _validate_function_asm(self, lines):
        """Replay patches are self-contained, except for explicit runtime globals.

        Calling an intercepted libc helper on protected tag storage is not
        valid instrumentation. Likewise, LLVM's out-of-function constant pools
        are discarded by extraction and must never become unresolved symbols.
        """
        symbols = {line[:-1] for line in lines if line.endswith(":")}
        symbols.update(self.REPLAY_SYMBOLS)
        if self.arch.name == "x64":
            registers = r"%[a-z][a-z0-9]*"
            modifiers = set()
        elif self.arch.name == "aarch64":
            registers = r"\b(?:[xwqdsbh]\d+|v\d+(?:\.[0-9]*[bhsdq])?|sp|wsp|xzr|wzr)\b"
            modifiers = {"lo12", "lsl", "lsr", "asr", "ror", "uxtb", "uxth", "uxtw", "uxtx",
                         "sxtb", "sxth", "sxtw", "sxtx", "eq", "ne", "cs", "hs", "cc", "lo",
                         "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"}
        else:
            registers = r"\b(?:zero|ra|sp|gp|tp|[ast]\d+|[xf]\d+|f[ast]\d+)\b"
            modifiers = {"hi", "lo", "pcrel_hi", "pcrel_lo", "rne", "rtz", "rdn", "rup", "rmm", "dyn"}
        for line in lines:
            if line.endswith(":"):
                continue
            parts = line.split(None, 1)
            mnemonic = parts[0]
            if mnemonic in {"call", "callq", "lcall", "bl", "blr", "tail", "jal", "jalr", "c.jal", "c.jalr"}:
                raise ValueError(f"LLVM DIFT replay contains a call: {line}")
            if len(parts) == 1:
                continue
            operands = re.sub(registers, "", parts[1])
            operands = re.sub(r"(?<![\w.])(?:0x[0-9a-fA-F]+|\d+)(?![\w.])", "", operands)
            for token in re.findall(r"[A-Za-z_.$][A-Za-z0-9_.$]*", operands):
                # '$' by itself is x64's immediate marker, not a symbol.
                if token != "$" and token.lstrip("$") not in symbols | modifiers:
                    raise ValueError(f"LLVM DIFT replay references an outside symbol {token}: {line}")

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        self._reset()

        super().visit_code_block(block, function)

        instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
        index = self._block_flush_index(instructions)
        self._flush_dift(block, function, index, sum(i.size for i in instructions[:index]))

    def _block_flush_index(self, instructions):
        return len(instructions) - 1

    def _flush_dift(self, block, function, inst_idx, inst_offset):
        """Commit a batch before an instruction that observes or changes tags."""
        if len(self.llvm_ir) == 0:
            return

        ir_parsed = self._parse_and_optimize_llvm(
            self._format_llvm_ir("\n".join(self.llvm_ir), target_triple=self.target_triple))

        asm = self._extract_function_asm(self.target_machine.emit_assembly(ir_parsed))
        regs_usage = self._get_register_usage(asm)

        scratch_plan = self._scratch_plan(function, block, inst_idx)
        patch = self._build_optimized_dift_values_patch(
            asm, regs_usage, scratch_plan=scratch_plan)
        if self.ALLOCATE_BLOCK_PATCH_REGISTERS:
            patch = self.allocate_registers(function, block, inst_idx)(patch)
        self.insert_at(block, inst_offset, Patch.from_function(patch))
        self._reset()

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
            patch = self.allocate_registers(function, block, inst_idx)(patch)
        self.insert_at(block, inst_offset, Patch.from_function(patch))

    def _instruction_effects(self, block: gtirb.CodeBlock, inst: CsInsn):
        regs_read = self.arch.access_registers(self.reg_manager.abi, inst, 0)
        regs_write = self.arch.access_registers(self.reg_manager.abi, inst, 1)
        regs_read = self._filter_ignored_registers(regs_read)
        regs_write = self._filter_ignored_registers(regs_write)
        mem_operand = self.arch.memory_operand(inst)
        if mem_operand is not None:
            regs_read.update(self._filter_ignored_registers(
                self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand)))
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
        return self._plan_scratch_registers(2, self._insertion_live_registers(function, block, inst_idx))

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
        read_elements = self._memory_elements(inst, regs_write, mem_read)
        write_elements = self._memory_elements(inst, regs_read, mem_write)

        if read_elements or write_elements:
            mem_operand = mem_read if read_elements else mem_write
            if not clear_dest_tags:
                self._or_register_tags_into_tag(tag, self._filter_ignored_registers(
                    self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand)))
            # Snapshot before any destination tag can overwrite an address tag.
            address_tag = self._load(self.TAG_TYPE, tag)
            mem_addr = self._load_scratchpad_addr(capture_operands, block, inst, inst_offset, mem_operand)
            for element in read_elements or write_elements:
                self._store(self.TAG_TYPE, address_tag, tag)
                if read_elements:
                    if element.register is None:
                        continue
                    if not clear_dest_tags:
                        self._or_shadow_mem_tag_into_tag(
                            tag, mem_addr, offset=element.offset, size=element.read_tag_size)
                    self._store(self.TAG_TYPE, self._load(self.TAG_TYPE, tag), self._build_gep(
                        self.TAG_TYPE, "dift_reg_tags", self.arch.dift_register_id(element.register),
                        ptr_type=self.DIFT_REG_TAGS_TYPE))
                else:
                    if not clear_dest_tags and element.register is not None:
                        self._or_register_tags_into_tag(tag, (element.register,))
                    self._store_shadow_mem_tags(
                        self._load(self.TAG_TYPE, tag), mem_addr, element.offset, element.size)

            loaded_registers = {element.register for element in read_elements}
            for reg in self._ordered_registers(regs_write - loaded_registers):
                self._store(self.TAG_TYPE, address_tag, self._build_gep(
                    self.TAG_TYPE, "dift_reg_tags", self.arch.dift_register_id(reg),
                    ptr_type=self.DIFT_REG_TAGS_TYPE))
        else:
            if not clear_dest_tags:
                self._or_register_tags_into_tag(tag, regs_read)

                if mem_read is not None:
                    mem_read_addr = self._load_scratchpad_addr(capture_operands, block, inst, inst_offset, mem_read)
                    self._or_shadow_mem_tag_into_tag(tag, mem_read_addr)

            loaded_tag = self._load(self.TAG_TYPE, tag)

            for reg in self._ordered_registers(regs_write):
                self._store(self.TAG_TYPE, loaded_tag, self._build_gep(
                    self.TAG_TYPE, "dift_reg_tags", self.arch.dift_register_id(reg),
                    ptr_type=self.DIFT_REG_TAGS_TYPE))

            if mem_write is not None:
                mem_addr = mem_read_addr
                if mem_addr is None or mem_read is None or mem_write != mem_read:
                    mem_addr = self._load_scratchpad_addr(capture_operands, block, inst, inst_offset, mem_write)
                self._store_shadow_mem_tags(loaded_tag, mem_addr, 0, mem_write_size)

        self._after_instruction_effects(mem_read)

        if conditional:
            self._br(f"%dift_skip_{label_id}")
            self._label(f"dift_skip_{label_id}")

        return self._build_store_values_patch(
            inst, capture_operands, scratch_plan=scratch_plan,
            conditional=conditional, conditional_slot=label_id)

    def _after_instruction_effects(self, mem_read):
        """Transient replays apply queued load tags inside the same condition."""

    def _load_scratchpad_addr(self, capture_operands, block, inst, inst_offset, mem_operand):
        scratchpad_idx = self.scratchpad_offset
        mem_symexpr = self.arch.mem_operand_address_expression(block, inst, mem_operand, inst_offset)
        capture_operands.append((scratchpad_idx, mem_operand, mem_symexpr))
        mem_addr = self._load(self.SCRATCHPAD_ELEM_TYPE, self._build_gep(
            self.SCRATCHPAD_ELEM_TYPE, "scratchpad", scratchpad_idx, ptr_type=self.SCRATCHPAD_ARR_TYPE))
        self.scratchpad_offset += 1
        return mem_addr

    def _or_register_tags_into_tag(self, tag, registers):
        for reg in self._ordered_registers(registers):
            self._store(self.TAG_TYPE, self._or(
                self.TAG_TYPE, self._load(self.TAG_TYPE, tag),
                self._load(self.TAG_TYPE, self._build_gep(
                    self.TAG_TYPE, "dift_reg_tags", self.arch.dift_register_id(reg),
                    ptr_type=self.DIFT_REG_TAGS_TYPE))), tag)

    def _or_shadow_mem_tag_into_tag(self, tag, mem_addr, *, offset=0, size=1):
        for idx in range(offset, offset + size):
            byte_addr = mem_addr if idx == 0 else self._add(self.SCRATCHPAD_ELEM_TYPE, mem_addr, idx)
            memtag_addr = self._inttoptr(self.SCRATCHPAD_ELEM_TYPE, self._xor(
                self.SCRATCHPAD_ELEM_TYPE, byte_addr, self.dift_layout.xor_mask
            ))
            self._store(self.TAG_TYPE, self._or(self.TAG_TYPE, self._load(self.TAG_TYPE, tag),
                                              self._load(self.TAG_TYPE, memtag_addr, dift_mem=True)), tag)

    def _store_shadow_mem_tags(self, tag, mem_addr, offset, size):
        for idx in range(offset, offset + size):
            byte_addr = mem_addr if idx == 0 else self._add(self.SCRATCHPAD_ELEM_TYPE, mem_addr, idx)
            memtag_addr = self._inttoptr(self.SCRATCHPAD_ELEM_TYPE, self._xor(
                self.SCRATCHPAD_ELEM_TYPE, byte_addr, self.dift_layout.xor_mask
            ))
            self._store(self.TAG_TYPE, tag, memtag_addr, dift_mem=True)

    def _build_store_values_patch(self, inst: CsInsn, capture_operands, scratch_plan=None,
                                  conditional: Optional[str] = None, conditional_slot: Optional[int] = None):
        raise NotImplementedError(type(self).__name__)

    def _get_register_usage(self, asm: str):
        raise NotImplementedError(type(self).__name__)

    def _build_optimized_dift_values_patch(self, assembly: str, registers, *, scratch_plan=None):
        raise NotImplementedError(type(self).__name__)
