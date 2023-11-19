import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints, InsertionContext)
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from gtirb_live_register_analysis import LiveRegisterManager
from capstone_gt import CsInsn, CS_OP_MEM, CS_OP_REG, CS_OP_IMM, CS_AC_READ, CS_AC_WRITE
from capstone_gt.x86 import X86_REG_EFLAGS
from typing import List, Set, Optional
import llvmlite.binding as llvm
import re
import functools

from NaHCO3.config import BLACKLIST_FUNCTION_NAMES, SYMBOL_SUFFIX, SCRATCHPAD_SIZE
from NaHCO3.patch_helpers import dift_add_reg_tag_snippet
from NaHCO3.utils.dift import reg_to_dift_reg_id
from NaHCO3.utils.rewriting import mem_access_to_symbolic_str

from NaHCO3.passes import DiftPropagationPass


class DiftPropagationLLVMPass(DiftPropagationPass):
    DIFT_REG_TAGS_TYPE = "[48 x i8]"
    SCRATCHPAD_ARR_TYPE = f"[{SCRATCHPAD_SIZE // 8} x i64]"
    TAG_TYPE = "i8"
    SCRATCHPAD_ELEM_TYPE = "i64"

    LLVM_IR_TEMPLATE = f"""
@dift_reg_tags = dso_local local_unnamed_addr global {DIFT_REG_TAGS_TYPE} zeroinitializer, align 16
@scratchpad = dso_local local_unnamed_addr global {SCRATCHPAD_ARR_TYPE} zeroinitializer, align 16

define dso_local void @func() local_unnamed_addr #0 {{{{
{{0}}

ret void
}}}}

declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #2
attributes #2 = {{{{ argmemonly nofree nounwind willreturn writeonly }}}}
    """

    scratchpad_offset: int = 0
    tempval_cnt: int = 0
    llvm_ir: List

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        assert (not self.insert_memlog)

        llvm.initialize()
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()

        pmb = llvm.create_pass_manager_builder()
        pmb.opt_level = 3
        self.pm = llvm.create_module_pass_manager()
        pmb.populate(self.pm)

        self.target_machine = llvm.Target.from_default_triple().create_target_machine(
            '', '', 3, 'static'
        )

    def __del__(self):
        llvm.shutdown()

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        self.__reset()

        super().visit_code_block(block, function)

        if len(self.llvm_ir) > 0:
            ir = self.LLVM_IR_TEMPLATE.format("\n".join(self.llvm_ir))
            #print(ir)

            ir_parsed = llvm.parse_assembly(ir)
            self.pm.run(ir_parsed)
            #print(ir_parsed)

            asm = re.search(r"func:(.+?)retq", self.target_machine.emit_assembly(ir_parsed), re.S)[1].strip()
            if "memset" in asm:
                raise NotImplementedError("LLVM DIFT generates memset")
            regs_usage = self.__get_register_usage(asm)
            #print(asm)

            instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
            last_inst_offset = functools.reduce(lambda x, i: x + i.size, instructions[:-1], 0)

            self.rewriting_ctx.insert_at(block, last_inst_offset, Patch.from_function(
                self.reg_manager.allocate_registers(function, block, len(instructions) - 1)(
                    self.__build_llvm_optimized_dift_values_patch(asm, regs_usage)
                )
            ))

    '''def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if inst.mnemonic.startswith("rep stos"):
            access_size = inst.operands[0].size
            self.rewriting_ctx.insert_at(
                block, inst_offset, self.reg_manager.allocate_registers(function, block, inst_idx)(
                    self.__build_dift_store_values_patch(
                        None, "[rcx]", "[rdi]")))  # FIXME: this is so hacky!

            rax_tag = self.__load(self.TAG_TYPE, self.__build_gep(
                self.TAG_TYPE, "dift_reg_tags", 0, ptr_type=self.DIFT_REG_TAGS_TYPE))
            rcx_val = self.__load(self.SCRATCHPAD_ELEM_TYPE, self.__build_gep(
                self.SCRATCHPAD_ELEM_TYPE, "scratchpad", 0, ptr_type=self.SCRATCHPAD_ARR_TYPE))
            memtag_addr = self.__inttoptr(
                self.SCRATCHPAD_ELEM_TYPE, self.__load(
                    self.SCRATCHPAD_ELEM_TYPE, self.__build_gep(
                        self.SCRATCHPAD_ELEM_TYPE, "scratchpad",
                        self.scratchpad_offset + 1, ptr_type=self.SCRATCHPAD_ARR_TYPE)), self.TAG_TYPE)

            memset_size = self.__mul(self.SCRATCHPAD_ELEM_TYPE, rcx_val, access_size)
            self.__memset(self.TAG_TYPE, memtag_addr, rax_tag, memset_size)

        else:
            super().visit_inst(inst, inst_idx, inst_offset, block, function, live_registers)'''

    def __get_register_usage(self, asm):
        regs = {self.rewriting_ctx._abi.get_register(r) for r in re.findall("%([0-9a-zA-Z]+)", asm) if r != "rip"}
        return regs

    def __reset(self):
        self.scratchpad_offset = 0
        self.tempval_cnt = 0
        self.llvm_ir = []

    def __get_tempval(self):
        self.tempval_cnt += 1
        return f"%{self.tempval_cnt}"

    def __build_inst(self, inst):
        tempval = self.__get_tempval()
        self.llvm_ir.append(f"{tempval} = {inst}")
        return tempval

    def __build_gep(self, type, ptr, offset, *, ptr_type=None):
        if ptr_type is None:
            ptr_type = type
        return f"getelementptr inbounds ({ptr_type}, {ptr_type}* @{ptr}, i64 0, i64 {offset})"

    def __alloca(self, type):
        return self.__build_inst(f"alloca {type}")

    def __load(self, type, v):
        return self.__build_inst(f"load {type}, {type}* {v}")

    def __inttoptr(self, type, v, ptr_type):
        return self.__build_inst(f"inttoptr {type} {v} to {ptr_type}*")

    def __icmp(self, opt, type, v1, v2):
        return self.__build_inst(f"icmp {opt} {type} {v1}, {v2}")

    def __or(self, type, v1, v2):
        return self.__build_inst(f"or {type} {v1}, {v2}")

    def __xor(self, type, v1, v2):
        return self.__build_inst(f"xor {type} {v1}, {v2}")

    def __mul(self, type, v1, v2):
        return self.__build_inst(f"mul {type} {v1}, {v2}")

    def __store(self, type, v, ptr):
        self.llvm_ir.append(f"store {type} {v}, {type}* {ptr}")

    def __br(self, l):
        self.llvm_ir.append(f"br label {l}")

    def __br_cond(self, cond_v, l1, l2):
        self.llvm_ir.append(f"br i1 {cond_v}, label {l1}, label {l2}")

    def __label(self, l):
        self.llvm_ir.append(f"{l}:")

    def __memset(self, type, ptr, val, len):
        self.llvm_ir.append(f"call void @llvm.memset.p0i8.i64({type}* {ptr}, {type} {val}, i64 {len}, i1 false)")

    def __ret(self):
        self.llvm_ir.append("ret void")

    def _build_dift_patch(self, regs_read: Set[Register], regs_write: Set[Register], *,
                          conditional: Optional[str] = None,
                          clear_dest_tags: bool = False,  # Ignore tag propagation and zero out the tags
                          mem_read_operand_str: Optional[str] = None,
                          mem_write_operand_str: Optional[str] = None,
                          mem_write_size: Optional[int] = None):
        # FIXME: inttoptr hinders with store-load optimizations

        if conditional:
            conditional_value = self.__load(
                self.SCRATCHPAD_ELEM_TYPE, self.__build_gep(
                    self.SCRATCHPAD_ELEM_TYPE, "scratchpad", self.scratchpad_offset, ptr_type=self.SCRATCHPAD_ARR_TYPE))

            cmp_result = self.__icmp("eq", self.SCRATCHPAD_ELEM_TYPE, conditional_value, "0")
            self.__br_cond(cmp_result, f"dift_skip_{self.scratchpad_offset}", f"dift_proceed_{self.scratchpad_offset}")
            self.__label(f"dift_proceed_{self.scratchpad_offset}:")

        tag = self.__alloca(self.TAG_TYPE)
        self.__store(self.TAG_TYPE, "0", tag)

        if not clear_dest_tags:
            for reg in regs_read:
                self.__store(self.TAG_TYPE, self.__or(
                    self.TAG_TYPE,
                    self.__load(self.TAG_TYPE, tag),
                    self.__load(self.TAG_TYPE, self.__build_gep(
                        self.TAG_TYPE, "dift_reg_tags", reg_to_dift_reg_id(reg), ptr_type=self.DIFT_REG_TAGS_TYPE))), tag)

            if mem_read_operand_str:
                memtag_addr = self.__inttoptr(
                    self.SCRATCHPAD_ELEM_TYPE, self.__load(
                        self.SCRATCHPAD_ELEM_TYPE, self.__build_gep(
                            self.SCRATCHPAD_ELEM_TYPE, "scratchpad",
                            self.scratchpad_offset + (1 if conditional else 0), ptr_type=self.SCRATCHPAD_ARR_TYPE)), self.TAG_TYPE)

                self.__store(self.TAG_TYPE, self.__or(
                    self.TAG_TYPE,
                    self.__load(self.TAG_TYPE, tag),
                    self.__load(self.TAG_TYPE, memtag_addr)), tag)

        loaded_tag = self.__load(self.TAG_TYPE, tag)

        for reg in regs_write:
            self.__store(self.TAG_TYPE, loaded_tag, self.__build_gep(
                self.TAG_TYPE, "dift_reg_tags", reg_to_dift_reg_id(reg), ptr_type=self.DIFT_REG_TAGS_TYPE))

        if mem_write_operand_str:
            offset = 1 if mem_write_operand_str == mem_read_operand_str else 0
            offset = offset + 1 if conditional else offset

            memtag_addr = self.__inttoptr(
                self.SCRATCHPAD_ELEM_TYPE, self.__load(
                    self.SCRATCHPAD_ELEM_TYPE, self.__build_gep(
                        self.SCRATCHPAD_ELEM_TYPE, "scratchpad",
                        self.scratchpad_offset + offset, ptr_type=self.SCRATCHPAD_ARR_TYPE)), self.TAG_TYPE)

            self.__memset(self.TAG_TYPE, memtag_addr, loaded_tag, mem_write_size)

        if conditional:
            self.__br(f"dift_skip_{self.scratchpad_offset}")
            self.__label(f"dift_skip_{self.scratchpad_offset}:")

        return self.__build_dift_store_values_patch(conditional, mem_read_operand_str, mem_write_operand_str)

    def __build_dift_store_values_patch(self, conditional: Optional[str] = None,
                                        mem_read_operand_str: Optional[str] = None,
                                        mem_write_operand_str: Optional[str] = None):
        scratch_registers = 1 if mem_read_operand_str or mem_write_operand_str or conditional else 0
        asm = ""

        def store_r1():
            s = f"mov scratchpad+{self.scratchpad_offset * 8}, {{0}}\n"
            self.scratchpad_offset += 1
            return s

        if conditional:
            asm += f"set{conditional} {{1}}"
            asm += store_r1()

        if mem_read_operand_str:
            asm += f"""
                lea {{0}}, {mem_read_operand_str}
                btc {{0}}, 45
            """
            asm += store_r1()

        if mem_write_operand_str and mem_write_operand_str != mem_read_operand_str:
            asm += f"""
                lea {{0}}, {mem_write_operand_str}
                btc {{0}}, 45
            """
            asm += store_r1()

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers)
        def patch(ctx: InsertionContext):
            if not (mem_read_operand_str or mem_write_operand_str or conditional):
                return ""

            r1: Register = ctx.scratch_registers[0]
            return asm.format(r1.name, r1.sizes['8l'])

        return patch

    def __build_llvm_optimized_dift_values_patch(self, assembly: str, registers: Set[Register]):
        @patch_constraints(scratch_registers=len(registers), clobbers_flags=True)
        def patch(ctx: InsertionContext):
            asm = assembly
            for reg_idx, register in enumerate(registers):
                for size, name in register.sizes.items():
                    asm = asm.replace(f"%{name}", f"%tmpr{reg_idx}:{size}")

            for reg_idx, register in enumerate(ctx.scratch_registers):
                for size, name in register.sizes.items():
                    asm = asm.replace(f"%tmpr{reg_idx}:{size}", f"%{name}")

            return asm

        return patch