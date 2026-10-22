import re
from dataclasses import replace

import llvmlite.binding as llvm
from capstone import CS_OP_REG, CsInsn
from gtirb_rewriting import InsertionContext

from teapot.configs.slots import (
    RISCV64_ORIGINAL_TP_OFFSET,
    SCRATCHPAD_FIRST_SPILL_OFFSET,
)
from teapot.passes.text.dift.base import (
    TextDiftLLVMBase,
    TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT,
    TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET,
    TEXT_DIFT_LLVM_STACK_SP_OFFSET,
)


class RISCV64TextDiftPropagationLLVMPass(TextDiftLLVMBase):
    EXPECTED_ARCH = "riscv64"
    ASM_RETURN_BRANCH = "j"
    TARGET_TRIPLE = "riscv64-unknown-linux-gnu"
    # Keep patch instructions four bytes wide: implicit compression breaks the
    # rewriter's padding alignment, independently of the input binary's ISA.
    TARGET_FEATURES = "+m,+a,+f,+d"
    # This is the inserted replay's ISA, not the original input's GNU-as ISA.
    # Production mcasm does not support the named Z extensions or CZERO.
    # Lower selects into base-I branches/integer operations instead.
    PURE_TARGET_FEATURES = "+m,+a,-c,-f,-d,-zfh,-zfhmin,-zfa,-v"
    PURE_ASM_ARCH = "rv64ima"
    LLVM_CALLER_SAVED_GPRS = (
        "ra",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    )

    @property
    def _pure_lp64(self):
        # Only the pipeline's explicit profile may select integer replay.
        # An absent profile retains the published LP64D code path verbatim.
        return getattr(self.arch, "riscv_profile", "lp64d") == "lp64-pure"

    def _init_llvm_target(self, target_triple: str):
        if not self._pure_lp64:
            return super()._init_llvm_target(target_triple)
        llvm.initialize_all_targets()
        llvm.initialize_all_asmprinters()
        self.target_triple = target_triple
        self.TARGET_FEATURES = self.PURE_TARGET_FEATURES
        self.target_machine = llvm.Target.from_triple(target_triple).create_target_machine(
            features=self.TARGET_FEATURES, opt=3, codemodel="small", abiname="lp64")
        self._init_llvm_pass_manager()

    def _validate_function_asm(self, lines):
        super()._validate_function_asm(lines)
        if not self._pure_lp64:
            return
        for line in lines:
            if not line or line.endswith(":"):
                continue
            mnemonic = line.split(None, 1)[0].lower()
            if ((mnemonic.startswith("f") and mnemonic not in {"fence", "fence.i"})
                    or mnemonic.startswith(("v", "csr"))
                    or re.search(r"\b(?:f[ast][0-9]+|f[0-9]+|fcsr|frm|fflags)\b", line)):
                raise ValueError(f"pure-LP64 LLVM DIFT replay contains FP/vector/control state: {line}")

    def _czero_operands(self, inst):
        if not self._pure_lp64 or inst.mnemonic not in {"czero.eqz", "czero.nez"}:
            return None
        if len(inst.operands) != 3 or any(op.type != CS_OP_REG for op in inst.operands):
            raise ValueError(f"Malformed RISC-V conditional-zero operands: {inst.op_str}")
        return tuple(self.reg_manager.abi.get_register(inst.reg_name(op.reg))
                     for op in inst.operands)

    def _instruction_effects(self, block, inst):
        effects = super()._instruction_effects(block, inst)
        operands = self._czero_operands(inst)
        if operands is not None:
            _, source, condition = operands
            # These results are constants regardless of the condition's value
            # or tag. Mark them before the generic no-change/alias skip rule.
            if (source.name == "zero"
                    or (condition.name == "zero" and inst.mnemonic == "czero.eqz")
                    or (inst.mnemonic == "czero.nez" and source == condition)):
                # NEZ rd,rs,rs is zero for either value of rs, including the
                # triple-alias case that otherwise hits the unchanged-tag skip.
                effects = replace(effects, clear_dest_tags=True)
        return effects

    def _or_instruction_register_tags_into_tag(self, tag, inst, registers,
                                                capture_operands, *, capture_metadata=True):
        operands = self._czero_operands(inst)
        if operands is None:
            return super()._or_instruction_register_tags_into_tag(
                tag, inst, registers, capture_operands,
                capture_metadata=capture_metadata)
        _, source, condition = operands
        if condition.name == "zero":
            # czero.nez with x0 as its condition is an unconditional copy.
            self._or_register_tags_into_tag(tag, self._filter_ignored_registers({source}))
            return

        slot = self.scratchpad_offset
        self.scratchpad_offset += 1
        # A None memory operand denotes a scalar register-value capture, not a
        # memory address. Snapshot original rs2, including when rd == rs2.
        if capture_metadata:
            capture_operands.append((slot, None, condition))
        condition_value = self._load(self.SCRATCHPAD_ELEM_TYPE, self._build_gep(
            self.SCRATCHPAD_ELEM_TYPE, "scratchpad", slot,
            ptr_type=self.SCRATCHPAD_ARR_TYPE))
        selected = self._icmp("ne" if inst.mnemonic == "czero.eqz" else "eq",
                              self.SCRATCHPAD_ELEM_TYPE, condition_value, "0")

        def register_tag(reg):
            if not self._filter_ignored_registers({reg}):
                return "0"
            return self._load(self.TAG_TYPE, self._build_gep(
                self.TAG_TYPE, "dift_reg_tags", self.arch.dift_register_id(reg),
                ptr_type=self.DIFT_REG_TAGS_TYPE))

        # The condition can influence either outcome. The value source cannot
        # influence the zero arm; do not promote its tag on that arm.
        source_tag, condition_tag = register_tag(source), register_tag(condition)
        selected_tag = self._build_inst(
            f"select i1 {selected}, {self.TAG_TYPE} {source_tag}, {self.TAG_TYPE} 0")
        self._store(self.TAG_TYPE, self._or(self.TAG_TYPE, condition_tag, selected_tag), tag)

    def _get_register_usage(self, asm: str):
        regs = {}
        for name in re.findall(
                r"\b(zero|ra|sp|gp|tp|t[0-6]|s(?:[0-9]|1[01])|a[0-7]|x(?:[0-9]|[12][0-9]|3[01]))\b",
                asm):
            normalized = self.reg_manager.abi.normalize_register_name(name)
            if normalized != "zero":
                regs[normalized] = self.reg_manager.abi.register_from_name(normalized)

        # Libcall clobbers are implicit and absent from the assembly scan.
        if re.search(r"(?m)^\s*call\s+", asm):
            for name in self.LLVM_CALLER_SAVED_GPRS:
                reg = self.reg_manager.abi.register_from_name(name)
                regs[reg.name] = reg
        return self.reg_manager.abi.sort_registers(regs.values())

    def _build_store_values_patch(self, inst: CsInsn, capture_operands, scratch_plan=None,
                                  conditional=None, conditional_slot=None):
        if not capture_operands:
            @self.arch.constraints()
            def empty_patch(ctx: InsertionContext):
                return ""

            return empty_patch

        if scratch_plan is None:
            scratch_plan = self._plan_scratch_registers(2)
        addr_reg, tmp_reg = scratch_plan.registers
        saved_reg_offsets = {
            reg.name: SCRATCHPAD_FIRST_SPILL_OFFSET + idx * 8
            for idx, reg in enumerate(scratch_plan.saved_regs)
        }

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            asm = self.arch.save_regs_to_first_spill(scratch_plan.saved_regs)
            for scratchpad_idx, mem_operand, mem_symexpr in capture_operands:
                if mem_operand is None:
                    # Capture a czero condition before LLVM replay and before
                    # the application can overwrite an aliased destination.
                    source = mem_symexpr
                    if source.name in saved_reg_offsets:
                        asm += self.arch.load_address(
                            addr_reg, f"scratchpad+{saved_reg_offsets[source.name]}")
                        asm += f"ld {addr_reg}, 0({addr_reg})\n"
                    elif source != addr_reg:
                        asm += f"mv {addr_reg}, {source}\n"
                    asm += self.arch.load_address(tmp_reg, f"scratchpad+{scratchpad_idx * 8}")
                    asm += f"sd {addr_reg}, 0({tmp_reg})\n"
                    continue
                asm += self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi,
                    inst,
                    addr_reg,
                    tmp_reg,
                    mem_operand,
                    ctx.stack_adjustment,
                    mem_symexpr=mem_symexpr,
                    saved_reg_offsets=saved_reg_offsets,
                )
                asm += self.arch.load_address(tmp_reg, f"scratchpad+{scratchpad_idx * 8}")
                asm += f"sd {addr_reg}, 0({tmp_reg})\n"
            asm += self.arch.restore_regs_from_first_spill(scratch_plan.saved_regs)
            return asm

        return patch

    def _build_optimized_dift_values_patch(self, assembly: str, registers, *, scratch_plan=None):
        if self._pure_lp64:
            # Also check direct wrapper callers, not just LLVM extraction. A
            # rejected FP/call body must never turn into an FP-saving wrapper.
            self._validate_function_asm([line.strip() for line in assembly.splitlines() if line.strip()])
        if scratch_plan is None:
            scratch_plan = self._plan_scratch_registers(2)
        has_call = bool(re.search(r'(?m)^\s*call\s+', assembly))
        uses_stack = has_call or any(reg.name == 'sp' for reg in registers)
        uses_tp = any(reg.name == 'tp' for reg in registers)
        float_regs = sorted(set(re.findall(
            r"\b(?:f[ts](?:[0-9]|1[01])|fa[0-7]|f(?:[0-9]|[12][0-9]|3[01]))\b",
            assembly)))
        if has_call:
            float_regs = [f'f{idx}' for idx in range(32)]
        # Extraction rejects calls. Only an actual stack operand or FP-control
        # save needs a wrapper temporary; leaf integer snippets need neither.
        controls = scratch_plan.registers[:1] if uses_stack or float_regs else ()
        saved_regs = []
        primary_scratch = scratch_plan.registers[0]
        for reg in (*controls, *registers):
            if (reg.name in {"zero", "sp", "tp"} or reg in saved_regs
                    or reg not in scratch_plan.live_registers):
                continue
            saved_regs.append(reg)
        stack_delta = TEXT_DIFT_LLVM_STACK_SP_OFFSET - TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET
        float_offset = len(saved_regs) * 8
        control_offset = float_offset + len(float_regs) * 8
        assert control_offset + 8 <= TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            # mcasm starts at RV64I. Match LLVM's features for this assembly
            # transaction, including preservation of generated FP operations.
            asm = (f'.attribute arch, "{self.PURE_ASM_ARCH}"\n' if self._pure_lp64
                   else '.attribute arch, "rv64imafd"\n')
            if not (saved_regs or float_regs or uses_stack or uses_tp):
                return asm + assembly.strip() + '\n'
            asm += self.arch.load_address("tp", f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            for idx, reg in enumerate(saved_regs):
                asm += f"sd {reg}, {idx * 8}(tp)\n"
            for idx, reg in enumerate(float_regs):
                asm += f"fsd {reg}, {float_offset + idx * 8}(tp)\n"
            if float_regs:
                asm += f"frcsr {primary_scratch}\nsd {primary_scratch}, {control_offset}(tp)\n"
            if uses_stack:
                asm += f"""
                li {primary_scratch}, {TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}
                add {primary_scratch}, tp, {primary_scratch}
                sd sp, 0({primary_scratch})
                li {primary_scratch}, {stack_delta}
                add sp, tp, {primary_scratch}
                """
            # Tag accesses can fault. Restore application TLS even if LLVM
            # never names TP: an application signal handler needs it too.
            asm += f"""
                {self.arch.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}")}
                ld tp, 0(tp)
            """
            asm += assembly.strip() + "\n"
            asm += self.arch.load_address("tp", f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            if uses_stack:
                asm += f"""
                li {primary_scratch}, {TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}
                add {primary_scratch}, tp, {primary_scratch}
                ld sp, 0({primary_scratch})
                """
            for idx, reg in enumerate(float_regs):
                asm += f"fld {reg}, {float_offset + idx * 8}(tp)\n"
            if float_regs:
                asm += f"ld {primary_scratch}, {control_offset}(tp)\nfscsr {primary_scratch}\n"
            for idx, reg in reversed(list(enumerate(saved_regs))):
                asm += f"ld {reg}, {idx * 8}(tp)\n"
            asm += f"""
                {self.arch.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}")}
                ld tp, 0(tp)
            """
            return asm

        return patch
