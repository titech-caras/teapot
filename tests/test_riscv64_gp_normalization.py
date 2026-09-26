import io
from contextlib import redirect_stdout
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import warnings
from unittest.mock import Mock

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import Assembler, PassManager

from teapot.arch import RISCV64Architecture
from teapot.passes.preprocessing.normalize_riscv64_gp_references_pass import (
    NormalizeRISCV64GPReferencesPass,
)
from teapot.preprocess.copy_section import copy_section
from test_live_register_preservation import make_module


class RISCV64GPNormalizationTests(unittest.TestCase):
    def make_reference(self, instruction, free=()):
        arch = RISCV64Architecture()
        ir, module, block, abi, registers = make_module(
            arch, gtirb.Module.ISA.ValidButUnsupported, bytes.fromhex("67800000"))
        assembler = Assembler(module)
        isa = '.attribute arch,"rv64ifd"\n' if instruction.startswith(("fld ", "fsd ")) else ""
        assembler.assemble(f"{isa}.option norvc\n{instruction}\nret")
        contents = assembler.finalize().text_section.data
        block.byte_interval.contents = contents
        block.byte_interval.size = block.size = len(contents)
        data = gtirb.Section(name=".data", module=module, flags={
            gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Readable,
            gtirb.Section.Flag.Writable, gtirb.Section.Flag.Initialized})
        target = gtirb.Symbol(name="target", module=module, payload=gtirb.DataBlock(
            size=8, byte_interval=gtirb.ByteInterval(address=0x2800, contents=b"\0" * 8, section=data)))
        gp = gtirb.Symbol(name="__global_pointer$", payload=0x2880, module=module)
        block.byte_interval.symbolic_expressions[0] = gtirb.SymAddrAddr(
            1, 0, target, gp, {gtirb.SymbolicExpression.Attribute.LO})
        decoder = CachedGtirbInstructionDecoder(module.isa)
        mask = sum(1 << index for index, reg in enumerate(registers) if reg.name not in free)
        module.aux_data["liveRegisterSets"].data = {
            gtirb.Offset(block, inst.address - block.address): mask
            for inst in decoder.get_instructions(block)}
        manager = LiveRegisterManager(module, abi, decoder, analysis_scope="block")
        manager.analyzer.analyze = Mock(side_effect=AssertionError("Unexpected Python LRA fallback"))
        module.aux_data["riscvUnresolvedPcrelReferences"] = gtirb.AuxData(
            [], "sequence<tuple<uint64_t,uint64_t,string>>")
        normalization = NormalizeRISCV64GPReferencesPass(decoder, manager, arch)
        return ir, module, block, normalization

    def run_pass(self, ir, normalization):
        manager = PassManager()
        manager.add(normalization)
        with redirect_stdout(io.StringIO()):
            manager.run(ir)
        normalization.reg_manager.refresh(preserve_liveness=True)

    def instructions(self, module, normalization):
        return [inst for block in sorted(module.code_blocks, key=lambda block: block.address or 0)
                for inst in normalization.decoder.get_instructions(block)]

    def test_integer_destinations_reused_and_new_instructions_are_all_live(self):
        for instruction in ("ld a0,-128(gp)", "lbu t0,-128(gp)", "addi a1,gp,-128", "addi a1,gp,0"):
            with self.subTest(instruction=instruction):
                ir, module, _, normalization = self.make_reference(instruction)
                self.run_pass(ir, normalization)
                self.assertEqual((normalization.reused, normalization.spare, normalization.spilled), (1, 0, 0))
                self.assertFalse(any(isinstance(expr, gtirb.SymAddrAddr)
                                     for interval in module.byte_intervals
                                     for expr in interval.symbolic_expressions.values()))
                self.assertEqual(self.instructions(module, normalization)[0].mnemonic, "auipc")
                function = next(iter(Function.build_functions(module)))
                normalization.reg_manager.analyze(function)
                for block in function.get_all_blocks():
                    for index, inst in enumerate(normalization.decoder.get_instructions(block)):
                        if not normalization.arch.is_return_instruction(inst):
                            self.assertEqual(normalization.reg_manager.live_registers(function, block, index),
                                             set(normalization.arch.abi.all_registers()))

    def test_store_uses_available_register_not_its_source(self):
        ir, module, _, normalization = self.make_reference("sd t0,-128(gp)", ("t0", "t1"))
        self.run_pass(ir, normalization)
        self.assertEqual((normalization.spare, normalization.spilled), (1, 0))
        instructions = self.instructions(module, normalization)
        self.assertEqual(instructions[0].op_str.split(",")[0], "t1")
        # The real instructions behind mv and ret.
        self.assertEqual([inst.mnemonic for inst in instructions], ["auipc", "addi", "sd", "jalr"])

    def test_pressure_never_skips_and_no_runtime_storage_is_needed(self):
        for instruction in ("sd t0,-128(gp)", "sd sp,-128(gp)", "ld sp,-128(gp)",
                            "addi sp,gp,-128", "ld zero,-128(gp)", "fld fa0,-128(gp)",
                            "fsd fa0,-128(gp)", "ld gp,-128(gp)", "ld tp,-128(gp)"):
            with self.subTest(instruction=instruction):
                ir, module, _, normalization = self.make_reference(instruction)
                self.run_pass(ir, normalization)
                self.assertEqual((normalization.normalized, normalization.spilled), (1, 1))
                instructions = self.instructions(module, normalization)
                self.assertEqual(instructions[0].op_str, "sp, sp, -0x10")
                self.assertFalse(any("scratchpad" in symbol.name for symbol in module.symbols))

    def test_missing_or_unsupported_metadata_rejects(self):
        for replacement in (None, "scale", "attribute"):
            with self.subTest(replacement=replacement):
                ir, _, block, normalization = self.make_reference("ld a0,-128(gp)")
                if replacement is None:
                    block.byte_interval.symbolic_expressions.clear()
                else:
                    old = block.byte_interval.symbolic_expressions[0]
                    block.byte_interval.symbolic_expressions[0] = gtirb.SymAddrAddr(
                        2 if replacement == "scale" else 1, 0, old.symbol1, old.symbol2,
                        {gtirb.SymbolicExpression.Attribute.GOT} if replacement == "attribute" else old.attributes)
                with self.assertRaisesRegex(ValueError, "lacks supported symbolic metadata"):
                    self.run_pass(ir, normalization)

    def test_gp_initialization_is_not_replaced(self):
        ir, module, block, normalization = self.make_reference("auipc gp,0\naddi gp,gp,0")
        gp = next(module.symbols_named("__global_pointer$"))
        entry = next(module.symbols_named("test_function"))
        attrs = gtirb.SymbolicExpression.Attribute
        block.byte_interval.symbolic_expressions.update({
            0: gtirb.SymAddrConst(0, gp, {attrs.HI, attrs.PCREL}),
            4: gtirb.SymAddrConst(0, entry, {attrs.LO, attrs.PCREL})})
        self.run_pass(ir, normalization)
        self.assertEqual(normalization.normalized, 0)

    def test_gp_metadata_on_other_register_rejects(self):
        ir, _, _, normalization = self.make_reference("ld a0,-128(a1)")
        with self.assertRaisesRegex(ValueError, "does not match the operand"):
            self.run_pass(ir, normalization)

    def test_raw_gp_copy_and_derived_load_require_symbolic_metadata(self):
        for instruction in ("mv a0,gp", "mv a0,gp\nld a1,-128(a0)",
                            ".option rvc\nc.mv a0,gp\nld a1,-128(a0)"):
            with self.subTest(instruction=instruction):
                ir, _, block, normalization = self.make_reference(instruction)
                block.byte_interval.symbolic_expressions.clear()
                original = block.byte_interval.contents
                with self.assertRaisesRegex(ValueError, "lacks supported symbolic metadata"):
                    self.run_pass(ir, normalization)
                self.assertEqual(block.byte_interval.contents, original)

    def test_copy_not_using_gp_is_unaffected(self):
        ir, _, block, normalization = self.make_reference("mv a0,a1")
        block.byte_interval.symbolic_expressions.clear()
        self.run_pass(ir, normalization)
        self.assertEqual(normalization.normalized, 0)

    def test_serialized_unresolved_pair_diagnostics_refuse_before_normalization(self):
        ir, module, block, normalization = self.make_reference("ld a0,-128(gp)")
        module.aux_data["riscvUnresolvedPcrelReferences"] = gtirb.AuxData(
            [(0x1000, 0x1008, "multiple completed addresses")],
            "sequence<tuple<uint64_t,uint64_t,string>>")
        stream = io.BytesIO()
        ir.save_protobuf_file(stream)
        stream.seek(0)
        ir = gtirb.IR.load_protobuf_file(stream)
        module = ir.modules[0]
        block = next(module.symbols_named("test_function")).referent
        original = block.byte_interval.contents
        with self.assertRaisesRegex(ValueError, "0x1000 -> 0x1008: multiple completed addresses"):
            self.run_pass(ir, normalization)
        self.assertEqual(normalization.normalized, 0)
        self.assertEqual(block.byte_interval.contents, original)

    def test_empty_unresolved_pair_table_allows_normalization(self):
        ir, module, _, normalization = self.make_reference("ld a0,-128(gp)")
        module.aux_data["riscvUnresolvedPcrelReferences"] = gtirb.AuxData(
            [], "sequence<tuple<uint64_t,uint64_t,string>>")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.run_pass(ir, normalization)
        self.assertEqual(caught, [])
        self.assertEqual(normalization.normalized, 1)

    def test_absent_unresolved_pair_table_warns_without_claiming_validation(self):
        ir, module, _, normalization = self.make_reference("ld a0,-128(gp)")
        del module.aux_data["riscvUnresolvedPcrelReferences"]
        with self.assertWarnsRegex(RuntimeWarning, "lacks riscvUnresolvedPcrelReferences") as caught:
            self.run_pass(ir, normalization)
        self.assertIn("Regenerate", str(caught.warning))
        self.assertEqual(normalization.normalized, 1)

    def test_overlapping_views_require_a_spare_in_both(self):
        ir, module, block, normalization = self.make_reference("sd a0,-128(gp)", ("t0",))
        overlap = gtirb.CodeBlock(size=block.size, offset=block.offset, byte_interval=block.byte_interval)
        next(iter(module.aux_data["functionBlocks"].data.values())).add(overlap)
        mask = (1 << len(module.aux_data["liveRegisterNames"].data)) - 1
        for inst in normalization.decoder.get_instructions(overlap):
            module.aux_data["liveRegisterSets"].data[gtirb.Offset(overlap, inst.address - overlap.address)] = mask
        normalization.reg_manager.refresh(preserve_liveness=True)
        self.run_pass(ir, normalization)
        self.assertEqual((normalization.normalized, normalization.spilled), (1, 1))

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc"), "RV64 linker required")
    def test_unreachable_pc_relative_address_is_rejected_not_truncated(self):
        _, _, block, normalization = self.make_reference("ld a0,-128(gp)")
        inst = next(normalization.decoder.get_instructions(block))
        snippet = normalization._replacement(inst, block.byte_interval.symbolic_expressions[0], set())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "far.S"
            source.write_text(f".text\n.globl _start\n_start:\n{snippet}\nret\n.data\ntarget: .dword 37\n")
            result = subprocess.run([
                "riscv64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie", "-Wl,--no-relax",
                "-Wl,-Ttext=0x10000,-Tdata=0x200000000", str(source), "-o", str(root / "far")],
                text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("R_RISCV_PCREL_HI20", result.stderr)

    def test_pairs_survive_copy_serialization_and_another_round(self):
        ir, module, block, normalization = self.make_reference("sd a0,-128(gp)")
        self.run_pass(ir, normalization)
        copy_section(block.section, ".teapot_transient")
        stream = io.BytesIO()
        ir.save_protobuf_file(stream)
        stream.seek(0)
        ir = gtirb.IR.load_protobuf_file(stream)
        module = ir.modules[0]
        manager = PassManager()
        manager.add(NormalizeRISCV64GPReferencesPass(
            normalization.decoder, None, normalization.arch))
        with redirect_stdout(io.StringIO()):
            manager.run(ir)
        lows = [expr for interval in module.byte_intervals for expr in interval.symbolic_expressions.values()
                if gtirb.SymbolicExpression.Attribute.LO in expr.attributes]
        self.assertEqual(len(lows), 2)
        self.assertEqual({expr.symbol.referent.section.name for expr in lows}, {".text", ".teapot_transient"})

    @unittest.skipUnless(shutil.which("riscv64-linux-gnu-gcc") and shutil.which("qemu-riscv64"),
                         "RV64 compiler and QEMU required")
    def test_generated_spills_preserve_registers_and_stack_at_relocated_addresses(self):
        cases = {
            "ld a0,-128(gp)": "li t6,37\nbne a0,t6,fail",
            "sd t0,-128(gp)": "la t6,target\nld t6,0(t6)\nbne t0,t6,fail",
            "sd sp,-128(gp)": "la t6,target\nld t6,0(t6)\nbne sp,t6,fail",
            "ld sp,-128(gp)": "la t6,new_stack_end\nbne sp,t6,fail\nmv sp,s0",
            "addi sp,gp,-128": "la t6,target\nbne sp,t6,fail\nmv sp,s0",
            "fsd fa0,-128(gp)": "la t6,target\nld t6,0(t6)\nli a0,37\nbne a0,t6,fail",
            "fld fa0,-128(gp)": "fmv.x.d t6,fa0\nli a0,37\nbne a0,t6,fail",
        }
        for compressed in (False, True):
            for instruction, check in cases.items():
                with self.subTest(compressed=compressed, instruction=instruction), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    _, _, block, normalization = self.make_reference(instruction)
                    inst = next(normalization.decoder.get_instructions(block))
                    snippet = normalization._replacement(inst, block.byte_interval.symbolic_expressions[0], set())
                    # The per-patch MC ISA directive is not printed into the
                    # application. This standalone harness uses -march=rv64gc.
                    snippet = "\n".join(line for line in snippet.splitlines()
                                        if not line.startswith(".attribute arch,"))
                    initial = "new_stack_end" if instruction.startswith("ld sp") else "37"
                    asm = f"""
                        .option {'rvc' if compressed else 'norvc'}
                        .option norelax
                        .text
                        .globl _start
                        _start:
                            mv s0,sp
                            li gp,0x2880
                            li t0,51
                            li t1,52
                            li a0,37
                            fmv.d.x fa0,a0
                            {snippet}
                            {check}
                            bne sp,s0,fail
                            li t6,51
                            bne t0,t6,fail
                            li t6,52
                            bne t1,t6,fail
                            li t6,0x2880
                            bne gp,t6,fail
                            li a0,0
                            j done
                        fail: li a0,1
                        done: li a7,93
                            ecall
                        .data
                        .balign 16
                        target: .dword {initial}
                        .bss
                        .balign 16
                        .space 4096
                        new_stack_end:
                    """
                    source = root / "input.S"
                    source.write_text(asm)
                    for text, data in ((0x10000, 0x40000), (0x100010000, 0x100040000)):
                        binary = root / "run"
                        result = subprocess.run([
                            "riscv64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie",
                            "-march=rv64gc", "-mabi=lp64d", "-Wl,--no-relax,--build-id=none",
                            f"-Wl,-Ttext={text:#x},-Tdata={data:#x}", str(source), "-o", str(binary)],
                            text=True, capture_output=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(subprocess.run(["qemu-riscv64", str(binary)], timeout=10).returncode, 0)


if __name__ == "__main__":
    unittest.main()
