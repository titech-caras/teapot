"""Optional LP64 code generation through actual LLVM and mcasm."""
from collections import Counter
import hashlib
import re
import struct
from types import SimpleNamespace
import unittest
from uuid import uuid4

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints

from teapot.arch import RISCV64Architecture
from teapot.arch.decoders import riscv64_decoder
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
from teapot.passes.transient.lazy_dift import transient_replay_pass
from teapot.rewrite_state import RewriteState, TransientPads
from test_live_register_preservation import make_module


def record_object_bytes(data):
    # Functional LLVM output checks, not an IR/body certificate.
    if data[:5] != b"\x7fELF\x02" or struct.unpack_from("<I", data, 48)[0] & 6:
        raise AssertionError("LLVM did not emit an LP64 ELF object")


def code_summary(module):
    instructions = [inst for block in module.code_blocks if block.size
        for inst in riscv64_decoder().disasm(bytes(block.byte_interval.contents[
            block.offset:block.offset + block.size]), block.address or 0)]
    return {"instruction_count": len(instructions),
            "code_bytes": sum(block.size for block in module.code_blocks),
            "extension_counts": {"zicond": sum(inst.mnemonic.startswith("czero.") for inst in instructions)},
            "executable_data_bytes": sum(block.size for section in module.sections
                if gtirb.Section.Flag.Executable in section.flags
                for interval in section.byte_intervals for block in interval.blocks
                if isinstance(block, gtirb.DataBlock))}


def architecture(profile="lp64-pure"):
    arch = RISCV64Architecture()
    if profile is not None:
        # Profile selection is explicit and local to this architecture.
        object.__setattr__(arch, "riscv_profile", profile)
    return arch


def replay(arch, kind="text"):
    args = (SimpleNamespace(abi=arch.abi), None, None)
    kwargs = {"dift_layout": SimpleNamespace(xor_mask=0)}
    if kind == "text":
        return RISCV64TextDiftPropagationLLVMPass(*args, arch, **kwargs)
    return transient_replay_pass(
        arch, *args, **kwargs, immediate=(kind == "eager"),
        shadow_mapping_enforcement=(kind == "enforcing"))


def conditional_zero(mnemonic, rd, rs1, rs2):
    # Independent encoding from the Zicond instruction format, not the printer
    # or assembler under test. eqz funct3=101, nez funct3=111; funct7=0000111.
    word = (7 << 25 | rs2 << 20 | rs1 << 15 |
            (5 if mnemonic == "czero.eqz" else 7) << 12 | rd << 7 | 0x33)
    code = word.to_bytes(4, "little")
    decoded = list(riscv64_decoder().disasm(code, 0x1000))
    if len(decoded) != 1 or decoded[0].size != 4 or decoded[0].mnemonic != mnemonic:
        raise AssertionError(f"production decoder did not recognize {mnemonic}: {decoded}")
    return decoded[0]


def build_effect(dift, inst):
    block = gtirb.CodeBlock(size=4)
    gtirb.ByteInterval(address=inst.address, contents=bytes(inst.bytes), blocks=[block])
    dift._reset()
    dift.rewriting_ctx = SimpleNamespace(_abi=dift.arch.abi)
    effects = dift._instruction_effects(block, inst)
    # Match visit_inst: an unchanged/ignored effect never reaches LLVM or
    # capture insertion. In particular EQZ rd,rd,rd keeps its existing tag.
    if dift._should_skip_effects(effects):
        return "", "", effects
    options = dict(vars(effects))
    regs_read, regs_write = options.pop("regs_read"), options.pop("regs_write")
    capture = dift._build_dift_patch(
        block, inst, 0, regs_read, regs_write,
        scratch_plan=dift._plan_scratch_registers(2), **options)
    body = "\n".join(dift.llvm_ir)
    if getattr(dift, "shadow_mapping_enforcement", False):
        rebuilt = dift._rebuild_replay_body(dift.effects)
        if body != rebuilt:
            raise AssertionError("enforcing rebuild changed czero's captured-value rule")
        body = rebuilt
    parsed = dift._parse_and_optimize_llvm(dift._format_llvm_ir(
        body, target_triple=dift.target_triple))
    if getattr(dift.arch, "riscv_profile", "lp64d") == "lp64-pure":
        record_object_bytes(dift.target_machine.emit_object(parsed))
    assembly = dift._extract_function_asm(dift.target_machine.emit_assembly(parsed))
    registers = dift._get_register_usage(assembly)
    plan = dift._plan_scratch_registers(2)
    if hasattr(dift, "_allocate_replay_scratch"):
        assembly, registers, _ = dift._allocate_replay_scratch(
            assembly, registers, plan.live_registers)
    flush = dift._build_optimized_dift_values_patch(
        assembly, registers, scratch_plan=plan)
    context = SimpleNamespace(stack_adjustment=0)
    return capture(context), flush(context), effects


def core_recipe(name, dift, inst, capture, flush, effects):
    skipped = dift._should_skip_effects(effects)
    operands = dift._czero_operands(inst)
    if operands is None:
        raise AssertionError("pure core fixture requires an original CZERO instruction")
    capture_required = not skipped and not effects.clear_dest_tags and operands[2].name != "zero"
    return {"name": name, "instruction": inst, "capture": capture, "flush": flush,
            "skip_effects": skipped, "capture_required": capture_required}


def mcasm_cores(arch, recipes):
    """Send inserted patches, never original CZERO bytes, through mcasm."""
    ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ValidButUnsupported,
                                         bytes(recipes[0]["instruction"].bytes) + bytes.fromhex("67800000"))
    module.name = "pure-czero-cores"
    symbol = next(module.symbols_named("test_function"))
    symbol.name = recipes[0]["name"]
    module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
        {symbol: (0, "FUNC", "GLOBAL", "DEFAULT", 0)},
        "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
    module.aux_data["elfSectionProperties"] = gtirb.AuxData(
        {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
    module.aux_data["sectionProperties"] = gtirb.AuxData(
        {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
    original_blocks = [block]
    interval = block.byte_interval
    contents = bytes(interval.contents)
    for recipe in recipes[1:]:
        start = len(contents)
        contents += bytes(recipe["instruction"].bytes) + bytes.fromhex("67800000")
        original = gtirb.CodeBlock(offset=start, size=8, byte_interval=interval)
        original_blocks.append(original)
        function_id = uuid4()
        name = gtirb.Symbol(recipe["name"], payload=original, module=module)
        module.aux_data["functionEntries"].data[function_id] = {original}
        module.aux_data["functionBlocks"].data[function_id] = {original}
        module.aux_data["functionNames"].data[function_id] = name
        module.aux_data["elfSymbolInfo"].data[name] = (0, "FUNC", "GLOBAL", "DEFAULT", 0)
    interval.contents = contents
    interval.size = len(contents)
    for name in ("scratchpad", "dift_reg_tags", "dift_reg_queued_tags", "dift_reg_queue_pending"):
        imported = gtirb.Symbol(name, payload=gtirb.ProxyBlock(module=module), module=module)
        module.aux_data["elfSymbolInfo"].data[imported] = (0, "NOTYPE", "GLOBAL", "DEFAULT", 0)
    context = RewritingContext(module, list(Function.build_functions(module)))
    emitted = []

    def patch(text, name, role, *, required, skipped):
        if not isinstance(text, str):
            raise AssertionError("fixture patch assembly must be a string")
        if re.search(r"\bczero\.(?:eqz|nez)\b|^\s*\.(?:word|4byte)\b", text, flags=re.M):
            raise AssertionError("an original CZERO was re-emitted through the patch assembler")
        text = re.sub(r"\.L[A-Za-z0-9_.]+", lambda m: f".L{name}_{m[0][2:]}", text)
        row = {"name": name, "role": role, "required": required,
               "skip_effects": skipped, "assembly_sha256": hashlib.sha256(text.encode()).hexdigest(),
               "assembly": text, "status": "scheduled"}
        emitted.append(row)
        if text == "":
            if required:
                raise AssertionError(f"mandatory {role} patch is empty")
            row.update(status="empty-omitted", reason="production-effect-skip" if skipped else "no-capture-needed")
            return None
        if skipped:
            raise AssertionError("production-skipped effect requested a nonempty patch")

        @patch_constraints()
        def emit(_ctx):
            if row["status"] != "scheduled":
                raise AssertionError("fixture nonempty patch callback was invoked more than once")
            row["status"] = "callback-invoked"
            return text

        return Patch.from_function(emit)

    for original, recipe in zip(original_blocks, recipes):
        skipped, capture_required = recipe["skip_effects"], recipe["capture_required"]
        if type(skipped) is not bool or type(capture_required) is not bool or (skipped and capture_required):
            raise AssertionError("fixture must declare the production skip and capture requirements")
        for role, offset, required in (("capture", 0, capture_required), ("flush", 4, not skipped)):
            insertion = patch(recipe[role], recipe["name"] + "_" + role, role,
                              required=required, skipped=skipped)
            if insertion is not None:
                context.insert_at(original, offset, insertion)
    context.apply()
    for row in emitted:
        if row["status"] not in {"callback-invoked", "empty-omitted"}:
            raise AssertionError("a scheduled nonempty patch did not traverse real RewritingContext")
        row["context_apply_completed"] = True
    expected = Counter(bytes(recipe["instruction"].bytes) for recipe in recipes)
    actual = Counter()
    for code in module.code_blocks:
        data = bytes(code.byte_interval.contents[code.offset:code.offset + code.size])
        for instruction in riscv64_decoder().disasm(data, code.address or 0):
            if instruction.mnemonic in {"czero.eqz", "czero.nez"}:
                actual[bytes(instruction.bytes)] += 1
    if actual != expected:
        raise AssertionError("rewriting insertion changed or duplicated original CZERO bytes")
    summary = code_summary(module)
    if summary["extension_counts"].get("zicond", 0) != len(recipes):
        raise AssertionError("inserted lowering unexpectedly emitted a CZERO instruction")
    return ir, module, summary, emitted


def marker_producer_snippets(arch, identity):
    """Use production architecture factories, not a hand-spelled marker."""
    context = SimpleNamespace(scratch_registers=tuple(
        arch.abi.get_register(name) for name in ("t0", "t1")), stack_adjustment=0)
    target = gtirb.Symbol("test_function")
    snippets = {
        "indirect-fixed": arch.indirect_branch_target_patch(target)(context),
        "indirect-allocated": arch.indirect_branch_target_patch(
            target, use_scratch_registers=True)(context),
        "landing-copy": arch.restore_landing_entry_patch(identity, preserve_marker=True)(context),
        "landing-normal": arch.restore_landing_entry_patch(
            identity, normal_text=True, preserve_marker=True)(context),
    }
    # Fallback emits a jump to a landing label. Define that local label in the
    # non-executed fixture so mcasm resolves it without an undefined-symbol waiver.
    fallback = arch.indirect_transform_fallback_patch(target, landing_target_uuid=identity)(context)
    snippets["indirect-fallback"] = fallback + "\n" + arch.landing_pad_entry_label(identity) + ":\nret\n"
    section = gtirb.Section(name=".teapot_transient")
    state = RewriteState()
    state.pads.set(TransientPads(padded_blocks=frozenset(), copy_blocks=frozenset()))
    snippets["transient-pad"] = arch.transient_pad_passes(section, None, state)[0].marker_text()
    snippets["transient-anchor"] = arch.transient_anchor_passes(section, state)[0].marker_text()
    return snippets


def mcasm_marker_module(arch, assembly):
    """Insert a complete production marker snippet through real mcasm."""
    ir, module, block, _, _ = make_module(
        arch, gtirb.Module.ISA.ValidButUnsupported, bytes.fromhex("67800000"))
    module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
        {}, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
    for name in ("scratchpad", "checkpoint_cnt"):
        gtirb.Symbol(name, payload=gtirb.ProxyBlock(module=module), module=module)
    # Keep the complete production snippet; do not replace .word with code in
    # the test. A missed producer must fail the functional marker checks below.
    context = RewritingContext(module, list(Function.build_functions(module)))

    @patch_constraints()
    def emitted(_ctx):
        return assembly

    context.insert_at(block, 0, Patch.from_function(emitted))
    context.apply()
    summary = code_summary(module)
    interval, = next(section for section in module.sections if section.name == ".text").byte_intervals
    return ir, module, interval, summary


class PureRISCVCodegenTests(unittest.TestCase):
    def test_pure_replay_refuses_fp_control_vector_and_hidden_calls(self):
        dift = replay(architecture())
        for body in ("fmv.d.x ft0, zero", "fld f0, 0(a0)", "frcsr a0", "fsflags a0",
                     "csrrw a0, 3, zero", "csrrs a0, fcsr, zero", "vmv.v.i v0, 0",
                     "call helper", "tail helper", "jalr ra, a0, 0"):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    dift._build_optimized_dift_values_patch(body, dift._get_register_usage(body))

    def test_vectorized_integer_tags_lower_without_fp_preservation(self):
        dift = replay(architecture())
        body = """
%v = load <16 x i8>, ptr @dift_reg_tags, align 16
%r = or <16 x i8> %v, <i8 1,i8 2,i8 4,i8 8,i8 16,i8 32,i8 64,i8 -128,i8 1,i8 2,i8 4,i8 8,i8 16,i8 32,i8 64,i8 -128>
store <16 x i8> %r, ptr @dift_reg_tags, align 16
"""
        parsed = dift._parse_and_optimize_llvm(dift._format_llvm_ir(body, target_triple=dift.target_triple))
        record_object_bytes(dift.target_machine.emit_object(parsed))
        emitted = dift._extract_function_asm(dift.target_machine.emit_assembly(parsed))
        snippet = dift._build_optimized_dift_values_patch(emitted, dift._get_register_usage(emitted))(
            SimpleNamespace(stack_adjustment=0))
        self.assertIn(f'.attribute arch, "{dift.PURE_ASM_ARCH}"', snippet)
        self.assertNotIn("rv64imafd", snippet)
        self.assertNotRegex(snippet, r"\b(?:f[ast][0-9]+|f[0-9]+|frcsr|fscsr|fsd|fld|v[0-9]+)\b")
        self.assertNotRegex(snippet, r"(?m)^\s*(?:call|tail)\s")


    def test_real_rewriting_context_assembles_lowered_czero_and_preserves_input(self):
        arch = architecture()
        for mnemonic in ("czero.eqz", "czero.nez"):
            for shape in ((10, 11, 12), (5, 11, 5), (11, 11, 11)):
                inst = conditional_zero(mnemonic, *shape)
                dift = replay(arch)
                capture, flush, effects = build_effect(dift, inst)
                self.assertEqual(dift.PURE_ASM_ARCH, "rv64ima")
                recipe = core_recipe("core", dift, inst, capture, flush, effects)
                _, module, summary, emitted = mcasm_cores(arch, [recipe])
                self.assertTrue(all(isinstance(symbol, gtirb.Symbol) and symbol.module is module
                                    for symbol in module.aux_data["elfSymbolInfo"].data))
                self.assertTrue(all(isinstance(section, gtirb.Section) and section.module is module
                                    for section in module.aux_data["elfSectionProperties"].data))
                self.assertGreater(summary["instruction_count"], 1)
                self.assertEqual(summary["extension_counts"].get("zicond"), 1)
                for row in emitted:
                    self.assertNotRegex(row["assembly"], r"\bczero\.(?:eqz|nez)\b")

    def test_pure_markers_remain_in_executable_code_blocks(self):
        arch = architecture()
        expected = bytes.fromhex("1300401113004051")
        self.assertEqual(arch.nop_bytes, expected)
        identity = uuid4()
        for label, assembly in marker_producer_snippets(arch, identity).items():
            with self.subTest(producer=label):
                _, module, interval, summary = mcasm_marker_module(arch, assembly)
                self.assertEqual(bytes(interval.contents[:8]), expected)
                for offset in range(8):
                    owners = [block for block in interval.blocks
                              if block.offset <= offset < block.offset + block.size]
                    self.assertTrue(owners, "every actual marker byte must have a block owner")
                    self.assertTrue(all(isinstance(block, gtirb.CodeBlock) for block in owners),
                                    "pure marker cannot become executable data")
                self.assertEqual(summary["executable_data_bytes"], 0)
                self.assertGreaterEqual(summary["instruction_count"], 3)
                self.assertFalse(any(isinstance(block, gtirb.DataBlock) and block.size
                                     for section in module.sections
                                     if gtirb.Section.Flag.Executable in section.flags
                                     for code_interval in section.byte_intervals
                                     for block in code_interval.blocks))
                decoded = list(riscv64_decoder().disasm(expected, 0x1000))
                self.assertEqual([bytes(instruction.bytes) for instruction in decoded],
                                 [expected[:4], expected[4:]])
                self.assertEqual([instruction.mnemonic for instruction in decoded], ["addi", "addi"])


if __name__ == "__main__":
    unittest.main()
