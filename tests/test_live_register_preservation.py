import unittest
import io
from contextlib import redirect_stdout
from unittest.mock import Mock
from uuid import uuid4

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import Patch, RewritingContext, patch_constraints
from gtirb_rewriting.abi import _ABIS

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.passes.common.aarch64_relax_conditional_branches_pass import (
    AArch64RelaxConditionalBranchesPass, _Replacement,
)
from teapot.passes.transient.transient_coverage import TransientCoveragePass
from teapot.preprocess.copy_section import copy_section
from teapot.pipeline import TeapotPipeline


def make_module(arch, isa, contents):
    abi = arch.register_abi(_ABIS)
    ir = gtirb.IR()
    module = gtirb.Module(
        name="liveness-test", isa=isa, file_format=gtirb.Module.FileFormat.ELF,
        byte_order=gtirb.Module.ByteOrder.Little, ir=ir)
    if arch.name == "riscv64":
        module.aux_data["archInfo"] = gtirb.AuxData(
            {"ISA": "RISCV64"}, "mapping<string,string>")
    section = gtirb.Section(
        name=".text", module=module,
        flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable,
               gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
    interval = gtirb.ByteInterval(address=0x1000, contents=contents, section=section)
    block = gtirb.CodeBlock(size=len(contents), byte_interval=interval)
    symbol = gtirb.Symbol(name="test_function", payload=block, module=module)
    function_id = uuid4()
    for name in ("functionEntries", "functionBlocks"):
        module.aux_data[name] = gtirb.AuxData(
            {function_id: {block}}, "mapping<UUID,set<UUID>>")
    module.aux_data["functionNames"] = gtirb.AuxData(
        {function_id: symbol}, "mapping<UUID,UUID>")
    # Frontend metadata includes only canonical scratch GPRs and flags here.
    registers = list(abi._scratch_registers())
    if abi.flag_register() is not None:
        registers.append(abi.flag_register())
    module.aux_data["liveRegisterNames"] = gtirb.AuxData(
        [reg.name for reg in registers], "sequence<string>")
    module.aux_data["liveRegisterSets"] = gtirb.AuxData({}, "mapping<Offset,uint64_t>")
    return ir, module, block, abi, registers


def symbol_references(section):
    """Addresses of the symbolic expressions in *section*, by the name of the symbol they refer to.

    Emitted code refers to a runtime symbol through these; the symbol itself exists as soon as
    ImportSymbolsPass has run, whether or not anything uses it."""
    references = {}
    for interval in section.byte_intervals:
        for offset, expression in interval.symbolic_expressions.items():
            if isinstance(expression, gtirb.SymAddrConst):
                references.setdefault(expression.symbol.name, []).append(interval.address + offset)
    return references


class LiveRegisterPreservationTests(unittest.TestCase):
    def test_refresh_reports_source_transitions(self):
        ir, module, _, abi, _ = make_module(
            X64Architecture(), gtirb.Module.ISA.X64, b"\x90\xc3")
        metadata = {name: module.aux_data[name]
                    for name in ("liveRegisterNames", "liveRegisterSets")}
        pipeline = TeapotPipeline(ir)
        pipeline.module = module
        pipeline.reg_manager = LiveRegisterManager(module, abi, analysis_scope="block")
        output = io.StringIO()
        with redirect_stdout(output):
            pipeline._refresh_register_analysis()
            self.assertEqual(output.getvalue(), "")
            module.aux_data["liveRegisterSets"] = gtirb.AuxData([], "sequence<uint64_t>")
            with self.assertWarnsRegex(RuntimeWarning, "Python block-scope"):
                pipeline._refresh_register_analysis()
            self.assertNotIn("liveRegisterSets", module.aux_data)
            module.aux_data.update(metadata)
            pipeline._refresh_register_analysis()
        self.assertEqual(output.getvalue().splitlines(), [
            "[teapot] live-register analysis: ddisasm -> python",
            "[teapot] live-register analysis: python -> ddisasm",
        ])

    def test_copies_diverge_without_sharing_added_live_state(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                _, module, source, abi, registers = make_module(
                    X64Architecture(), gtirb.Module.ISA.X64, b"\x90\x90\xc3")
                rax, rbx = abi.get_register("rax"), abi.get_register("rbx")
                module.aux_data["liveRegisterSets"].data = {
                    gtirb.Offset(source, 0): 1 << registers.index(rax),
                    gtirb.Offset(source, 1): 0,
                    gtirb.Offset(source, 2): 1 << registers.index(rbx),
                }
                manager = LiveRegisterManager(module, abi)
                module.aux_data['liveRegisterSetsHigh'] = gtirb.AuxData({
                    gtirb.Offset(source, 0): 1 << 55,
                    gtirb.Offset(source, 1): 0,
                    gtirb.Offset(source, 2): 1 << 54,
                }, 'mapping<Offset,uint64_t>')
                copied_section, _, _, mapping = copy_section(source.section, ".teapot_transient")
                copied = mapping.code_blocks_map[source.uuid]
                high = module.aux_data['liveRegisterSetsHigh'].data
                self.assertEqual(high[gtirb.Offset(copied, 0)], 1 << 55)
                self.assertEqual(high[gtirb.Offset(copied, 1)], 0)
                manager.refresh(preserve_liveness=True)
                manager.analyzer.analyze = Mock(side_effect=AssertionError("Python fallback"))

                @patch_constraints()
                def nop(_ctx):
                    return "nop"

                for block, offset in ((source, 0), (copied, 1)):
                    ctx = RewritingContext(module, list(Function.build_functions(module)))
                    ctx.insert_at(block, offset, Patch.from_function(nop))
                    ctx.apply()
                    manager.refresh(preserve_liveness=True)

                high = module.aux_data['liveRegisterSetsHigh'].data
                self.assertEqual({off.displacement: value for off, value in high.items()
                                  if off.element_id == source}, {1: 1 << 55, 2: 0, 3: 1 << 54})
                self.assertEqual({off.displacement: value for off, value in high.items()
                                  if off.element_id == copied}, {0: 1 << 55, 2: 0, 3: 1 << 54})

                functions = sorted(Function.build_functions(module), key=lambda fn: fn.get_name(),
                                   reverse=reverse)
                actual = {}
                for function in functions:
                    manager.analyze(function)
                    blocks = sorted(function.get_all_blocks(), key=lambda block: block.address)
                    values = []
                    for block in blocks:
                        for index, _ in enumerate(manager.analyzer.decoder.get_instructions(block)):
                            values.append(set(manager.live_registers(function, block, index)))
                    actual[blocks[0].section.name] = values
                # Missing producer masks keep every non-flag register live. No flag
                # is live into RET: neither ABI preserves flags for the caller.
                flags = {abi.flag_register()}
                all_live = set(abi.all_registers()) - flags
                self.assertEqual(actual[".text"], [all_live, {rax}, set(), {rbx}])
                self.assertEqual(actual[copied_section.name], [{rax}, all_live, set(), {rbx}])

                source_function = next(fn for fn in functions if fn.get_name() == "test_function")
                copy_function = next(fn for fn in functions if fn is not source_function)
                source_block = next(iter(source_function.get_entry_blocks()))
                copy_block = next(iter(copy_function.get_entry_blocks()))
                manager.add_live_registers(source_function, source_block, 1, {rbx})
                self.assertEqual(manager.live_registers(copy_function, copy_block, 0), {rax})
                manager.refresh(preserve_liveness=True)
                manager.analyze(source_function)
                self.assertEqual(manager.live_registers(source_function, source_block, 1), {rax})

    def test_riscv_coverage_allocates_after_auipc(self):
        arch = RISCV64Architecture()
        _, module, block, abi, registers = make_module(
            arch, gtirb.Module.ISA.ValidButUnsupported, bytes.fromhex("970200001383420067800000"))
        t0 = abi.get_register("t0")
        module.aux_data["liveRegisterSets"].data = {
            gtirb.Offset(block, 0): 0,
            gtirb.Offset(block, 4): 1 << registers.index(t0),
            gtirb.Offset(block, 8): 0,
        }
        target = gtirb.Symbol(name="target", payload=0x2000, module=module)
        block.byte_interval.symbolic_expressions[0] = gtirb.SymAddrConst(
            0, target, {gtirb.SymbolicExpression.Attribute.PCREL,
                        gtirb.SymbolicExpression.Attribute.HI})
        allocated, instructions = self._insert_coverage_probe(arch, module, block, abi)
        self.assertNotIn(t0, allocated)
        self.assertEqual(instructions[0].mnemonic, "auipc")
        self.assertEqual(instructions[1].operands[-1].imm, 7)
        self.assertEqual(abi.get_register(instructions[1].reg_name(instructions[1].operands[0].reg)),
                         allocated[0])

    def test_riscv_coverage_allocates_after_complete_hi_lo_pair(self):
        arch = RISCV64Architecture()
        _, module, block, abi, registers = make_module(
            arch, gtirb.Module.ISA.ValidButUnsupported, bytes.fromhex("97020000138342001300000067800000"))
        t0, t1 = abi.get_register("t0"), abi.get_register("t1")
        module.aux_data["liveRegisterSets"].data = {
            gtirb.Offset(block, 0): 0,
            gtirb.Offset(block, 4): 1 << registers.index(t0),
            gtirb.Offset(block, 8): 1 << registers.index(t1),
            gtirb.Offset(block, 12): 0,
        }
        target = gtirb.Symbol(name="target", payload=0x2000, module=module)
        anchor = gtirb.Symbol(name="anchor", payload=block, module=module)
        block.byte_interval.symbolic_expressions.update({
            0: gtirb.SymAddrConst(0, target, {gtirb.SymbolicExpression.Attribute.PCREL,
                                           gtirb.SymbolicExpression.Attribute.HI}),
            4: gtirb.SymAddrConst(0, anchor, {gtirb.SymbolicExpression.Attribute.PCREL,
                                           gtirb.SymbolicExpression.Attribute.LO}),
        })
        allocated, instructions = self._insert_coverage_probe(arch, module, block, abi)
        self.assertNotIn(t1, allocated)
        self.assertEqual(instructions[0].mnemonic, "auipc")
        self.assertEqual(instructions[1].operands[-1].imm, 4)
        self.assertEqual(instructions[2].operands[-1].imm, 7)

    def test_riscv_coverage_allocates_in_preceding_call_prefix(self):
        arch = RISCV64Architecture()
        _, module, prefix, abi, registers = make_module(
            arch, gtirb.Module.ISA.ValidButUnsupported, bytes.fromhex("97000000e78000001300000067800000"))
        prefix.size = 4
        call = gtirb.CodeBlock(offset=4, size=4, byte_interval=prefix.byte_interval)
        suffix = gtirb.CodeBlock(offset=8, size=8, byte_interval=prefix.byte_interval)
        next(iter(module.aux_data["functionBlocks"].data.values())).update({call, suffix})
        t0 = abi.get_register("t0")
        module.aux_data["liveRegisterSets"].data = {
            gtirb.Offset(prefix, 0): 1 << registers.index(t0),
            gtirb.Offset(call, 0): 0,
            gtirb.Offset(suffix, 0): 0,
            gtirb.Offset(suffix, 4): 0,
        }
        target = gtirb.Symbol(name="callee", payload=gtirb.ProxyBlock(module=module), module=module)
        prefix.byte_interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, target)
        allocated, instructions = self._insert_coverage_probe(arch, module, call, abi)
        self.assertNotIn(t0, allocated)
        self.assertEqual(instructions[0].operands[-1].imm, 7)
        self.assertEqual(instructions[1].mnemonic, "auipc")

    def _insert_coverage_probe(self, arch, module, block, abi):
        manager = LiveRegisterManager(module, abi)
        manager.analyzer.analyze = Mock(side_effect=AssertionError("Python fallback"))
        function = next(iter(Function.build_functions(module)))
        manager.analyze(function)
        allocated = []

        @patch_constraints(scratch_registers=1)
        def patch(ctx):
            allocated.extend(ctx.scratch_registers)
            return f"li {ctx.scratch_registers[0]}, 7"

        arch.coverage_patch = lambda _idx, index_base_symbol=None: patch
        guard_section = gtirb.Section(name=".teapot_guards", module=module)
        visitor = TransientCoveragePass(
            manager, block.section, manager.analyzer.decoder, guard_section, arch)
        ctx = RewritingContext(module, [function])
        visitor.rewriting_ctx = ctx
        visitor.visit_code_block(block, function)
        ctx.apply()
        self.assertEqual(len(allocated), 1)
        manager.refresh(preserve_liveness=True)
        instructions = [inst for current in sorted(module.code_blocks, key=lambda b: b.address)
                        for inst in manager.analyzer.decoder.get_instructions(current)]
        return allocated, instructions

    def test_aarch64_direct_relaxation_retains_only_surviving_masks(self):
        _, module, block, abi, _ = make_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, bytes.fromhex("1f2003d5" * 4))
        interval = block.byte_interval
        module.aux_data["liveRegisterSets"].data = {
            gtirb.Offset(block, offset): offset + 1 for offset in range(0, 16, 4)}
        relax = AArch64RelaxConditionalBranchesPass(CachedGtirbInstructionDecoder(module.isa), direct_pads={})
        relax.module = module
        relax.replacements_by_interval = {
            interval: [_Replacement(4, bytes.fromhex("1f2003d5" * 2), symbolic_expressions=())]}
        relax._apply_replacements()
        self.assertEqual(dict(module.aux_data["liveRegisterSets"].data), {
            gtirb.Offset(block, 0): 1,
            gtirb.Offset(block, 12): 9,
            gtirb.Offset(block, 16): 13,
        })
        relax.replacements_by_interval = {
            interval: [_Replacement(0, bytes.fromhex("1f2003d5" * 3), symbolic_expressions=())]}
        relax._apply_replacements()
        self.assertEqual(dict(module.aux_data["liveRegisterSets"].data), {
            gtirb.Offset(block, 20): 9,
            gtirb.Offset(block, 24): 13,
        })


if __name__ == "__main__":
    unittest.main()
