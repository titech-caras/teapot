"""Speculative coverage pushes only for a runtime built for a fuzzer.

The runtime's contract carries its coverage mode. For an ordinary runtime, which
resets the guard list at every rollback, the rewrite has no coverage pushes, no
register spills around them and no guards; for a fuzzer's runtime the coverage
pass runs exactly as before.
"""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import gtirb
from gtirb_rewriting import Assembler

from teapot.liveness import LiveRegisterManager
from teapot.passes.transient.transient_coverage import TransientCoveragePass
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.preprocess.contract_record import RECORD_AUX_DATA
from test_live_register_preservation import make_module, symbol_references
from test_rewrite_reproducibility import VARIANTS
from runtime_contract_support import fixture_contract, fixture_layout


def assembled_module(variant):
    """The reproducibility test's small function of this ISA, every register live."""
    arch_type, isa, assembly, _, _ = VARIANTS[variant]
    arch = arch_type()
    ir, module, block, abi, registers = make_module(arch, isa, b"")
    assembler = Assembler(module)
    assembler.assemble(assembly)
    code = assembler.finalize().text_section.data
    block.byte_interval.contents = code
    block.byte_interval.size = block.size = len(code)
    manager = LiveRegisterManager(module, abi)
    for inst in manager.decoder.get_instructions(block):
        # All live: every coverage push needs its own spill wrapper.
        module.aux_data["liveRegisterSets"].data[gtirb.Offset(block, inst.address - block.address)] = \
            (1 << len(registers)) - 1
    return arch, ir, module, block, abi


def section(module, name):
    return next(s for s in module.sections if s.name == name)


class CoverageEmissionTests(unittest.TestCase):
    def test_rewrites_push_coverage_only_for_a_coverage_runtime(self):
        for variant in range(len(VARIANTS)):
            sizes, guards = {}, {}
            for coverage in (False, True):
                arch, ir, module, _, _ = assembled_module(variant)
                with self.subTest(arch=arch.name, coverage=coverage):
                    TeapotPipeline(ir, runtime_contract=fixture_contract(arch.name, coverage=coverage)).run()
                    transient = section(module, ".teapot_transient")
                    references = symbol_references(transient)
                    guards[coverage] = sum(interval.size
                                           for interval in section(module, ".teapot_guards").byte_intervals)
                    sizes[coverage] = sum(interval.size for interval in transient.byte_intervals)
                    # The guard bounds exist either way; a coverage runtime refers to them.
                    for name in ("__guard_start__teapot__", "__guard_end__teapot__"):
                        self.assertEqual(len(list(module.symbols_named(name))), 1)
                    record = json.loads(module.aux_data[RECORD_AUX_DATA].data)
                    self.assertIs(record["policy"]["coverage"], coverage)
                    self.assertEqual("coverage" in record["requirements"], coverage)
                    if coverage:
                        self.assertIn("guard_list_top", references)
                        self.assertGreater(guards[coverage], 0)
                        self.assertEqual(guards[coverage] % 4, 0)
                    else:
                        self.assertNotIn("guard_list_top", references)
                        self.assertEqual(guards[coverage], 0)
            with self.subTest(arch=arch.name):
                # The pushes and their spill wrappers are gone, and nothing else is added.
                self.assertLess(sizes[False], sizes[True])

    def test_transient_passes_differ_only_by_the_coverage_pass(self):
        for variant in range(len(VARIANTS)):
            for nested in (False, True):
                passes = {}
                for coverage in (False, True):
                    arch, ir, module, block, abi = assembled_module(variant)
                    with self.subTest(arch=arch.name, nested=nested, coverage=coverage):
                        options = InstrumentationOptions(enable_nested_speculation=nested)
                        contract = fixture_contract(arch.name, nested=nested, coverage=coverage)
                        pipeline = TeapotPipeline(ir, options=options, runtime_contract=contract)
                        pipeline.arch = arch
                        pipeline.reg_manager = LiveRegisterManager(module, abi)
                        pipeline.decoder = pipeline.reg_manager.decoder
                        pipeline.dift_layout = fixture_layout(arch.name)
                        pipeline.text_section = pipeline.transient_section = block.section
                        pipeline.guard_section = gtirb.Section(name=".teapot_guards", module=module)
                        gtirb.ByteInterval(section=pipeline.guard_section)
                        for name in ("text_section_start_symbol", "text_section_end_symbol",
                                     "transient_section_start_symbol", "transient_section_end_symbol"):
                            setattr(pipeline, name, gtirb.Symbol(name=name, payload=block, module=module))
                        pipeline.checkpoint_spare_registers = {}
                        pipeline.checkpoint_block_uuids = set()
                        pipeline._run_pass_manager = Mock()
                        pipeline._run_transient_passes()
                        manager, phase = pipeline._run_pass_manager.call_args.args
                        self.assertEqual(phase, "transient")
                        passes[coverage] = manager._passes
                        guard_symbols = list(module.symbols_named("__guard_start__teapot__"))
                        # Without coverage the guard section is made empty at once; with
                        # it, the coverage pass fills it once it has numbered the blocks.
                        self.assertEqual(len(guard_symbols), 0 if coverage else 1)
                with self.subTest(arch=arch.name, nested=nested):
                    plain = [type(p) for p in passes[False]]
                    covered = [type(p) for p in passes[True]]
                    self.assertNotIn(TransientCoveragePass, plain)
                    self.assertEqual(covered.count(TransientCoveragePass), 1)
                    index = covered.index(TransientCoveragePass)
                    self.assertEqual(covered[:index] + covered[index + 1:], plain)

    def test_disabled_gadgets_push_no_coverage_for_either_runtime(self):
        for variant in range(len(VARIANTS)):
            for coverage in (False, True):
                arch, ir, module, _, _ = assembled_module(variant)
                with self.subTest(arch=arch.name, coverage=coverage):
                    TeapotPipeline(ir, options=InstrumentationOptions(enable_gadgets=False),
                                   runtime_contract=fixture_contract(arch.name, coverage=coverage)).run()
                    self.assertNotIn("guard_list_top", symbol_references(section(module, ".teapot_transient")))
                    self.assertEqual(sum(i.size for i in section(module, ".teapot_guards").byte_intervals), 0)
                    record = json.loads(module.aux_data[RECORD_AUX_DATA].data)
                    self.assertIs(record["policy"]["coverage"], False)
                    self.assertEqual(record["abi"]["coverage"], int(coverage))


if __name__ == "__main__":
    unittest.main()
