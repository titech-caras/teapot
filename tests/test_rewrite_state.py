import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
import uuid

import gtirb
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting.abi import _ABIS
from gtirb_rewriting.decoder import GtirbInstructionDecoder

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.rewrite_state import Product, ProductNotReady, RewriteState
from test_live_register_preservation import make_module
from runtime_contract_support import fixture_contract

# One function per ISA that loads through its first argument and returns, so the
# copy gets a gadget check with a numbered report label.
_PROGRAMS = {
    "x64": (X64Architecture, gtirb.Module.ISA.X64, "488b07c3"),          # mov rax, [rdi]; ret
    "aarch64": (AArch64Architecture, gtirb.Module.ISA.ARM64, "000040f9c0035fd6"),  # ldr x0, [x0]; ret
    "riscv64": (RISCV64Architecture, gtirb.Module.ISA.ValidButUnsupported, "0335050067800000"),  # ld a0, 0(a0); ret
}
_LAYOUTS = {"x64": "x64-la48-asan-new", "aarch64": None, "riscv64": None}


def lifted(isa):
    """A small lift: all-live masks and a return edge, as tests/test_text_entry_marker_order.py builds it."""
    make, module_isa, contents = _PROGRAMS[isa]
    arch = make()
    ir, module, block, _, registers = make_module(arch, module_isa, bytes.fromhex(contents))
    next(module.symbols_named("test_function")).name = "callback"
    mask = (1 << len(registers)) - 1
    module.aux_data["liveRegisterSets"].data = {
        gtirb.Offset(block, inst.address - block.address): mask
        for inst in GtirbInstructionDecoder(module_isa).get_instructions(block)}
    ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module), gtirb.Edge.Label(gtirb.Edge.Type.Return)))
    return ir


def rewrite(ir, isa, **options):
    pipeline = TeapotPipeline(ir, _LAYOUTS[isa], InstrumentationOptions(**options),
                              runtime_contract=fixture_contract(isa))
    with redirect_stdout(io.StringIO()):
        pipeline.run()
    return pipeline


class ProductTests(unittest.TestCase):
    def test_not_run_disabled_and_done_are_distinct(self):
        product = Product("the transient pads", "the transient pad pass")
        with self.assertRaisesRegex(ProductNotReady, "the anchor pass needs the transient pads from the "
                                                     "transient pad pass, which has not run"):
            product.require("the anchor pass")
        with self.assertRaises(ProductNotReady):
            product.get("the anchor pass", disabled=())
        product.set(frozenset())
        # Ran and found nothing is a result, not a missing one.
        self.assertEqual(product.require("the anchor pass"), frozenset())
        with self.assertRaisesRegex(RuntimeError, "already done"):
            product.set(frozenset({1}))

        disabled = Product("the marked text targets", "the text indirect-branch transform")
        disabled.disable("--disable-indirect-transform")
        self.assertEqual(disabled.get("the marker check", disabled=()), ())
        with self.assertRaisesRegex(ProductNotReady, "--disable-indirect-transform turned off"):
            disabled.require("the marker check")


class SharedStateTests(unittest.TestCase):
    def test_label_numbers_belong_to_one_architecture(self):
        # The pipeline builds one Architecture per rewrite: a module's labels
        # must not depend on what the process rewrote before.
        for make in (AArch64Architecture, RISCV64Architecture):
            with self.subTest(isa=make.__name__):
                first, second = make(), make()
                first.register_abi(_ABIS)
                abi = second.register_abi(_ABIS)
                registers = [abi.get_register(name) for name in
                             (("x0", "x1", "x2", "x3") if make is AArch64Architecture else ("a0", "a1", "a2", "a3"))]

                def label(arch):
                    text = (arch.report_gadget_snippet("KASPER_MDS", *registers)
                            if make is AArch64Architecture else
                            arch.report_gadget_snippet("KASPER_MDS", *registers[:3]))
                    return next(token for token in text.split() if token.startswith(".L__report_gadget_call_"))

                # Each architecture starts at the same number and counts on its own.
                first_label = label(first)
                self.assertEqual(first_label, label(second))
                self.assertNotEqual(label(first), first_label)

    def test_riscv_pc_relative_labels_belong_to_one_architecture(self):
        first, second = RISCV64Architecture(), RISCV64Architecture()
        abi = first.register_abi(_ABIS)
        second.register_abi(_ABIS)
        attributes = {gtirb.SymbolicExpression.Attribute.PCREL, gtirb.SymbolicExpression.Attribute.HI}
        expression = gtirb.SymAddrConst(0, gtirb.Symbol(name="data_target"), attributes)

        def label(arch):
            text = arch._pcrel_address_snippet(abi.get_register("a0"), expression)
            return next(token.rstrip(":") for token in text.split() if token.startswith(".L__riscv64_mem_addr_"))

        first_label = label(first)
        self.assertEqual(first_label, label(second))
        self.assertNotEqual(label(first), first_label)

    def test_two_rewrites_of_one_ir_share_nothing(self):
        # The component driver rewrites several modules in one process; a copy of
        # one IR, loaded twice (same UUIDs), must come out the same both times.
        for isa in _PROGRAMS:
            with self.subTest(isa=isa):
                results, architectures = [], []
                with tempfile.TemporaryDirectory() as directory:
                    path = str(Path(directory) / "lifted.gtirb")
                    lifted(isa).save_protobuf(path)
                    for _ in range(2):
                        pipeline = rewrite(gtirb.IR.load_protobuf(path), isa)
                        architectures.append(pipeline.arch)
                        # The numbered labels are assembler-local and leave no symbol,
                        # so compare where each run's numbering got to. Symbol sets
                        # are not compared: gtirb-rewriting's set order, and with it
                        # an occasional helper label, differs between runs.
                        results.append((len(pipeline.state.pads.require("the test").padded_blocks),
                                        pipeline.arch.next_label_number("report"),
                                        pipeline.arch.next_label_number("pcrel")))
                self.assertIsNot(architectures[0], architectures[1])
                if isa != "x64":  # x64 report calls need no numbered label
                    self.assertGreater(results[0][1], 0, "the rewrite numbered no report label")
                self.assertEqual(results[0], results[1])

    def test_rewrite_without_the_target_transform_completes(self):
        # Turning the transform off disables its products; every consumer must
        # accept that rather than wait for a producer that never runs.
        for isa in _PROGRAMS:
            with self.subTest(isa=isa):
                state = rewrite(lifted(isa), isa, enable_indirect_transform=False).state
                for product in (state.text_targets, state.direct_entry_pads,
                                state.potential_targets, state.flags_dead_blocks):
                    self.assertTrue(product.disabled, product.name)
                self.assertTrue(state.pads.ran)

    def test_run_starts_with_an_empty_decoder_cache(self):
        sentinel = uuid.uuid4()
        CachedGtirbInstructionDecoder.cache[sentinel] = []
        with self.assertRaisesRegex(ValueError, "--runtime-contract"):
            TeapotPipeline(lifted("x64"), "x64-la48-asan-new").run()
        self.assertNotIn(sentinel, CachedGtirbInstructionDecoder.cache)

    def test_pipelines_share_no_state(self):
        first = TeapotPipeline(gtirb.IR())
        second = TeapotPipeline(gtirb.IR())
        first.checkpoint_df_blocks.add("block")
        self.assertEqual(second.checkpoint_df_blocks, set())
        self.assertIsNot(first.state, second.state)
        self.assertIsInstance(first.state, RewriteState)


if __name__ == "__main__":
    unittest.main()
