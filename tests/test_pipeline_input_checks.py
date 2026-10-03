"""Inputs the pipeline refuses up front, and the end state it checks or restores."""
import unittest

import gtirb

from teapot.arch import X64Architecture
from teapot.pipeline import TeapotPipeline
from test_live_register_preservation import make_module
from teapot.rewrite_state import ProductNotReady, TransientPads


class PipelineEndStateTests(unittest.TestCase):
    def test_section_bounds_return_to_their_intervals_ends(self):
        module = gtirb.Module(name="bounds", isa=gtirb.Module.ISA.X64)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".text", module=module)
        interval = gtirb.ByteInterval(section=section, contents=bytes(32), size=32)
        gtirb.CodeBlock(offset=0, size=32, byte_interval=interval)
        start = gtirb.Symbol(name="start", payload=gtirb.CodeBlock(offset=8, size=0, byte_interval=interval),
                             module=module)
        end = gtirb.Symbol(name="end", payload=gtirb.CodeBlock(offset=24, size=0, byte_interval=interval),
                           module=module)
        external = gtirb.Symbol(name="external", payload=gtirb.ProxyBlock(module=module), module=module)
        pipeline = TeapotPipeline(gtirb.IR())
        pipeline.text_section_start_symbol, pipeline.text_section_end_symbol = start, end
        pipeline.transient_section_start_symbol = pipeline.transient_section_end_symbol = external
        pipeline._pin_section_bounds()
        self.assertEqual((start.referent.offset, end.referent.offset), (0, 32))
        self.assertIsInstance(external.referent, gtirb.ProxyBlock)

    def test_an_owned_copy_block_without_its_marker_fails_the_build(self):
        from teapot.arch.aarch64.bti import AArch64BTIArchitecture

        module = gtirb.Module(name="verify", isa=gtirb.Module.ISA.ARM64)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, contents=b"\x1f\x20\x03\xd5" * 4, size=16)
        block = gtirb.CodeBlock(offset=0, size=16, byte_interval=interval)
        pipeline = TeapotPipeline(gtirb.IR())
        pipeline.arch = AArch64BTIArchitecture()
        pipeline.transient_section = section
        pipeline.state.text_targets.disable("this test")
        # Without the pad pass's result there is nothing it may skip: fail closed.
        with self.assertRaisesRegex(ProductNotReady, "the transient pad pass, which has not run"):
            pipeline._verify_target_markers()
        pipeline.state.pads.set(TransientPads(frozenset({block.uuid}), frozenset({block.uuid})))
        with self.assertRaisesRegex(ValueError, "1 padded targets do not start with the marker"):
            pipeline._verify_target_markers()

    def test_a_recorded_pad_whose_block_is_gone_fails_the_build(self):
        from uuid import uuid4
        from teapot.arch.aarch64.bti import AArch64BTIArchitecture

        module = gtirb.Module(name="verify", isa=gtirb.Module.ISA.ARM64)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        gtirb.ByteInterval(section=section, contents=b"\x1f\x20\x03\xd5", size=4)
        pipeline = TeapotPipeline(gtirb.IR())
        pipeline.arch = AArch64BTIArchitecture()
        pipeline.transient_section = section
        pipeline.state.text_targets.disable("this test")
        gone = uuid4()
        pipeline.state.pads.set(TransientPads(frozenset({gone}), frozenset({gone})))
        with self.assertRaisesRegex(ValueError, f"1 padded targets do not start with the marker, "
                                                f"e.g. copy block {gone} \\(gone or empty\\)"):
            pipeline._verify_target_markers()


class PipelineInputTests(unittest.TestCase):
    def test_unlabeled_cfg_edges_are_rejected(self):
        ir, _, block, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        ir.cfg.add(gtirb.Edge(block, block))
        with self.assertRaisesRegex(ValueError, r"1 CFG edge\(s\) without a label"):
            TeapotPipeline(ir).run()


if __name__ == "__main__":
    unittest.main()
