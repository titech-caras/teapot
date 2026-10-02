"""Inputs the pipeline refuses up front, and the end state it checks or restores."""
import unittest

import gtirb

from teapot.arch import X64Architecture
from teapot.pipeline import TeapotPipeline
from test_live_register_preservation import make_module


class PipelineEndStateTests(unittest.TestCase):
    def test_an_owned_copy_block_without_its_marker_fails_the_build(self):
        from teapot.arch.aarch64.bti import AArch64BTIArchitecture

        module = gtirb.Module(name="verify", isa=gtirb.Module.ISA.ARM64)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, contents=b"\x1f\x20\x03\xd5" * 4, size=16)
        block = gtirb.CodeBlock(offset=0, size=16, byte_interval=interval)
        pipeline = TeapotPipeline.__new__(TeapotPipeline)
        pipeline.arch = AArch64BTIArchitecture()
        pipeline.arch.transient_padded_blocks = frozenset({block.uuid})
        pipeline.transient_section = section
        with self.assertRaisesRegex(ValueError, "1 padded targets do not start with the marker"):
            pipeline._verify_target_markers()


class PipelineInputTests(unittest.TestCase):
    def test_unlabeled_cfg_edges_are_rejected(self):
        ir, _, block, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        ir.cfg.add(gtirb.Edge(block, block))
        with self.assertRaisesRegex(ValueError, r"1 CFG edge\(s\) without a label"):
            TeapotPipeline(ir).run()


if __name__ == "__main__":
    unittest.main()
