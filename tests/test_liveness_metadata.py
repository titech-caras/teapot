"""Teapot runs no Python liveness analysis: it requires DDisasm's validated masks (A2)."""
import io
from contextlib import redirect_stdout
import unittest
import warnings

import gtirb
from gtirb_rewriting.decoder import GtirbInstructionDecoder

from teapot.arch import X64Architecture
from teapot.pipeline import TeapotPipeline
from test_live_register_preservation import make_module
from runtime_contract_support import fixture_contract

REMEDY = "relift the input with the supported DDisasm"


def lift(contents=b"\x90\xc3", masked=True):
    """nop; ret with the flag rule and, when masked, an all-live mask on every instruction."""
    ir, module, block, _, registers = make_module(X64Architecture(), gtirb.Module.ISA.X64, contents)
    next(module.symbols_named("test_function")).name = "callback"
    if masked:
        mask = (1 << len(registers)) - 1
        module.aux_data["liveRegisterSets"].data = {
            gtirb.Offset(block, inst.address - block.address): mask
            for inst in GtirbInstructionDecoder(module.isa).get_instructions(block)}
    ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module), gtirb.Edge.Label(gtirb.Edge.Type.Return)))
    return ir, module


def run(ir):
    pipeline = TeapotPipeline(ir, "x64-la48-asan-new", runtime_contract=fixture_contract("x64"))
    output = io.StringIO()
    with redirect_stdout(output), warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        pipeline.run()
    return pipeline, output.getvalue()


class LivenessMetadataTests(unittest.TestCase):
    def test_a_lift_without_masks_is_refused(self):
        for table in ("liveRegisterNames", "liveRegisterSets"):
            with self.subTest(missing=table):
                ir, module = lift()
                del module.aux_data[table]
                with self.assertRaisesRegex(ValueError, f"the lift has no DDisasm live-register masks; {REMEDY}"):
                    run(ir)

    def test_masks_without_the_flag_rule_are_refused(self):
        # An older DDisasm: the manager would recompute the flags in Python.
        ir, module = lift()
        del module.aux_data["liveRegisterFlagRule"]
        with self.assertRaisesRegex(ValueError, f"the masks name no liveRegisterFlagRule "
                                                f"\\(an older DDisasm\\); {REMEDY}"):
            run(ir)

    def test_masks_under_the_old_flag_rule_are_refused(self):
        # call-boundary masks kill every flag at a call, also where the callee
        # reads its caller's flags: the corrected producer says callee-entry.
        ir, module = lift()
        module.aux_data["liveRegisterFlagRule"].data = "call-boundary"
        with self.assertRaisesRegex(ValueError, "the masks follow the flag rule 'call-boundary', an older DDisasm, "
                                                f"whose masks kill every flag at a call.*; {REMEDY}"):
            run(ir)

    def test_an_unusable_table_is_refused_with_its_reason(self):
        ir, module = lift()
        names = module.aux_data["liveRegisterNames"].data
        module.aux_data["liveRegisterNames"].data = names + [names[0]]
        with self.assertRaisesRegex(ValueError, "the register-name table contains aliases of the same register; "
                                                f"{REMEDY}"):
            run(ir)

    def test_instructions_without_a_mask_are_counted(self):
        _, output = run(lift()[0])
        self.assertIn("[teapot] live-register masks: 2 original instructions, 0 without a mask (all-live), "
                      "0 invalid entries discarded", output)
        ir, module = lift()
        block = next(iter(module.code_blocks))
        module.aux_data["liveRegisterSets"].data.pop(gtirb.Offset(block, 1))
        module.aux_data["liveRegisterSets"].data[gtirb.Offset(block, 7)] = 0  # past the block's end
        _, output = run(ir)
        self.assertIn("2 original instructions, 1 without a mask (all-live), 1 invalid entries discarded", output)


if __name__ == "__main__":
    unittest.main()
