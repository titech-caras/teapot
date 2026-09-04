import unittest
from unittest import mock

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import PassManager
from gtirb_rewriting.abi import _ABIS

from teapot.arch.riscv64.architecture import RISCV64Architecture
from teapot.datacls.copied_section_mapping import CopiedSectionMapping
from teapot.passes.common.riscv64_relax_unconditional_branches_pass import (
    RISCV64RelaxUnconditionalBranchesPass,
)


def build_layout_growth_case():
    ir = gtirb.IR()
    module = gtirb.Module(
        name="riscv64-layout-growth",
        isa=gtirb.Module.ISA.ValidButUnsupported,
        file_format=gtirb.Module.FileFormat.ELF,
        byte_order=gtirb.Module.ByteOrder.Little,
        ir=ir,
    )
    module.aux_data["archInfo"] = gtirb.AuxData(
        {"ISA": "RISCV64"}, "mapping<string,string>"
    )
    gtirb.Symbol(
        name="scratchpad",
        payload=gtirb.ProxyBlock(module=module),
        module=module,
    )
    section = gtirb.Section(
        name=".teapot_transient",
        flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Readable},
        module=module,
    )

    # Jump A is initially within the deliberately small test threshold. Jump B
    # is outside it and expands between A and A's target, so A must be found on
    # a later relaxation iteration.
    contents = bytearray((0x00000013).to_bytes(4, "little") * 65)
    contents[0:4] = (0x0000006F).to_bytes(4, "little")
    contents[4:8] = (0x0000006F).to_bytes(4, "little")
    interval = gtirb.ByteInterval(
        address=0x400000,
        contents=bytes(contents),
        section=section,
    )
    jump_a = gtirb.CodeBlock(size=4, offset=0, byte_interval=interval)
    jump_b = gtirb.CodeBlock(size=4, offset=4, byte_interval=interval)
    gtirb.CodeBlock(size=112, offset=8, byte_interval=interval)
    target_a = gtirb.CodeBlock(size=4, offset=120, byte_interval=interval)
    gtirb.CodeBlock(size=132, offset=124, byte_interval=interval)
    target_b = gtirb.CodeBlock(size=4, offset=256, byte_interval=interval)

    target_a_symbol = gtirb.Symbol(
        name="target_a", payload=target_a, module=module
    )
    target_b_symbol = gtirb.Symbol(
        name="target_b", payload=target_b, module=module
    )
    interval.symbolic_expressions[0] = gtirb.SymAddrConst(
        0, target_a_symbol, set()
    )
    interval.symbolic_expressions[4] = gtirb.SymAddrConst(
        0, target_b_symbol, set()
    )
    module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData(
        {
            gtirb.Offset(interval, 0): 4,
            gtirb.Offset(interval, 4): 4,
        },
        "mapping<Offset,uint64_t>",
    )
    return ir, module, section, jump_a, jump_b


class RISCV64RelaxFixedPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.arch = RISCV64Architecture()
        cls.arch.install_decoder_compat()
        cls.arch.install_rewriting_compat()
        cls.arch.register_abi(_ABIS)

    def test_layout_growth_is_relaxed_to_fixed_point(self):
        ir, module, section, jump_a, jump_b = build_layout_growth_case()
        mapping = CopiedSectionMapping({}, {}, {})
        landing_pad_targets = set()

        def run_pass_manager(manager, _label):
            manager.run(ir)

        with mock.patch.object(
            RISCV64RelaxUnconditionalBranchesPass,
            "JAL_RELAX_THRESHOLD",
            128,
        ):
            adjusted = self.arch.relax_late_branches(
                module=module,
                text_section=section,
                transient_section=section,
                text_transient_mapping=mapping,
                landing_pad_targets=landing_pad_targets,
                run_pass_manager=run_pass_manager,
            )

        self.assertGreater(adjusted[0], 0)
        self.assertGreater(adjusted[1], 0)
        self.assertEqual(adjusted[-1], 0)

        decoder = GtirbInstructionDecoder(module.isa)
        self.assertNotIn(
            list(decoder.get_instructions(jump_a))[-1].mnemonic,
            {"j", "c.j"},
        )
        self.assertNotIn(
            list(decoder.get_instructions(jump_b))[-1].mnemonic,
            {"j", "c.j"},
        )

    def test_non_convergence_fails_loudly(self):
        ir, module, section, _jump_a, _jump_b = build_layout_growth_case()
        mapping = CopiedSectionMapping({}, {}, {})

        def report_growth_forever(relax, _module, _functions, _rewriting_ctx):
            relax.relaxed = 1

        def run_pass_manager(manager, _label):
            manager.run(ir)

        with mock.patch.object(
            RISCV64RelaxUnconditionalBranchesPass,
            "begin_module",
            report_growth_forever,
        ), mock.patch.object(
            self.arch,
            "MAX_BRANCH_RELAXATION_ITERATIONS",
            2,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                r"did not converge within 2 iterations: \[1, 1\]",
            ):
                self.arch.relax_late_branches(
                    module=module,
                    text_section=section,
                    transient_section=section,
                    text_transient_mapping=mapping,
                    landing_pad_targets=set(),
                    run_pass_manager=run_pass_manager,
                )


if __name__ == "__main__":
    unittest.main()
