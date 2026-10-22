import unittest
from unittest import mock
from pathlib import Path
import shutil
import subprocess
import tempfile

import gtirb
from gtirb_rewriting.decoder import GtirbInstructionDecoder
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
        for jump in (jump_a, jump_b):
            # Capstone decodes j as `jal zero, target`; a relaxed jump ends in jalr.
            self.assertFalse(self.arch.is_unconditional_jump(list(decoder.get_instructions(jump))[-1]))

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

    def test_far_external_tail_and_call_use_abi_long_forms(self):
        ir, module, text, tail, call = build_layout_growth_case()
        text.name = ".text"
        interval = tail.byte_interval
        interval.contents = interval.contents[:4] + bytes.fromhex("ef000000") + interval.contents[8:]
        external = gtirb.Symbol(name="far_external", payload=gtirb.ProxyBlock(module=module), module=module)
        entry = gtirb.Symbol(name="_start", payload=tail, module=module)
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData({
            external: (0, "FUNC", "GLOBAL", "DEFAULT", 0),
            entry: (0, "FUNC", "GLOBAL", "DEFAULT", 1),
        }, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
        module.aux_data["functionEntries"] = gtirb.AuxData(
            {entry.uuid: {tail}}, "mapping<UUID,set<UUID>>")
        module.aux_data["functionBlocks"] = gtirb.AuxData(
            {entry.uuid: set(text.code_blocks)}, "mapping<UUID,set<UUID>>")
        module.aux_data["functionNames"] = gtirb.AuxData(
            {entry.uuid: entry}, "mapping<UUID,UUID>")
        module.aux_data["sectionProperties"] = gtirb.AuxData(
            {text: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, external, set())
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, external, set())
        adjusted = self.arch.relax_late_branches(
            module=module, text_section=text, transient_section=text,
            text_transient_mapping=CopiedSectionMapping({}, {}, {}), landing_pad_targets=set(),
            run_pass_manager=lambda manager, label: manager.run(ir))
        self.assertEqual(adjusted, (2, 0))
        decoder = GtirbInstructionDecoder(module.isa)
        for block, temporary, link in ((tail, "t1", "zero"), (call, "ra", "ra")):
            instructions = list(decoder.get_instructions(block))
            self.assertEqual([i.mnemonic for i in instructions], ["auipc", "jalr"])
            self.assertEqual(instructions[0].reg_name(instructions[0].operands[0].reg), temporary)
            self.assertEqual(instructions[1].reg_name(instructions[1].operands[0].reg), link)
            self.assertEqual(instructions[1].reg_name(instructions[1].operands[1].reg), temporary)

        # Exercise the printer and the real no-relax link with the external
        # definition more than JAL's 1 MiB away, not a mocked distance.
        cc = shutil.which("riscv64-linux-gnu-gcc")
        printer = shutil.which("gtirb-pprinter")
        if cc is None or printer is None:
            self.skipTest("far external final-link test needs RV64 GCC and gtirb-pprinter")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ir.save_protobuf(root / "input.gtirb")
            printed = subprocess.run([printer, "--ir", root / "input.gtirb", "--asm", root / "main.S",
                                      "--policy", "complete", "--shared", "no"], capture_output=True)
            self.assertEqual(printed.returncode, 0, printed.stderr.decode(errors="replace"))
            (root / "external.S").write_text(
                '.section .far,"ax",@progbits\n.globl far_external\n.type far_external,@function\n'
                'far_external:\nret\n')
            linked = subprocess.run([cc, "-nostdlib", "-no-pie", "-Wl,--no-relax", "-Wl,-z,separate-code",
                                     "-Wl,--section-start=.far=0x400000", "-Wl,-e,_start",
                                     root / "main.S", root / "external.S", "-o", root / "linked"],
                                    capture_output=True)
            self.assertEqual(linked.returncode, 0, linked.stderr.decode(errors="replace"))

    def test_compressed_external_tail_keeps_following_alignment(self):
        ir, module, text, tail, following = build_layout_growth_case()
        interval = tail.byte_interval
        interval.contents = bytes.fromhex("01a00100") + interval.contents[4:]
        tail.size = 2
        gtirb.CodeBlock(size=2, offset=2, byte_interval=interval)
        external = gtirb.Symbol(name="far_external", payload=gtirb.ProxyBlock(module=module), module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, external, set())
        module.aux_data["symbolicExpressionSizes"].data[gtirb.Offset(interval, 0)] = 2
        module.aux_data["alignment"] = gtirb.AuxData({following: 4}, "mapping<UUID,uint64_t>")
        adjusted = self.arch.relax_late_branches(
            module=module, text_section=text, transient_section=text,
            text_transient_mapping=CopiedSectionMapping({}, {}, {}), landing_pad_targets=set(),
            run_pass_manager=lambda manager, label: manager.run(ir))
        self.assertEqual(adjusted, (1, 0))
        self.assertEqual(following.address % 4, 0)
        self.assertEqual(tail.byte_interval.contents[tail.offset:tail.offset + 2], bytes.fromhex("0100"))

    def test_normal_text_preserves_target_marker_and_transient_pad(self):
        for marked in (False, True):
            with self.subTest(marked=marked):
                ir, module, text, jump_a, jump_b = build_layout_growth_case()
                text.name = ".text"
                target_symbol = next(module.symbols_named("target_b"))
                target = target_symbol.referent
                if marked:
                    target.byte_interval.contents = (
                        target.byte_interval.contents[:target.offset] + self.arch.nop_bytes)
                    target.byte_interval.size = target.offset + len(self.arch.nop_bytes)
                    target.size = len(self.arch.nop_bytes)
                predecessor = next(b for b in text.code_blocks if b.offset == 124)
                module.ir.cfg.add(gtirb.Edge(
                    predecessor, target, gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))

                transient = gtirb.Section(name=".teapot_transient", flags=text.flags, module=module)
                transient_interval = gtirb.ByteInterval(
                    address=0x800000, contents=b"\x13\x00\x00\x00", section=transient)
                transient_target = gtirb.CodeBlock(size=4, byte_interval=transient_interval)
                transient_pad = gtirb.Symbol(
                    name=self.arch.landing_pad_entry_label(target.uuid),
                    payload=transient_target, module=module)
                mapping = CopiedSectionMapping({target.uuid: transient_target}, {}, {})

                with mock.patch.object(RISCV64RelaxUnconditionalBranchesPass,
                                       "JAL_RELAX_THRESHOLD", 128):
                    adjusted = self.arch.relax_late_branches(
                        module=module, text_section=text, transient_section=transient,
                        text_transient_mapping=mapping, landing_pad_targets={target.uuid},
                        run_pass_manager=lambda manager, label: manager.run(ir))
                self.assertGreater(sum(adjusted), 0)
                self.assertEqual(adjusted[-1], 0)
                self.assertIs(transient_pad.referent.section, transient)
                self.assertIs(target_symbol.referent.section, text)
                new_target = target_symbol.referent
                prefix = new_target.byte_interval.contents[
                    new_target.offset:new_target.offset + len(self.arch.nop_bytes)]
                self.assertEqual(prefix == self.arch.nop_bytes, marked)
                decoder = GtirbInstructionDecoder(module.isa)
                for jump in (jump_a, jump_b):
                    self.assertFalse(self.arch.is_unconditional_jump(list(decoder.get_instructions(jump))[-1]))


if __name__ == "__main__":
    unittest.main()
