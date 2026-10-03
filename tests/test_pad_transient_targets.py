"""Speculative-copy pad target selection (design step 5)."""
import io
from contextlib import redirect_stdout
import types
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import RewritingContext

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.arch.aarch64.bti import AArch64BTIArchitecture
from teapot.passes.transient.pad_transient_targets_pass import (
    AnchorTransientPadsPass, PadTransientTargetsPass,
)
from teapot.rewrite_state import ProductNotReady, RewriteState


def copy_module():
    module = gtirb.Module(name="pad", isa=gtirb.Module.ISA.ARM64)
    ir = gtirb.IR(modules=[module])
    section = gtirb.Section(name=".teapot_transient", module=module)
    contents = bytearray(b"\x1f\x20\x03\xd5" * 6)
    contents[16:24] = (0xd50324df).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little")
    interval = gtirb.ByteInterval(section=section, contents=bytes(contents), size=24)
    blocks = [gtirb.CodeBlock(offset=offset, size=size, byte_interval=interval)
              for offset, size in ((0, 4), (4, 4), (8, 4), (12, 4), (16, 8))]
    symbol_a = gtirb.Symbol(name="ref_a", payload=blocks[0], module=module)
    interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, symbol_a)
    symbol_e = gtirb.Symbol(name="ref_e", payload=blocks[4], module=module)
    interval.symbolic_expressions[16] = gtirb.SymAddrConst(0, symbol_e)
    ir.cfg.add(gtirb.Edge(blocks[2], blocks[1],
                          gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)))
    ir.cfg.add(gtirb.Edge(blocks[2], blocks[3],
                          gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=True)))
    return module, section, blocks


class PadTransientTargetsTests(unittest.TestCase):
    def test_unlabeled_edges_are_ignored(self):
        # GTIRB allows an edge without a label; it names no indirect target.
        module, section, blocks = copy_module()
        module.ir.cfg.add(gtirb.Edge(blocks[3], blocks[0]))
        pad = PadTransientTargetsPass(section, None, (0xd50324df, 0xd280a29f))
        self.assertIn(blocks[1], pad.target_blocks())

    def test_only_reachable_unmarked_targets(self):
        _, section, blocks = copy_module()
        pad = PadTransientTargetsPass(section, None, (0xd50324df, 0xd280a29f))
        # A is only named by a data symbol? No: both symbols name code blocks;
        # only the indirect edge target and no already-marked block are padded.
        self.assertEqual({block.offset for block in pad.target_blocks()}, {0, 4})

    def test_wiring_uses_the_mode_marker(self):
        _, section, _ = copy_module()
        bti = AArch64BTIArchitecture().transient_pad_passes(section, None, RewriteState())[0]
        self.assertEqual(bti.marker_words, (0xd50324df, 0xd280a29f))
        software = AArch64Architecture().transient_pad_passes(section, None, RewriteState())[0]
        self.assertEqual(software.marker_words, AArch64Architecture.MAGIC_WORDS)

    def test_every_isa_pads_the_copy_for_the_window_predicate(self):
        _, section, _ = copy_module()
        for arch in (AArch64Architecture(), X64Architecture(), RISCV64Architecture()):
            with self.subTest(isa=arch.name):
                pad = arch.transient_pad_passes(section, None, RewriteState())[0]
                self.assertEqual(pad.marker_words, tuple(arch.MAGIC_WORDS))
                directive = ".long" if arch.name == "x64" else ".word"
                self.assertEqual(pad.marker_text(), "".join(
                    f"{directive} 0x{word:08x}\n" for word in arch.MAGIC_WORDS))


    def test_direct_branch_operands_are_not_padded(self):
        # 0x1000: b +12 -> 0x100c target; 0x1004/0x1008: adrp/add target pair;
        # 0x100c: nop (the target).
        module = gtirb.Module(name="pad", isa=gtirb.Module.ISA.ARM64,
                              byte_order=gtirb.Module.ByteOrder.Little)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        contents = ((0x14000003).to_bytes(4, "little") +
                    (0x90000001).to_bytes(4, "little") +
                    (0x91000021).to_bytes(4, "little") +
                    (0xd503201f).to_bytes(4, "little"))
        interval = gtirb.ByteInterval(section=section, contents=contents, size=16, address=0x1000)
        branch = gtirb.CodeBlock(offset=0, size=4, byte_interval=interval)
        materialize = gtirb.CodeBlock(offset=4, size=8, byte_interval=interval)
        target = gtirb.CodeBlock(offset=12, size=4, byte_interval=interval)
        symbol = gtirb.Symbol(name="target", payload=target, module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, symbol)
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, symbol)
        interval.symbolic_expressions[8] = gtirb.SymAddrConst(0, symbol)
        decoder = GtirbInstructionDecoder(module.isa)
        pad = PadTransientTargetsPass(section, decoder, (0xd50324df, 0xd280a29f),
                                      arch=AArch64Architecture())
        # The direct branch alone would not pad; the address materialization does.
        self.assertEqual(pad.target_blocks(), {target})

        # Remove the address-taking reference: only the direct branch remains.
        del interval.symbolic_expressions[4]
        del interval.symbolic_expressions[8]
        self.assertEqual(pad.target_blocks(), set())

    def test_pcrel_lo_anchors_are_not_targets(self):
        # auipc a0, %pcrel_hi(target); addi a0, a0, %pcrel_lo(anchor): the LO
        # operand names the AUIPC's own label, so only the target is padded.
        module = gtirb.Module(name="pad", isa=gtirb.Module.ISA.ARM64)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, contents=bytes(16), size=16)
        auipc = gtirb.CodeBlock(offset=0, size=8, byte_interval=interval)
        target = gtirb.CodeBlock(offset=8, size=8, byte_interval=interval)
        attributes = gtirb.SymbolicExpression.Attribute
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name="target", payload=target, module=module),
            {attributes.PCREL, attributes.HI})
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name="anchor", payload=auipc, module=module),
            {attributes.PCREL, attributes.LO})
        pad = PadTransientTargetsPass(section, None, (0x11400013, 0x51400013))
        self.assertEqual(pad.target_blocks(), {target})

    @staticmethod
    def riscv_copy():
        """A RISC-V copy: a direct tail pair (PCREL HI/LO), a direct call pair (PLT),
        a register jump, a return, and the pairs' target."""
        from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder

        module = gtirb.Module(name="rv", isa=gtirb.Module.ISA.ValidButUnsupported,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        gtirb.IR(modules=[module])
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, address=0x1000, contents=bytes.fromhex(
            "17030000" "67000300" "97000000" "e7800000" "67808700" "67800000" "67800000"))
        blocks = {name: gtirb.CodeBlock(offset=offset, size=size, byte_interval=interval)
                  for name, offset, size in (("tail", 0, 8), ("call", 8, 8), ("jump", 16, 4),
                                             ("ret", 20, 4), ("target", 24, 4))}
        attrs = gtirb.SymbolicExpression.Attribute
        target = gtirb.Symbol(name="target", payload=blocks["target"], module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, target, {attrs.PCREL, attrs.HI})
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name=".Lpcrel_hi", payload=blocks["tail"], module=module),
            {attrs.PCREL, attrs.LO})
        interval.symbolic_expressions[8] = gtirb.SymAddrConst(0, target, {attrs.PLT})
        return module, section, blocks, CachedGtirbInstructionDecoder(module.isa)

    def test_direct_pair_targets_get_no_pad(self):
        # Direct calls and jumps do not need a landing pad, and a proven RISC-V
        # pair is direct although its symbol sits on the AUIPC.
        _, section, blocks, decoder = self.riscv_copy()
        pad = PadTransientTargetsPass(section, decoder, RISCV64Architecture.MAGIC_WORDS,
                                      arch=RISCV64Architecture())
        self.assertEqual(pad.target_blocks(), set())

    def test_an_anchor_that_is_also_a_target_keeps_its_pad(self):
        # The %pcrel_lo operand alone does not make the AUIPC block a target, but
        # an indirect branch to it does.
        module, section, blocks, decoder = self.riscv_copy()
        module.ir.cfg.add(gtirb.Edge(blocks["jump"], blocks["tail"],
                                     gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)))
        pad = PadTransientTargetsPass(section, decoder, RISCV64Architecture.MAGIC_WORDS,
                                      arch=RISCV64Architecture())
        self.assertEqual(pad.target_blocks(), {blocks["tail"]})

    def test_direct_transfer_classification(self):
        def instruction(mnemonic):
            return types.SimpleNamespace(mnemonic=mnemonic)

        aarch64 = AArch64Architecture()
        for mnemonic in ("b", "bl", "b.eq", "cbz", "cbnz", "tbz", "tbnz"):
            self.assertTrue(aarch64.is_direct_transfer_instruction(instruction(mnemonic)))
        for mnemonic in ("br", "blr", "ret", "adrp", "add"):
            self.assertFalse(aarch64.is_direct_transfer_instruction(instruction(mnemonic)))

        x64 = X64Architecture()
        for mnemonic in ("call", "jmp", "je", "jne", "loop", "loopne"):
            self.assertTrue(x64.is_direct_transfer_instruction(instruction(mnemonic)))
        for mnemonic in ("ret", "nop", "lea"):
            self.assertFalse(x64.is_direct_transfer_instruction(instruction(mnemonic)))

        riscv64 = RISCV64Architecture()
        for mnemonic in ("j", "jal", "beq", "bgeu", "c.j", "c.beqz"):
            self.assertTrue(riscv64.is_direct_transfer_instruction(instruction(mnemonic)))
        for mnemonic in ("jalr", "ret", "addi", "auipc"):
            self.assertFalse(riscv64.is_direct_transfer_instruction(instruction(mnemonic)))

    @staticmethod
    def marker_module(marker_at_start):
        from test_live_register_preservation import make_module as make_raw_module

        marker = (0xd50324df).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little")
        nop = b"\x1f\x20\x03\xd5"
        contents = (marker + nop * 2) if marker_at_start else (nop * 2 + marker + nop * 2)
        ir, module, first, _, _ = make_raw_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, b"\0" * 4)
        interval = first.byte_interval
        interval.contents = contents
        interval.size = len(contents)
        first.offset, first.size = 0, len(contents)
        return module, first.section, marker

    def test_displaced_pad_moves_to_the_block_start(self):
        module, section, marker = self.marker_module(marker_at_start=False)
        block = min(section.code_blocks, key=lambda candidate: candidate.offset)
        pad = AnchorTransientPadsPass(section, (0xd50324df, 0xd280a29f), padded={block.uuid})
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 1)
        block = min(section.code_blocks, key=lambda candidate: candidate.offset)
        self.assertEqual(bytes(block.contents)[:8], marker)

    def test_only_padded_blocks_are_anchored(self):
        # Pad ownership (Codex review): a marker-like sequence in a block the
        # pad pass did not pad is not a pad, and is left where it is.
        module, section, marker = self.marker_module(marker_at_start=False)
        pad = AnchorTransientPadsPass(section, (0xd50324df, 0xd280a29f))
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 0)
        block = min(section.code_blocks, key=lambda candidate: candidate.offset)
        self.assertEqual(bytes(block.contents)[8:16], marker)

    def test_each_padded_block_takes_only_its_own_pad(self):
        # Three padded blocks in one interval: the first lost its pad, the
        # second and third have theirs behind inserted entry code. The first
        # must not take the second's pad, and both displaced pads move back.
        from test_live_register_preservation import make_module as make_raw_module

        marker = (0xd50324df).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little")
        nop = b"\x1f\x20\x03\xd5"
        entry = (0xd503203f).to_bytes(4, "little")  # inserted code (yield)
        _, module, first, _, _ = make_raw_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, b"\0" * 4)
        interval = first.byte_interval
        parts = [nop * 2, entry + marker + nop, entry * 2 + marker + nop]
        interval.contents = b"".join(parts)
        interval.size = len(interval.contents)
        first.offset, first.size = 0, len(parts[0])
        second = gtirb.CodeBlock(offset=len(parts[0]), size=len(parts[1]), byte_interval=interval)
        third = gtirb.CodeBlock(offset=len(parts[0]) + len(parts[1]), size=len(parts[2]),
                                byte_interval=interval)
        pad = AnchorTransientPadsPass(first.section, (0xd50324df, 0xd280a29f),
                                      padded={first.uuid, second.uuid, third.uuid})
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 2)
        self.assertNotEqual(bytes(first.contents)[:8], marker)
        self.assertEqual(bytes(second.contents)[:8], marker)
        self.assertEqual(bytes(third.contents)[:8], marker)

    def test_a_block_without_its_pad_leaves_the_next_blocks_pad_alone(self):
        # The first padded block lost its pad. The second has entry code with a
        # label in front of its pad, so the pad sits in an unpadded piece. The
        # first must not claim that pad: both would delete the same bytes.
        from test_live_register_preservation import make_module as make_raw_module

        marker = (0xd50324df).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little")
        nop = b"\x1f\x20\x03\xd5"
        landing = (0xd503203f).to_bytes(4, "little") * 2   # inserted entry code
        _, module, first, _, _ = make_raw_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, b"\0" * 4)
        interval = first.byte_interval
        interval.contents = nop * 2 + landing + marker + nop
        interval.size = len(interval.contents)
        first.offset, first.size = 0, 8
        second = gtirb.CodeBlock(offset=8, size=8, byte_interval=interval)
        piece = gtirb.CodeBlock(offset=16, size=12, byte_interval=interval)
        pad = AnchorTransientPadsPass(first.section, (0xd50324df, 0xd280a29f),
                                      padded={first.uuid, second.uuid})
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 1)
        self.assertEqual(bytes(interval.contents), nop * 2 + marker + landing + nop)
        self.assertNotEqual(bytes(first.contents)[:8], marker)
        self.assertEqual(bytes(second.contents)[:8], marker)
        self.assertNotEqual(bytes(piece.contents)[:8], marker)

    def test_a_block_without_its_pad_stops_at_the_next_original_block(self):
        # The first padded block lost its pad, and an unpadded block of the
        # copy holds marker-like bytes before the next padded block. Those
        # bytes are that block's code, not a pad: the search stops at it.
        from test_live_register_preservation import make_module as make_raw_module

        marker = (0xd50324df).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little")
        nop = b"\x1f\x20\x03\xd5"
        _, module, first, _, _ = make_raw_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, b"\0" * 4)
        interval = first.byte_interval
        interval.contents = nop * 2 + marker + nop + marker + nop
        interval.size = len(interval.contents)
        first.offset, first.size = 0, 8
        other = gtirb.CodeBlock(offset=8, size=12, byte_interval=interval)
        second = gtirb.CodeBlock(offset=20, size=12, byte_interval=interval)
        pad = AnchorTransientPadsPass(first.section, (0xd50324df, 0xd280a29f),
                                      padded={first.uuid, second.uuid},
                                      originals={first.uuid, other.uuid, second.uuid})
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 0)
        self.assertEqual(bytes(interval.contents), nop * 2 + marker + nop + marker + nop)

    def test_each_interval_bounds_its_own_search(self):
        # The next original block in another byte interval does not bound the
        # search, even at a lower offset.
        from test_live_register_preservation import make_module as make_raw_module

        marker = (0xd50324df).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little")
        nop = b"\x1f\x20\x03\xd5"
        entry = (0xd503203f).to_bytes(4, "little") * 2
        _, module, first, _, _ = make_raw_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, b"\0" * 4)
        interval = first.byte_interval
        interval.contents = entry + marker + nop
        interval.size = len(interval.contents)
        first.offset, first.size = 0, len(interval.contents)
        other_interval = gtirb.ByteInterval(section=first.section, address=0x8000,
                                            contents=nop + marker + nop)
        gtirb.CodeBlock(offset=0, size=4, byte_interval=other_interval)
        second = gtirb.CodeBlock(offset=4, size=12, byte_interval=other_interval)
        pad = AnchorTransientPadsPass(first.section, (0xd50324df, 0xd280a29f),
                                      padded={first.uuid, second.uuid})
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 1)
        self.assertEqual(bytes(first.contents)[:8], marker)
        self.assertEqual(bytes(second.contents)[:8], marker)

    def test_an_already_marked_target_keeps_its_marker_first(self):
        # A copy target that already starts with the BTI mode's pair gets no
        # pad. Entry code inserted in front of it later must not stay in front.
        from test_live_register_preservation import make_module as make_raw_module
        from gtirb_rewriting import Patch, patch_constraints

        marker = (0xd50324df).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little")
        nop = b"\x1f\x20\x03\xd5"
        _, module, first, _, _ = make_raw_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, b"\0" * 4)
        interval = first.byte_interval
        interval.contents = nop * 2 + marker + nop
        interval.size = len(interval.contents)
        first.offset, first.size = 0, 8
        target = gtirb.CodeBlock(offset=8, size=12, byte_interval=interval)
        module.ir.cfg.add(gtirb.Edge(first, target,
                                     gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)))
        arch, state = AArch64BTIArchitecture(), RewriteState()
        pad = arch.transient_pad_passes(first.section, None, state)[0]
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.padded, 0)
        self.assertIn(target.uuid, state.pads.require("test").padded_blocks)

        @patch_constraints()
        def entry_code(_ctx):
            return "nop\nnop\n"

        context = RewritingContext(module, [])
        context.insert_at(target, 0, Patch.from_function(entry_code))
        context.apply()
        self.assertNotEqual(bytes(target.contents)[:8], marker)
        anchor = arch.transient_anchor_passes(first.section, state)[0]
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            anchor.begin_module(module, [], context)
            context.apply()
        self.assertEqual(anchor.anchored, 1)
        self.assertEqual(bytes(interval.contents)[target.offset:], marker + nop * 3)

    def test_pad_inside_a_later_piece_moves_back(self):
        # A RISC-V restore landing ends with a labelled nop, so the pad sits one
        # word into the piece that the label starts.
        from test_live_register_preservation import make_module as make_raw_module

        marker = (0x11400013).to_bytes(4, "little") + (0x51400013).to_bytes(4, "little")
        landing = (0x00100093).to_bytes(4, "little") * 2
        nop = (0x00000013).to_bytes(4, "little")
        body = (0x00200093).to_bytes(4, "little")
        _, module, first, _, _ = make_raw_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, b"\0" * 4)
        interval = first.byte_interval
        interval.contents = landing + nop + marker + body
        interval.size = len(interval.contents)
        first.offset, first.size = 0, len(landing)
        gtirb.CodeBlock(offset=len(landing), size=len(nop + marker + body), byte_interval=interval)
        pad = AnchorTransientPadsPass(first.section, (0x11400013, 0x51400013), padded={first.uuid})
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 1)
        self.assertEqual(bytes(interval.contents), marker + landing + nop + body)

    def test_pad_pushed_into_a_split_block_moves_back(self):
        # RISC-V restore landings contain labels: inserting one at a padded
        # block's start splits it, and the pad ends up starting the later piece.
        from test_live_register_preservation import make_module as make_raw_module

        marker = (0x11400013).to_bytes(4, "little") + (0x51400013).to_bytes(4, "little")
        landing = (0x00100093).to_bytes(4, "little") * 2   # two inserted words
        body = (0x00000013).to_bytes(4, "little")          # the block's own instruction
        _, module, first, _, _ = make_raw_module(
            AArch64Architecture(), gtirb.Module.ISA.ARM64, b"\0" * 4)
        interval = first.byte_interval
        interval.contents = landing + marker + body
        interval.size = len(interval.contents)
        first.offset, first.size = 0, len(landing)
        split = gtirb.CodeBlock(offset=len(landing), size=len(marker) + len(body),
                                byte_interval=interval)
        words = (0x11400013, 0x51400013)
        pad = AnchorTransientPadsPass(first.section, words, padded={first.uuid})
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 1)
        self.assertEqual(bytes(first.contents)[:8], marker)
        self.assertEqual(bytes(interval.contents), marker + landing + body)
        self.assertNotEqual(bytes(split.contents)[:8], marker)
        # Without knowing the block was padded, the pass leaves the split pad alone.
        self.assertEqual(AnchorTransientPadsPass(first.section, words).padded, frozenset())

    def test_pad_pass_tells_the_anchor_which_blocks_it_padded(self):
        for arch in (AArch64Architecture(), X64Architecture(), RISCV64Architecture()):
            with self.subTest(isa=arch.name):
                module, section, blocks = copy_module()
                state = RewriteState()
                with self.assertRaisesRegex(ProductNotReady, "the transient pad pass, which has not run"):
                    arch.transient_anchor_passes(section, state)
                pad = arch.transient_pad_passes(section, None, state)[0]
                expected = {block.uuid for block in pad.reachable_entries()}
                self.assertTrue(expected)
                with redirect_stdout(io.StringIO()):
                    pad.begin_module(module, [], types.SimpleNamespace(insert_at=lambda *args: None))
                self.assertEqual(state.pads.require("test").padded_blocks, expected)
                anchor = arch.transient_anchor_passes(section, state)[0]
                self.assertEqual(anchor.padded, expected)
                self.assertEqual(anchor.originals,
                                 {block.uuid for block in section.code_blocks if block.size})
                self.assertEqual(anchor.marker_text(), pad.marker_text())

    def test_already_marked_targets_are_owned_but_not_padded(self):
        # The copy's block at offset 16 already starts with the BTI mode's pair:
        # it gets no pad, but the anchor pass and the end-state check still
        # cover it, since later entry code can displace its marker too.
        module, section, blocks = copy_module()
        arch, state = AArch64BTIArchitecture(), RewriteState()
        pad = arch.transient_pad_passes(section, None, state)[0]
        inserted = []
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], types.SimpleNamespace(
                insert_at=lambda block, *args: inserted.append(block)))
        self.assertEqual(set(inserted), {blocks[0], blocks[1]})
        self.assertEqual(state.pads.require("test").padded_blocks,
                         {blocks[0].uuid, blocks[1].uuid, blocks[4].uuid})
        self.assertEqual(arch.transient_anchor_passes(section, state)[0].padded,
                         state.pads.require("test").padded_blocks)

    def test_pad_at_the_block_start_is_left_alone(self):
        module, section, _ = self.marker_module(marker_at_start=True)
        block = min(section.code_blocks, key=lambda candidate: candidate.offset)
        pad = AnchorTransientPadsPass(section, (0xd50324df, 0xd280a29f), padded={block.uuid})
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertEqual(pad.anchored, 0)

    def test_zero_sized_label_targets_insert_at_the_real_block(self):
        module = gtirb.Module(name="pad", isa=gtirb.Module.ISA.ARM64,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        ir = gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, contents=bytes(16), size=16)
        real = gtirb.CodeBlock(offset=0, size=8, byte_interval=interval)
        label = gtirb.CodeBlock(offset=0, size=0, byte_interval=interval)
        end_label = gtirb.CodeBlock(offset=16, size=0, byte_interval=interval)
        alias = gtirb.Symbol(name="alias", payload=label, module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, alias)
        interval.symbolic_expressions[8] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name="end", payload=end_label, module=module))
        pad = PadTransientTargetsPass(section, None, (0xd280229f, 0xd280a29f))
        # The shared-address label is padded through the real block; the
        # trailing label has no instruction to pad and is skipped.
        self.assertEqual(pad.target_blocks(), {real})
        self.assertEqual(ir, section.ir)

        # An insertion at the real block's start can go in front of the label,
        # so the label's symbol must name the real block to keep naming the pad.
        context = RewritingContext(module, [])
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], context)
            context.apply()
        marker = (0xd280229f).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little")
        self.assertIs(alias.referent, real)
        self.assertEqual(bytes(real.contents)[:8], marker)

    def test_alias_labels_hand_over_symbols_and_function_rows(self):
        module = gtirb.Module(name="pad", isa=gtirb.Module.ISA.ARM64,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, contents=bytes(24), size=24)
        real = gtirb.CodeBlock(offset=0, size=8, byte_interval=interval)
        label = gtirb.CodeBlock(offset=0, size=0, byte_interval=interval)
        other_real = gtirb.CodeBlock(offset=8, size=16, byte_interval=interval)
        bystander = gtirb.CodeBlock(offset=8, size=0, byte_interval=interval)
        names = [gtirb.Symbol(name=name, payload=label, module=module) for name in ("a", "b")]
        tail = gtirb.Symbol(name="tail", payload=label, at_end=True, module=module)
        untouched = gtirb.Symbol(name="untouched", payload=bystander, module=module)
        interval.symbolic_expressions[16] = gtirb.SymAddrConst(0, names[0])
        function = gtirb.Symbol(name="function", payload=label, module=module).uuid
        for table in ("functionEntries", "functionBlocks"):
            module.aux_data[table] = gtirb.AuxData({function: {label}}, "mapping<UUID,set<UUID>>")
        pad = PadTransientTargetsPass(section, None, (0xd280229f, 0xd280a29f))
        context = RewritingContext(module, [])
        output = io.StringIO()
        with redirect_stdout(output):
            pad.begin_module(module, [], context)
            context.apply()
        self.assertIn("(1 zero-size label aliases)", output.getvalue())
        for symbol in names + [tail]:
            self.assertIs(symbol.referent, real)
            self.assertFalse(symbol.at_end)
        # A label at another block's offset that no branch can reach keeps its symbol.
        self.assertIs(untouched.referent, bystander)
        self.assertNotEqual(bytes(other_real.contents)[:8],
                            (0xd280229f).to_bytes(4, "little") + (0xd280a29f).to_bytes(4, "little"))
        for table in ("functionEntries", "functionBlocks"):
            self.assertEqual(module.aux_data[table].data[function], {label, real})

    def test_software_mode_pads_every_return_site(self):
        # Blocks: a call with a fallthrough, a call the lift thinks never
        # returns, a direct branch, and the three blocks that follow them.
        module = gtirb.Module(name="pad", isa=gtirb.Module.ISA.ARM64)
        ir = gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, contents=b"\x1f\x20\x03\xd5" * 6, size=24)
        call, after_call, noreturn, after_noreturn, branch, after_branch = (
            gtirb.CodeBlock(offset=offset, size=4, byte_interval=interval)
            for offset in range(0, 24, 4))
        callee = gtirb.ProxyBlock(module=module)
        for source, target, kind in ((call, callee, gtirb.Edge.Type.Call),
                                     (call, after_call, gtirb.Edge.Type.Fallthrough),
                                     (noreturn, callee, gtirb.Edge.Type.Call),
                                     (branch, call, gtirb.Edge.Type.Branch)):
            ir.cfg.add(gtirb.Edge(source, target, gtirb.Edge.Label(kind, direct=True)))
        software = PadTransientTargetsPass(section, None, (0xd280229f, 0xd280a29f),
                                           pad_return_sites=True)
        self.assertEqual(software.target_blocks(), {after_call, after_noreturn})
        combined = PadTransientTargetsPass(section, None, (0xd280229f, 0xd280a29f))
        self.assertEqual(combined.target_blocks(), set())

    def test_only_the_combined_mode_leaves_return_sites_unpadded(self):
        _, section, _ = copy_module()
        for arch in (AArch64Architecture(), X64Architecture(), RISCV64Architecture()):
            with self.subTest(isa=arch.name):
                self.assertTrue(arch.transient_pad_passes(section, None, RewriteState())[0].pad_return_sites)
        self.assertFalse(AArch64BTIArchitecture().transient_pad_passes(section, None, RewriteState())[0].pad_return_sites)


if __name__ == "__main__":
    unittest.main()
