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
    def test_only_reachable_unmarked_targets(self):
        _, section, blocks = copy_module()
        pad = PadTransientTargetsPass(section, None, (0xd50324df, 0xd280a29f))
        # A is only named by a data symbol? No: both symbols name code blocks;
        # only the indirect edge target and no already-marked block are padded.
        self.assertEqual({block.offset for block in pad.target_blocks()}, {0, 4})

    def test_wiring_uses_the_mode_marker(self):
        _, section, _ = copy_module()
        bti = AArch64BTIArchitecture().transient_pad_passes(section, None)[0]
        self.assertEqual(bti.marker_words, (0xd50324df, 0xd280a29f))
        software = AArch64Architecture().transient_pad_passes(section, None)[0]
        self.assertEqual(software.marker_words, AArch64Architecture.MAGIC_WORDS)

    def test_every_isa_pads_the_copy_for_the_window_predicate(self):
        _, section, _ = copy_module()
        for arch in (AArch64Architecture(), X64Architecture(), RISCV64Architecture()):
            with self.subTest(isa=arch.name):
                pad = arch.transient_pad_passes(section, None)[0]
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
        pad = AnchorTransientPadsPass(section, (0xd50324df, 0xd280a29f))
        context = RewritingContext(module, [])
        pad.begin_module(module, [], context)
        context.apply()
        self.assertEqual(pad.anchored, 1)
        block = min(section.code_blocks, key=lambda candidate: candidate.offset)
        self.assertEqual(bytes(block.contents)[:8], marker)

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
        module, section, blocks = copy_module()
        arch = AArch64Architecture()
        pad = arch.transient_pad_passes(section, None)[0]
        expected = {block.uuid for block in pad.target_blocks()}
        self.assertTrue(expected)
        with redirect_stdout(io.StringIO()):
            pad.begin_module(module, [], types.SimpleNamespace(insert_at=lambda *args: None))
        self.assertEqual(arch.transient_padded_blocks, expected)
        self.assertEqual(arch.transient_anchor_passes(section)[0].padded, expected)

    def test_pad_at_the_block_start_is_left_alone(self):
        module, section, _ = self.marker_module(marker_at_start=True)
        pad = AnchorTransientPadsPass(section, (0xd50324df, 0xd280a29f))
        context = RewritingContext(module, [])
        pad.begin_module(module, [], context)
        context.apply()
        self.assertEqual(pad.anchored, 0)

    def test_zero_sized_label_targets_insert_at_the_real_block(self):
        module = gtirb.Module(name="pad", isa=gtirb.Module.ISA.ARM64)
        ir = gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module)
        interval = gtirb.ByteInterval(section=section, contents=bytes(16), size=16)
        real = gtirb.CodeBlock(offset=0, size=8, byte_interval=interval)
        label = gtirb.CodeBlock(offset=0, size=0, byte_interval=interval)
        end_label = gtirb.CodeBlock(offset=16, size=0, byte_interval=interval)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name="alias", payload=label, module=module))
        interval.symbolic_expressions[8] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name="end", payload=end_label, module=module))
        pad = PadTransientTargetsPass(section, None, (0xd280229f, 0xd280a29f))
        # The shared-address label is padded through the real block; the
        # trailing label has no instruction to pad and is skipped.
        self.assertEqual(pad.target_blocks(), {real})
        self.assertEqual(ir, section.ir)

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
                self.assertTrue(arch.transient_pad_passes(section, None)[0].pad_return_sites)
        self.assertFalse(AArch64BTIArchitecture().transient_pad_passes(section, None)[0].pad_return_sites)


if __name__ == "__main__":
    unittest.main()
