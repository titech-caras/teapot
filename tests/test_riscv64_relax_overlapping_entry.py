"""A jump-only block can need both a new entry and a jump replacement."""

import unittest

import gtirb
from gtirb_rewriting.abi import _ABIS

from teapot.arch.riscv64.architecture import RISCV64Architecture
from teapot.datacls.copied_section_mapping import CopiedSectionMapping


def build_jump_cycle(compressed=False):
    ir = gtirb.IR()
    module = gtirb.Module(
        name="jump-cycle", isa=gtirb.Module.ISA.ValidButUnsupported,
        file_format=gtirb.Module.FileFormat.ELF,
        byte_order=gtirb.Module.ByteOrder.Little, ir=ir,
    )
    module.aux_data["archInfo"] = gtirb.AuxData(
        {"ISA": "RISCV64"}, "mapping<string,string>")
    gtirb.Symbol("scratchpad", payload=gtirb.ProxyBlock(module=module), module=module)
    section = gtirb.Section(
        name=".teapot_transient", module=module,
        flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Readable},
    )
    contents = bytes.fromhex("01a0" if compressed else "6f000000")
    blocks = []
    for address in (0x400000, 0x800000):
        interval = gtirb.ByteInterval(address=address, contents=contents, section=section)
        blocks.append(gtirb.CodeBlock(size=len(contents), byte_interval=interval))
    symbols = [gtirb.Symbol(name, payload=block, module=module)
               for name, block in zip(("cycle_a", "cycle_b"), blocks)]
    for block, target in zip(blocks, reversed(symbols)):
        block.byte_interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, target, set())
        ir.cfg.add(gtirb.Edge(block, target.referent,
                             gtirb.Edge.Label(gtirb.Edge.Type.Branch)))
    module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData(
        {gtirb.Offset(b.byte_interval, 0): len(contents) for b in blocks},
        "mapping<Offset,uint64_t>",
    )
    return ir, module, section, blocks


class RelaxOverlappingEntryTests(unittest.TestCase):
    def test_jump_only_targets_accept_entry_before_replacement(self):
        arch = RISCV64Architecture()
        arch.register_abi(_ABIS)
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                ir, module, section, _ = build_jump_cycle(compressed)
                adjustments = arch.relax_late_branches(
                    module=module, text_section=section, transient_section=section,
                    text_transient_mapping=CopiedSectionMapping({}, {}, {}),
                    landing_pad_targets=set(),
                    run_pass_manager=lambda manager, label: manager.run(ir),
                )
                self.assertEqual(adjustments, (2, 0))
                for name in ("cycle_a", "cycle_b"):
                    target = next(module.symbols_named(name)).referent
                    entry_name = arch.landing_pad_entry_label(target.uuid)
                    self.assertEqual(len(list(module.symbols_named(entry_name))), 1)



if __name__ == "__main__":
    unittest.main()
