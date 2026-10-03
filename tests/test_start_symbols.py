"""A branch to a block's start must name its start, never a label at its end."""
import unittest

import gtirb

from teapot.arch.x64.architecture import X64Architecture
from teapot.utils.misc import get_or_insert_symbol


def module_with_interval(contents):
    module = gtirb.Module(name="labels", isa=gtirb.Module.ISA.X64,
                          file_format=gtirb.Module.FileFormat.ELF,
                          byte_order=gtirb.Module.ByteOrder.Little)
    ir = gtirb.IR(modules=[module])
    section = gtirb.Section(name=".text", module=module,
                            flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable})
    interval = gtirb.ByteInterval(address=0x1000, section=section, contents=contents)
    return ir, module, interval


class StartSymbolTests(unittest.TestCase):
    def test_a_block_with_only_an_end_label_gets_a_start_label(self):
        _, module, interval = module_with_interval(b"\x90\x90\xc3")
        block = gtirb.CodeBlock(size=3, byte_interval=interval)
        end = gtirb.Symbol(name="after", payload=block, at_end=True, module=module)
        symbol = get_or_insert_symbol(".L__start", block, module)
        self.assertIsNot(symbol, end)
        self.assertEqual((symbol.name, symbol.referent, symbol.at_end), (".L__start", block, False))
        # Asked again, the start label exists now.
        self.assertIs(get_or_insert_symbol(".L__other", block, module), symbol)

    def test_among_start_labels_the_choice_is_by_name(self):
        _, module, interval = module_with_interval(b"\x90\xc3")
        block = gtirb.CodeBlock(size=2, byte_interval=interval)
        gtirb.Symbol(name="a_end", payload=block, at_end=True, module=module)
        for name in ("zeta", "beta", "gamma"):
            gtirb.Symbol(name=name, payload=block, module=module)
        self.assertEqual(get_or_insert_symbol(".L__new", block, module).name, "beta")

    def test_relaxed_jrcxz_to_a_target_with_only_an_end_label_lands_on_its_start(self):
        # jrcxz far; 300 nops; far: ret. The target has a label only at its
        # end, and the branch operand is not symbolic; the relaxed sequence
        # must still jump to the target's first byte.
        ir, module, interval = module_with_interval(b"\xe3\x00" + b"\x90" * 300 + b"\xc3")
        branch = gtirb.CodeBlock(size=2, byte_interval=interval)
        fallthrough = gtirb.CodeBlock(size=300, offset=2, byte_interval=interval)
        target = gtirb.CodeBlock(size=1, offset=302, byte_interval=interval)
        end = gtirb.Symbol(name="past_target", payload=target, at_end=True, module=module)
        for name, schema in (("functionEntries", "mapping<UUID,set<UUID>>"),
                             ("functionBlocks", "mapping<UUID,set<UUID>>"),
                             ("functionNames", "mapping<UUID,UUID>"),
                             ("elfSymbolInfo", "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")):
            module.aux_data[name] = gtirb.AuxData({}, schema)
        module.aux_data["sectionProperties"] = gtirb.AuxData(
            {interval.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
        ir.cfg.update({
            gtirb.Edge(branch, target, gtirb.Edge.Label(
                type=gtirb.Edge.Type.Branch, conditional=True, direct=True)),
            gtirb.Edge(branch, fallthrough, gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough))})
        X64Architecture().relax_conditional_branches(module, direct_pads={})
        used = [expression.symbol for interval in module.byte_intervals
                for expression in interval.symbolic_expressions.values()
                if isinstance(expression, gtirb.SymAddrConst) and expression.symbol.referent is target]
        self.assertTrue(used)
        self.assertNotIn(end, used)
        self.assertTrue(all(not symbol.at_end for symbol in used))


if __name__ == "__main__":
    unittest.main()
