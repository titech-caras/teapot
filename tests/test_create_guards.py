"""The guard bounds always print as global symbols."""
import unittest

import gtirb

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.preprocess.create_guards import create_guards

ELF_SYMBOL_INFO = "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"


def guard_section():
    module = gtirb.Module(name="guards", isa=gtirb.Module.ISA.X64,
                          file_format=gtirb.Module.FileFormat.ELF)
    gtirb.IR(modules=[module])
    section = gtirb.Section(name=".teapot_guards", module=module)
    gtirb.ByteInterval(section=section)
    return module, section


class CreateGuardsTests(unittest.TestCase):
    def assert_global_bounds(self, info, start, end, count):
        self.assertEqual(start.name, "__guard_start" + SYMBOL_SUFFIX)
        self.assertEqual(end.name, "__guard_end" + SYMBOL_SUFFIX)
        self.assertEqual(info[start], (4 * count, "OBJECT", "GLOBAL", "DEFAULT", 0))
        self.assertEqual(info[end], (0, "OBJECT", "GLOBAL", "DEFAULT", 0))

    def test_bounds_are_global_without_a_symbol_table(self):
        module, section = guard_section()
        start, end = create_guards(section, 3)
        table = module.aux_data["elfSymbolInfo"]
        self.assertEqual(table.type_name, ELF_SYMBOL_INFO)
        self.assertEqual(set(table.data), {start, end})
        self.assert_global_bounds(table.data, start, end, 3)

    def test_bounds_join_an_existing_symbol_table(self):
        module, section = guard_section()
        other = gtirb.Symbol(name="other", module=module)
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            {other: (0, "FUNC", "LOCAL", "DEFAULT", 1)}, ELF_SYMBOL_INFO)
        start, end = create_guards(section, 2)
        table = module.aux_data["elfSymbolInfo"].data
        self.assertEqual(table[other], (0, "FUNC", "LOCAL", "DEFAULT", 1))
        self.assert_global_bounds(table, start, end, 2)
        self.assertEqual(len(next(iter(section.byte_intervals)).contents), 8)


if __name__ == "__main__":
    unittest.main()
