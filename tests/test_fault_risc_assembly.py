import unittest
import struct
import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
from unittest.mock import patch

import gtirb

from teapot.arch import RISCV64Architecture
from teapot.fault_risc_assembly import AUX, PREFIX, SCHEMA, emit_fault_risc_scopes, fault_risc_assembler_flags
from test_live_register_preservation import make_module


class RiscAssemblyScopeTests(unittest.TestCase):
    def fixture(self):
        _, module, block, _, _ = make_module(
            RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported, bytes(16))
        block.section.name = ".teapot_transient"
        begin = gtirb.Symbol(PREFIX + "begin_" + "a" * 32, payload=block, module=module)
        tail = gtirb.CodeBlock(size=0, offset=16, byte_interval=block.byte_interval)
        end = gtirb.Symbol(PREFIX + "end_" + "a" * 32, payload=tail, module=module)
        info = module.aux_data.setdefault("elfSymbolInfo", gtirb.AuxData({},
            "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"))
        info.data[begin] = info.data[end] = (0, "NOTYPE", "LOCAL", "DEFAULT", 0)
        module.aux_data[AUX] = gtirb.AuxData({begin: end}, SCHEMA)
        before = ".text\naddi a0,a0,1\n.section .teapot_transient,\"ax\",@progbits\nld a1,0(a2)\n"
        inside = begin.name + ":\nauipc t0,%pcrel_hi(value)\naddi t0,t0,%pcrel_lo(" + begin.name + ")\n"
        after = end.name + ":\nld a3,0(a4)\n.data\nvalue: .8byte 0\n"
        return module, begin, end, before, inside, after

    def test_only_owned_span_changes_and_both_sides_survive(self):
        module, begin, end, before, inside, after = self.fixture()
        result = emit_fault_risc_scopes(module, before + inside + after)
        self.assertEqual(result, before + ".option push\n.option norvc\n.option norelax\n" +
                         inside + ".option pop\n" + after)
        self.assertEqual(result.count(".option push"), 1)
        self.assertEqual(result.count(".option pop"), 1)
        with self.assertRaises(ValueError):
            emit_fault_risc_scopes(module, result)

    def test_disabled_byte_identity(self):
        module, begin, end, *_ = self.fixture()
        del module.aux_data[AUX]
        module.symbols.discard(begin); module.symbols.discard(end)
        for assembly in ("", ".text\r\naddi a0,a0,1\r\n", ".option rvc\n# no newline"):
            self.assertEqual(emit_fault_risc_scopes(module, assembly), assembly)
        original_argv = ["riscv64-linux-gnu-gcc", "-c", "raw.S", "-o", "component.o", "-mno-relax", "-Wa,-mno-relax"]
        self.assertEqual([*original_argv, *fault_risc_assembler_flags(module)], original_argv)

    def emitted(self, isa="riscv64"):
        from test_fault_risc_windows import RiscWindowEmissionTests
        from teapot.preprocess.fault_risc_windows import add_risc_fault_windows
        module, section, bounds, manager, _ = RiscWindowEmissionTests().fixture(isa)
        table = add_risc_fault_windows(module, section, bounds, manager, isa)
        return module, table.referent.byte_interval

    def test_assembler_flag_only_for_checked_emitted_rv_v4(self):
        module, _ = self.emitted()
        self.assertEqual(fault_risc_assembler_flags(module), ("-Wa,--no-pad-sections",))
        module, _ = self.emitted("aarch64")
        self.assertEqual(fault_risc_assembler_flags(module), ())
        module, *_ = self.fixture()  # scope metadata alone is insufficient
        with self.assertRaisesRegex(ValueError, "emitted v4 table"):
            fault_risc_assembler_flags(module)

    def test_assembler_flag_rejects_malformed_table_and_ownership(self):
        for change in ("missing", "duplicate", "short", "version", "entry_size", "count", "flags", "reserved", "scope"):
            module, interval = self.emitted()
            data = bytearray(interval.contents)
            if change == "missing": module.sections.discard(interval.section)
            elif change == "duplicate": gtirb.Section(name=interval.section.name, module=module)
            elif change == "short": data = data[:16]
            elif change == "version": struct.pack_into("<H", data, 4, 3)
            elif change == "entry_size": struct.pack_into("<I", data, 8, 16)
            elif change == "count": struct.pack_into("<I", data, 12, 1)
            elif change == "flags": struct.pack_into("<I", data, 16, 0)
            elif change == "reserved": data[88] = 1
            elif change == "scope": del module.aux_data[AUX]
            interval.contents = bytes(data)
            with self.subTest(change=change), self.assertRaises(ValueError):
                fault_risc_assembler_flags(module)

    def test_component_argv_preserves_disabled_arguments(self):
        from experiments.reusable_libraries.rewrite_components import component_assembler_argv
        plain, begin, end, *_ = self.fixture()
        del plain.aux_data[AUX]
        plain.symbols.discard(begin); plain.symbols.discard(end)
        for isa, storage, extra in (("RISCV64", "asan", ["-mno-relax", "-Wa,-mno-relax"]),
                                     ("ARM64", "mte", ["-march=armv8.5-a+memtag"]),
                                     ("X64", "asan", [])):
            expected = ["cc", "-c", "raw.S", "-o", "component.o", *extra]
            self.assertEqual(component_assembler_argv(plain, "cc", "raw.S", "component.o", isa, storage), expected)
        owned, _ = self.emitted()
        self.assertEqual(component_assembler_argv(owned, "cc", "raw.S", "component.o", "RISCV64", "asan"),
                         ["cc", "-c", "raw.S", "-o", "component.o", "-mno-relax", "-Wa,-mno-relax",
                          "-Wa,--no-pad-sections"])

    def test_preassembly_clis_report_only_metadata_selected_flag(self):
        from teapot import fault_risc_assembly, debug_lines
        for enabled in (False, True):
            module, _ = self.emitted() if enabled else (self.fixture()[0], None)
            if enabled:
                begin, end = next(iter(module.aux_data[AUX].data.items()))
                raw = '.section .teapot_transient,"ax",@progbits\n' + begin.name + ':\n.long 0\n' + end.name + ':\n'
            else:
                del module.aux_data[AUX]
                for symbol in tuple(module.symbols):
                    if symbol.name.startswith(PREFIX): module.symbols.discard(symbol)
                raw = ".text\nret\n"
            for cli in (fault_risc_assembly, debug_lines):
                with self.subTest(enabled=enabled, cli=cli.__name__), tempfile.TemporaryDirectory() as directory:
                    source, output = Path(directory) / "raw.S", Path(directory) / "ready.S"
                    source.write_text(raw)
                    stdout = io.StringIO()
                    with patch("sys.argv", [cli.__name__, "input.gtirb", str(source), str(output)]), \
                         patch.object(gtirb.IR, "load_protobuf", return_value=module.ir), \
                         patch.object(debug_lines, "emit_source_lines", return_value=raw), redirect_stdout(stdout):
                        cli.main()
                    self.assertEqual("-Wa,--no-pad-sections" in stdout.getvalue(), enabled)
                    if not enabled:
                        self.assertEqual(stdout.getvalue(), "")
                        self.assertEqual(output.read_text(), raw)

    def test_missing_duplicate_malformed_wrong_section_and_nested_refuse(self):
        module, begin, end, before, inside, after = self.fixture()
        original = before + inside + after
        mutants = (
            original.replace(begin.name + ":\n", ""),
            original.replace(end.name + ":\n", ""),
            original + begin.name + ":\n",
            original.replace(begin.name + ":", begin.name + ": nop"),
            original.replace(begin.name + ":", PREFIX + "begin_" + "b" * 32 + ":"),
            original.replace(".section .teapot_transient,\"ax\",@progbits", ".text"),
            before + ".option push\n" + inside + after,
            before + inside + ".option rvc\n" + after,
            before + inside + ".section .other\n" + after,
            before + inside + ".previous\n" + after,
            before + inside + "nop; .option rvc\n" + after,
            before + inside + ".set " + end.name + ", .\n",
            before + inside + ".global " + end.name + "\n" + after,
            before + inside + ".include \"extra.s\"\n" + after,
            before + inside + ".if 0\n" + after,
        )
        for mutant in mutants:
            with self.subTest(mutant=mutant), self.assertRaises(ValueError):
                emit_fault_risc_scopes(module, mutant)

    def test_ownership_metadata_must_match_unique_local_boundaries(self):
        for change in ("missing", "empty", "type", "isa", "end_identity", "alias", "duplicate", "order", "global"):
            module, begin, end, before, inside, after = self.fixture()
            if change == "missing": del module.aux_data[AUX]
            elif change == "empty": module.aux_data[AUX].data = {}
            elif change == "type": module.aux_data[AUX].type_name = "string"
            elif change == "isa": module.aux_data["archInfo"].data["ISA"] = "RISCV32"
            elif change == "end_identity": end.name = PREFIX + "end_" + "b" * 32
            elif change == "alias": begin.at_end = True
            elif change == "duplicate": gtirb.Symbol(begin.name, payload=begin.referent, module=module)
            elif change == "order": end.referent.offset = 0
            elif change == "global": module.aux_data["elfSymbolInfo"].data[begin] = (0, "NOTYPE", "GLOBAL", "DEFAULT", 0)
            with self.subTest(change=change), self.assertRaises(ValueError):
                emit_fault_risc_scopes(module, before + inside + after)


if __name__ == "__main__":
    unittest.main()
