"""Real ELF -> lift -> instrument -> relink line-table probes on every ISA.

Unresolved runtime symbols are allowed in these non-executed line-table probes;
the other runtime tests cover executing instrumentation.
"""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

import gtirb
from elftools.elf.elffile import ELFFile
from gtirb_rewriting.decoder import GtirbInstructionDecoder

from teapot.arch import get_arch
from teapot.debug_lines import SourceLines, _filename, _asm_string, emit_source_lines
from teapot.pipeline import TeapotPipeline
from teapot.utils.serialization import compact_for_pprinter
from runtime_contract_support import fixture_contract, fixture_contract_path


class SourceLineTests(unittest.TestCase):
    def _run(self, command, root):
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, f"{command}\n{result.stdout}\n{result.stderr}")
        return result

    def test_file_tables_and_escaping(self):
        cu = SimpleNamespace(get_top_DIE=lambda: SimpleNamespace(attributes={
            "DW_AT_comp_dir": SimpleNamespace(value=b"/build")}))
        for version, index in ((4, 1), (5, 0)):
            program = SimpleNamespace(header={
                "version": version,
                "file_entry": [SimpleNamespace(name=b"first.c", dir_index=0)],
                "include_directory": [b"/build"],
            })
            self.assertEqual(_filename(cu, program, index), "/build/first.c")
        for name, expected in ((b"/source/absolute.c", "/source/absolute.c"),
                               (b"relative.c", "/build/relative.c")):
            program = SimpleNamespace(header={"version": 5,
                "file_entry": [SimpleNamespace(name=name, dir_index=None)]})
            self.assertEqual(_filename(cu, program, 0), expected)
        self.assertEqual(_asm_string('a"b\\c\n'), '"a\\042b\\134c\\012"')

    def test_inserted_and_replaced_code_does_not_inherit_source_lines(self):
        from gtirb_rewriting import Pass, PassManager, Patch, Constraints
        from teapot.arch import X64Architecture
        from test_live_register_preservation import make_module
        ir, module, block, _, _ = make_module(
            X64Architecture(), gtirb.Module.ISA.X64, b"\x90\x90\xc3")
        # Populate capture endpoints without an ELF: each one-byte instruction
        # has its begin/end at the same byte, a common source of off-by-one bugs.
        lines = SourceLines.__new__(SourceLines)
        lines.module = module
        lines.locations = [("/source.c", n, 0, 1, 0) for n in (10, 20, 30)]
        module.aux_data["comments"] = gtirb.AuxData({
            gtirb.Offset(block, offset): f"TEAPOT_SOURCE_LINE:{offset}:0\nTEAPOT_SOURCE_LINE:{offset}:1"
            for offset in range(3)}, "mapping<Offset,string>")

        class Replace(Pass):
            def begin_module(self, m, functions, context):
                context.insert_at(block, 0, Patch.from_function(lambda ctx: "nop", Constraints()))
                context.replace_at(block, 1, 1, Patch.from_function(lambda ctx: "nop; nop", Constraints()))

        manager = PassManager()
        manager.add(Replace())
        manager.run(ir)
        lines.finish(GtirbInstructionDecoder(module.isa))
        metadata = json.loads(module.aux_data["teapotSourceLines"].data)
        names = {s.name: s for s in module.symbols}
        intervals = []
        for name, value in metadata["labels"].items():
            symbol = names[name]
            pos = symbol.referent.offset + (symbol.referent.size if symbol.at_end else 0)
            intervals.append((pos, 0 if value is None else value[1]))
        self.assertEqual(sorted(intervals), [(1, 10), (2, 0), (4, 30), (5, 0)])

    def _check_target(self, compiler, version):
        for tool in (compiler, "ddisasm", "gtirb-pprinter"):
            if not shutil.which(tool):
                self.skipTest(f"{tool} unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").mkdir()
            (root / "two").mkdir()
            sources = {
                "one/unit.c": "int helper(int);\nint main(void) {\n  int a = helper(7);\n  return a + 1;\n}\n",
                "two/unit.c": "int helper(int value) {\n  int doubled = value * 2;\n  return doubled - 1;\n}\n",
            }
            for name, source in sources.items():
                (root / name).write_text(source)
            self._run([compiler, f"-gdwarf-{version}", "-O0", "-fno-stack-protector",
                       "-fno-pie", "-no-pie", "-nostdlib", "-Wl,-e,main",
                       *(["-Wl,--emit-relocs"] if version == 5 else []),
                       *sources, "-o", "input"], root)
            self._run(["ddisasm", "input", "--ir", "input.gtirb", "-j", "2"], root)
            ir = gtirb.IR.load_protobuf(root / "input.gtirb")
            module = ir.modules[0]
            arch = get_arch(module)
            block = next(b for b in module.code_blocks if b.size and b.section.name == ".text")
            module.aux_data["comments"] = gtirb.AuxData(
                {gtirb.Offset(block, 0): "existing analysis comment"}, "mapping<Offset,string>")
            if version == 4:
                lines = SourceLines(module, root / "input", arch.name, GtirbInstructionDecoder(module.isa))
                TeapotPipeline(ir, runtime_contract=fixture_contract(arch.name)).run()
                before = {bi.uuid: (bytes(bi.contents), copy.copy(dict(bi.symbolic_expressions)))
                          for bi in module.byte_intervals}
                lines.finish(GtirbInstructionDecoder(module.isa))
                self.assertEqual(before, {bi.uuid: (bytes(bi.contents), dict(bi.symbolic_expressions))
                                          for bi in module.byte_intervals})
                compact_for_pprinter(ir)
                ir.save_protobuf(root / "instrumented.gtirb")
            else:
                # Exercise both public CLI stages, including compact serialization.
                ir.save_protobuf(root / "input.gtirb")
                self._run([sys.executable, "-B", "-m", "teapot.cmdline", "--compact-output",
                           "--runtime-contract", str(fixture_contract_path(arch.name)),
                           "--debug-source", "input", "input.gtirb", "instrumented.gtirb"], root)
                ir = gtirb.IR.load_protobuf(root / "instrumented.gtirb")
                module = ir.modules[0]
            self.assertTrue(any("existing analysis comment" in value
                                for value in module.aux_data["comments"].data.values()))
            self._run(["gtirb-pprinter", "--ir", "instrumented.gtirb", "--asm", "raw.S"], root)
            if version == 4:
                output = emit_source_lines(module, (root / "raw.S").read_text())
                (root / "lines.S").write_text(output)
            else:
                self._run([sys.executable, "-B", "-m", "teapot.debug_lines",
                           "instrumented.gtirb", "raw.S", "lines.S"], root)
            self._run([compiler, "-nostdlib", "-no-pie", "-Wa,-L", "-Wl,-e,main",
                       "-Wl,--discard-none,--unresolved-symbols=ignore-all", "lines.S", "-o", "rewritten"], root)
            with (root / "rewritten").open("rb") as stream:
                elf = ELFFile(stream)
                by_name = {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols()}
                found, rows = {}, set()
                dwarf = elf.get_dwarf_info()
                for cu in dwarf.iter_CUs():
                    program = dwarf.line_program_for_CU(cu)
                    if program is None:
                        continue
                    for entry in program.get_entries():
                        state = entry.state
                        if state is None or state.end_sequence or not state.line:
                            continue
                        name = _filename(cu, program, state.file)
                        found.setdefault(name, set()).add(state.line)
                        rows.add((state.address, name, state.line))
                for name in sources:
                    self.assertTrue({2, 3}.issubset(found[str(root / name)]), found)
                transient = elf.get_section_by_name(".teapot_transient")
                self.assertIsNotNone(transient)
                lo, hi = transient["sh_addr"], transient["sh_addr"] + transient["sh_size"]
                self.assertFalse(any(lo <= address < hi for address, _, _ in rows))
                metadata = json.loads(module.aux_data["teapotSourceLines"].data)
                expected = {(by_name[name], metadata["files"][value[0]-1], value[1])
                            for name, value in metadata["labels"].items()
                            if value is not None and name in by_name}
                self.assertTrue(expected)
                self.assertTrue(expected.issubset(rows), expected - rows)

    def test_x64_dwarf4_and_5(self):
        for version in (4, 5):
            with self.subTest(dwarf=version):
                self._check_target("gcc", version)

    def test_aarch64_dwarf4_and_5(self):
        for version in (4, 5):
            with self.subTest(dwarf=version):
                self._check_target("aarch64-linux-gnu-gcc", version)

    def test_riscv64_dwarf4_and_5(self):
        for version in (4, 5):
            with self.subTest(dwarf=version):
                self._check_target("riscv64-linux-gnu-gcc", version)


if __name__ == "__main__":
    unittest.main()
