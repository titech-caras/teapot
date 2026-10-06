"""The final component link keeps every contract record, and validate_link compares them."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

from experiments.reusable_libraries.rewrite_components import component_layout
from experiments.reusable_libraries.validate_link import contract_records, validate_contract_records

FINGERPRINT = "0123456789abcdef"
ANCHOR = "__libcheckpoint_contract_v2_" + FINGERPRINT


def record(section, kind, fingerprint, capabilities, abi, *, anchor=None, label=None, component=None,
           policy=None):
    """Assembly for one contract record (libcheckpoint's runtime_contract.h)."""
    payload = json.dumps(dict({"abi": abi}, **({"component": component} if component else {}),
                              **({"policy": policy} if policy is not None else {}))).encode()
    lines = [f'.section {section},"a",@progbits', ".balign 8"]
    if label:
        lines += [f".global {name}" for name in label] + [f"{name}:" for name in label]
    lines += [".4byte 0x54435054", ".2byte 2", f".2byte {kind}", ".4byte 48", f".4byte {len(payload)}",
              f".8byte 0x{fingerprint}", f".8byte {capabilities}", f".8byte {anchor or 0}",
              ".8byte 0", ".byte " + ",".join(str(byte) for byte in payload), ".balign 8, 0"]
    return "\n".join(lines) + "\n"


def raw_record(kind, json_bytes, json_size=None):
    """One record's bytes, without the padding that rounds it to 8 bytes."""
    header = struct.pack("<IHHIIQQQQ", 0x54435054, 2, kind, 48,
                         len(json_bytes) if json_size is None else json_size, int(FINGERPRINT, 16), 0, 0, 0)
    return header + json_bytes


class FakeSection(dict):
    def __init__(self, data, address=0x1000):
        super().__init__(sh_addr=address)
        self._data = data

    def data(self):
        return self._data


class FakeElf:
    def __init__(self, section):
        self.section = section

    def get_section_by_name(self, name):
        return self.section


class ContractRecordParserTests(unittest.TestCase):
    """Malformed record layouts are refused, as the runtime's start-up walk refuses them."""

    def records(self, data, address=0x1000):
        return contract_records(FakeElf(FakeSection(data, address)), "teapot_contract", 2)

    def test_padded_records_are_read(self):
        first = raw_record(2, b"{}")
        data = first + bytes(-len(first) % 8) + raw_record(2, b"")
        self.assertEqual(len(self.records(data)), 2)

    def test_malformed_layouts_are_refused(self):
        cases = {
            "the JSON runs past the section": raw_record(2, b"", json_size=4096),
            "the section ends inside the padding": raw_record(2, b"{"),
            # One byte of valid JSON, so only the grid can refuse it.
            "a record off the 8-byte grid": raw_record(2, b"1") + raw_record(2, b""),
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaisesRegex(ValueError, "(truncated|malformed) contract record"):
                self.records(data)
        with self.assertRaisesRegex(ValueError, "misaligned contract record section"):
            self.records(raw_record(2, b""), address=0x1004)


@unittest.skipUnless(shutil.which("cc"), "ELF compiler/linker required")
class ComponentContractRecordTests(unittest.TestCase):
    def link(self, root, modules, runtimes=1, coverage=False):
        """Link two components with a runtime record of this coverage mode: with
        coverage each component has one guard, without it none."""
        components = [dict(component_id=key, guard_count=int(coverage), coverage=coverage)
                      for key in ("a" * 16, "b" * 16)]
        objects = []
        for index, (component, module) in enumerate(zip(components, modules)):
            key = component["component_id"]
            source = root / f"component-{index}.S"
            source.write_text(f'''
.section .teapot_component_text,"ax",@progbits
.long 0
.section .teapot_transient,"ax",@progbits
.long 0
.section .teapot_component_guards.{key},"aw",@progbits
.global __guard_start__teapot___{key}, __guard_end__teapot___{key}
__guard_start__teapot___{key}: {".long 0" if coverage else ""}
__guard_end__teapot___{key}:
''' + module + '.section .note.GNU-stack,"",@progbits\n')
            objects.append(source)
        runtime = root / "runtime.S"
        text = '.text\n.global _start\n_start: ret\n'
        for index in range(runtimes):
            text += record("libcheckpoint_contract", 1, FINGERPRINT, 0b101 | (0b10000 if coverage else 0),
                           {"a": 1, "coverage": int(coverage)},
                           label=(ANCHOR, "libcheckpoint_runtime_contract") if index == 0 else ())
        runtime.write_text(text + '.section .note.GNU-stack,"",@progbits\n')
        layout, binary = root / "layout.ld", root / "linked"
        layout.write_text(component_layout(components))
        # Nothing refers to the module records but the runtime's start-up walk:
        # the layout keeps them under --gc-sections.
        subprocess.run(["cc", "-no-pie", "-nostdlib", "-Wl,--gc-sections", "-Wl,-e,_start",
                        *map(str, objects), str(runtime), "-Wl,-T," + str(layout), "-o", str(binary)],
                       check=True, capture_output=True)
        return binary, components

    def validate(self, binary, components, recorded=FINGERPRINT, coverage=False):
        manifest = {"components": components,
                    "runtime_contract": {"version": 2, "fingerprint": recorded, "coverage": coverage}}
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            symbols = {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols()}
            return validate_contract_records(elf, symbols.__getitem__, manifest)

    def module(self, index, fingerprint=FINGERPRINT, capabilities=0b100, abi=None, component=None,
               coverage=False, pushed=None, requires=None):
        """A component's record for a runtime of this coverage mode; pushed says
        whether the component pushes coverage guards (by default, as it should),
        requires whether its record requires the coverage capability (as pushed)."""
        pushed = coverage if pushed is None else pushed
        requires = pushed if requires is None else requires
        return record("teapot_contract", 2, fingerprint, capabilities | (0b10000 if requires else 0),
                      abi or {"a": 1, "coverage": int(coverage)}, anchor=ANCHOR,
                      component=component or ("a" * 16, "b" * 16)[index], policy={"coverage": pushed})

    def test_matching_records_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, components = self.link(Path(directory), [self.module(0), self.module(1)])
            result = self.validate(binary, components)
            self.assertEqual(result["module_records"], 2)
            self.assertEqual(result["runtime_capabilities"], ["nested", "dift_runtime"])

    def test_mismatches_are_refused_with_their_fields(self):
        cases = (
            ("another ABI", [self.module(0), self.module(1, "fedcba9876543210", abi={"a": 2, "coverage": 0})], {}),
            ("capabilities the linked archive lacks", [self.module(0), self.module(1, capabilities=0b10)], {}),
            ("another runtime contract", [self.module(0), self.module(1)], {"recorded": "fedcba9876543210"}),
            ("one module contract record per component", [self.module(0), ""], {}),
            # Another object's record cannot stand in for a component without one.
            ("one module contract record per component",
             [self.module(0) + self.module(0, component="c" * 16), ""], {}),
            ("one libcheckpoint runtime record", [self.module(0), self.module(1)], {"runtimes": 2}),
        )
        for message, modules, options in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                binary, components = self.link(Path(directory), modules, options.get("runtimes", 1))
                with self.assertRaisesRegex(ValueError, message):
                    self.validate(binary, components, options.get("recorded", FINGERPRINT))
        with tempfile.TemporaryDirectory() as directory:
            binary, components = self.link(
                Path(directory), [self.module(0), self.module(1, "fedcba9876543210", abi={"a": 2, "coverage": 0})])
            with self.assertRaisesRegex(ValueError, r"a: component 2, runtime 1"):
                self.validate(binary, components)

    def test_coverage_runtime_with_covered_components_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, components = self.link(Path(directory), [self.module(0, coverage=True),
                                                             self.module(1, coverage=True)], coverage=True)
            result = self.validate(binary, components, coverage=True)
            self.assertTrue(result["coverage"])
            self.assertIn("coverage", result["runtime_capabilities"])
        with tempfile.TemporaryDirectory() as directory:
            binary, components = self.link(Path(directory), [self.module(0), self.module(1)])
            self.assertFalse(self.validate(binary, components)["coverage"])

    def test_mixed_coverage_modes_are_refused(self):
        # A component rewritten for the other coverage mode has another ABI (its
        # fingerprint covers the mode); one that does not push guards for a
        # fuzzer's runtime, or pushes them for an ordinary one, is refused too.
        uncovered = self.module(1, "fedcba9876543210", abi={"a": 1, "coverage": 0})
        covered = self.module(1, "fedcba9876543210", abi={"a": 1, "coverage": 1}, coverage=True)
        cases = (
            ("another ABI", [self.module(0, coverage=True), uncovered], {"coverage": True}),
            ("another ABI", [self.module(0), covered], {}),
            ("speculative coverage does not match",
             [self.module(0, coverage=True), self.module(1, coverage=True, pushed=False)], {"coverage": True}),
            ("capabilities the linked archive lacks", [self.module(0), self.module(1, pushed=True)], {}),
            ("speculative coverage does not match",
             [self.module(0), self.module(1, pushed=True, requires=False)], {}),
            ("built for another coverage mode",
             [self.module(0, coverage=True), self.module(1, coverage=True)], {"coverage": True, "recorded": False}),
            ("recorded coverage does not match",
             [self.module(0, coverage=True), self.module(1, coverage=True)], {"coverage": True, "component": False}),
        )
        for message, modules, options in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                coverage = options.get("coverage", False)
                binary, components = self.link(Path(directory), modules, coverage=coverage)
                if "component" in options:
                    components[1]["coverage"] = options["component"]
                with self.assertRaisesRegex(ValueError, message):
                    self.validate(binary, components, coverage=options.get("recorded", coverage))
        with tempfile.TemporaryDirectory() as directory:
            binary, components = self.link(Path(directory), [self.module(0, coverage=True), uncovered],
                                           coverage=True)
            with self.assertRaisesRegex(ValueError, r"coverage: component 0, runtime 1"):
                self.validate(binary, components, coverage=True)
        # Guards in a link whose runtime does not replay them.
        with tempfile.TemporaryDirectory() as directory:
            binary, components = self.link(Path(directory), [self.module(0), self.module(1)])
            components[0]["guard_count"] = 1
            with self.assertRaisesRegex(ValueError, "recorded coverage does not match"):
                self.validate(binary, components)

    def test_components_without_coverage_link_empty_guard_storage(self):
        # No component pushes guards, so the guard section is empty, and its bounds
        # and every component's guard base still resolve for the final link.
        with tempfile.TemporaryDirectory() as directory:
            binary, components = self.link(Path(directory), [self.module(0), self.module(1)])
            with binary.open("rb") as stream:
                elf = ELFFile(stream)
                symbols = {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols()}
                section = elf.get_section_by_name(".teapot_component_guards")
                self.assertIsNotNone(section)
                self.assertEqual(section["sh_size"], 0)
                self.assertEqual(symbols["__guard_start__teapot__"], section["sh_addr"])
                self.assertEqual(symbols["__guard_end__teapot__"], section["sh_addr"])
                for key in ("a" * 16, "b" * 16):
                    self.assertEqual(symbols["__teapot_component_guard_base_" + key], 0)
                    self.assertEqual(symbols["__guard_start__teapot___" + key], section["sh_addr"])


if __name__ == "__main__":
    unittest.main()
