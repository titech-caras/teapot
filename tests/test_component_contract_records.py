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
ANCHOR = "__libcheckpoint_contract_v1_" + FINGERPRINT


def record(section, kind, fingerprint, capabilities, abi, *, anchor=None, label=None, component=None):
    """Assembly for one contract record (libcheckpoint's runtime_contract.h)."""
    payload = json.dumps(dict({"abi": abi}, **({"component": component} if component else {}))).encode()
    lines = [f'.section {section},"a",@progbits', ".balign 8"]
    if label:
        lines += [f".global {name}" for name in label] + [f"{name}:" for name in label]
    lines += [".4byte 0x54435054", ".2byte 1", f".2byte {kind}", ".4byte 40", f".4byte {len(payload)}",
              f".8byte 0x{fingerprint}", f".8byte {capabilities}", f".8byte {anchor or 0}",
              ".byte " + ",".join(str(byte) for byte in payload), ".balign 8, 0"]
    return "\n".join(lines) + "\n"


def raw_record(kind, json_bytes, json_size=None):
    """One record's bytes, without the padding that rounds it to 8 bytes."""
    header = struct.pack("<IHHIIQQQ", 0x54435054, 1, kind, 40,
                         len(json_bytes) if json_size is None else json_size, int(FINGERPRINT, 16), 0, 0)
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
    def link(self, root, modules, runtimes=1):
        components = [dict(component_id=key, guard_count=1) for key in ("a" * 16, "b" * 16)]
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
__guard_start__teapot___{key}: .long 0
__guard_end__teapot___{key}:
''' + module + '.section .note.GNU-stack,"",@progbits\n')
            objects.append(source)
        runtime = root / "runtime.S"
        text = '.text\n.global _start\n_start: ret\n'
        for index in range(runtimes):
            text += record("libcheckpoint_contract", 1, FINGERPRINT, 0b101, {"a": 1},
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

    def validate(self, binary, components, recorded=FINGERPRINT):
        manifest = {"components": components, "runtime_contract": {"version": 1, "fingerprint": recorded}}
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            symbols = {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols()}
            return validate_contract_records(elf, symbols.__getitem__, manifest)

    def module(self, index, fingerprint=FINGERPRINT, capabilities=0b100, abi=None, component=None):
        return record("teapot_contract", 2, fingerprint, capabilities, abi or {"a": 1}, anchor=ANCHOR,
                      component=component or ("a" * 16, "b" * 16)[index])

    def test_matching_records_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, components = self.link(Path(directory), [self.module(0), self.module(1)])
            result = self.validate(binary, components)
            self.assertEqual(result["module_records"], 2)
            self.assertEqual(result["runtime_capabilities"], ["nested", "dift_runtime"])

    def test_mismatches_are_refused_with_their_fields(self):
        cases = (
            ("another ABI", [self.module(0), self.module(1, "fedcba9876543210", abi={"a": 2})], {}),
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
                Path(directory), [self.module(0), self.module(1, "fedcba9876543210", abi={"a": 2})])
            with self.assertRaisesRegex(ValueError, r"a: component 2, runtime 1"):
                self.validate(binary, components)


if __name__ == "__main__":
    unittest.main()
