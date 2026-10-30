"""The final component link retains empty coverage guard storage."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

from experiments.reusable_libraries.rewrite_components import component_layout

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
