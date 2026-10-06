"""Persistent generated-fixture and C/Python parity gates (not timing/native proof)."""
import ctypes
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

import gtirb
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from teapot.fault_risc import (ORIG, choose_recipe, decode_load, guard_template,
                              ordinary_registers, resolve_template)
from teapot.fault_risc_assembly import emit_fault_risc_scopes, fault_risc_assembler_flags
from teapot.preprocess.fault_risc_windows import add_risc_fault_windows
import test_fault_risc_windows as fixture_support


def runtime_source():
    root = Path(__file__).resolve().parents[1]
    choices = ([Path(os.environ["TEAPOT_RUNTIME_SOURCE"])] if "TEAPOT_RUNTIME_SOURCE" in os.environ
               else [root / "libcheckpoint", root.parent / "libcheckpoint"])
    for path in choices:
        if (path / "tests/fault_risc_template_bridge.c").is_file():
            return path
    raise AssertionError("RISC integration tests require the matching runtime checkout; set TEAPOT_RUNTIME_SOURCE")


def canonical_uuids(assembly):
    """Only generated identity tokens vary; instructions/directives may not."""
    identifiers = {}
    def token(match):
        value = match.group()
        if value not in identifiers:
            identifiers[value] = f"fixture_uuid_{len(identifiers)}"
        return identifiers[value]
    return re.sub(r"[0-9a-f]{32}", token, assembly)


def object_semantics(path):
    """Ignore symbol-table ordering, never bytes, relocations or label positions.

    The printer may order co-located aliases differently. Assembling both
    sources compares that harmless variance without normalizing instructions,
    alignment, option scopes or addresses. Keep local labels with -Wa,-L.
    """
    with path.open("rb") as stream:
        elf = ELFFile(stream)

        def symbol_key(symbol):
            section = symbol["st_shndx"]
            if isinstance(section, int):
                section = elf.get_section(section).name
            return (symbol.name, section, symbol["st_value"], symbol["st_size"],
                    symbol["st_info"]["bind"], symbol["st_info"]["type"], symbol["st_other"]["visibility"])

        result = {"machine": elf["e_machine"], "flags": elf["e_flags"], "sections": {}, "symbols": [], "relocations": {}}
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                result["symbols"].extend(symbol_key(symbol) for symbol in section.iter_symbols()
                                         if symbol["st_info"]["type"] != "STT_FILE")
            elif isinstance(section, RelocationSection):
                symbols = elf.get_section(section["sh_link"])
                result["relocations"][elf.get_section(section["sh_info"]).name] = sorted(
                    (entry["r_offset"], entry["r_info_type"], entry["r_addend"],
                     symbol_key(symbols.get_symbol(entry["r_info_sym"]))) for entry in section.iter_relocations())
            elif section["sh_type"] not in ("SHT_NULL", "SHT_STRTAB"):
                result["sections"][section.name] = (
                    section["sh_type"], section["sh_flags"], section["sh_addralign"],
                    section["sh_size"], section.data() if section["sh_type"] != "SHT_NOBITS" else b"")
        result["symbols"].sort()
        return result


class RiscPersistentFixtureTests(unittest.TestCase):
    maxDiff = None

    def test_checked_in_fixtures_match_the_emitter_and_printer(self):
        printer = shutil.which("gtirb-pprinter")
        if not printer:
            self.skipTest("gtirb-pprinter is required to regenerate assembly fixtures")
        runtime = runtime_source()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for isa in ("aarch64", "riscv64"):
                with self.subTest(isa=isa):
                    compiler = shutil.which(isa + "-linux-gnu-gcc")
                    if not compiler:
                        self.skipTest(f"{isa} cross compiler is required to compare generated fixtures")
                    module, section, bounds, manager, _ = fixture_support.RiscWindowEmissionTests().fixture(isa)
                    function = next(module.symbols_named("test_function"))
                    module.entry_point = function.referent
                    module.aux_data["elfSymbolInfo"].data[function] = (0, "FUNC", "GLOBAL", "DEFAULT", 0)
                    module.aux_data["binaryType"] = gtirb.AuxData(["EXEC"], "sequence<string>")
                    add_risc_fault_windows(module, section, bounds, manager, isa)
                    ir, raw = directory / (isa + ".gtirb"), directory / (isa + ".raw.S")
                    module.ir.save_protobuf(ir)
                    result = subprocess.run([printer, "--ir", str(ir), "--asm", str(raw)],
                                            text=True, capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    prepared = emit_fault_risc_scopes(module, raw.read_text())
                    recorded = (runtime / "tests/fixtures/fault-risc" / (isa + ".S")).read_text()
                    flags = fault_risc_assembler_flags(module)
                    self.assertEqual(flags, ("-Wa,--no-pad-sections",) if isa == "riscv64" else ())
                    objects = []
                    for name, assembly in (("generated", prepared), ("recorded", recorded)):
                        source, obj = directory / (isa + name + ".S"), directory / (isa + name + ".o")
                        source.write_text(canonical_uuids(assembly))
                        result = subprocess.run([compiler, *flags, "-Wa,-L", "-c", str(source), "-o", str(obj)],
                                                text=True, capture_output=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        objects.append(object_semantics(obj))
                    self.assertEqual(*objects)

    def test_c_and_python_template_parity(self):
        compiler = shutil.which("cc")
        if not compiler:
            self.skipTest("a host C compiler is required for the template bridge")
        runtime = runtime_source()
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / "template-bridge.so"
            command = [compiler, "-std=gnu11", "-O2", "-fPIC", "-shared", "-fno-stack-protector",
                       "-UNDEBUG", "-Wall", "-Wextra", "-Werror", "-I" + str(runtime / "include"),
                       str(runtime / "tests/fault_risc_template_bridge.c"), "-o", str(library)]
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            bridge = ctypes.CDLL(str(library)).test_fault_risc_template
            pointer = ctypes.POINTER(ctypes.c_ubyte)
            bridge.argtypes = [pointer, ctypes.c_uint, *([ctypes.c_size_t] * 5), pointer,
                               ctypes.POINTER(ctypes.c_size_t)]
            bridge.restype = ctypes.c_size_t
            counts = {}
            for isa, identifier in (("aarch64", 1), ("riscv64", 2)):
                words = []
                if isa == "aarch64":
                    for size in range(4):
                        for opc in (1, 2, 3):
                            for base, destination in ((1, 2), (1, 1), (27, 28), (28, 28)):
                                for imm in (0, 1, 511, 4095):
                                    words.append(0x39000000 | size << 30 | opc << 22 | imm << 10 | base << 5 | destination)
                                for imm in (-256, -1, 0, 255):
                                    words.append(0x38000000 | size << 30 | opc << 22 | (imm & 511) << 12 | base << 5 | destination)
                                for extension in (2, 3, 6, 7):
                                    for scaled in (0, 1):
                                        for index in (destination, 26):
                                            words.append(0x38200800 | size << 30 | opc << 22 | index << 16 |
                                                         extension << 13 | scaled << 12 | base << 5 | destination)
                else:
                    for funct in range(7):
                        for base, destination in ((11, 12), (11, 11), (30, 31), (31, 31)):
                            for imm in (-2048, -1, 0, 2047):
                                words.append((imm & 4095) << 20 | base << 15 | funct << 12 | destination << 7 | 3)
                accepted, rejected = 0, 0
                for word in words:
                    load = decode_load(isa, struct.pack("<I", word))
                    if load is None:
                        rejected += 1
                        continue
                    recipe = choose_recipe(load, ORIG, ordinary_registers(isa) - load.address_inputs - {load.destination})
                    self.assertIsNotNone(recipe)
                    template = guard_template(load, recipe)
                    record = bytearray(128)
                    struct.pack_into("<H", record, 12, 4)
                    struct.pack_into("<I12BqHH", record, 48, load.word, ORIG, load.width, load.base, load.index,
                        load.extension, load.shift, load.destination, recipe.bootstrap, recipe.temp0, recipe.temp1,
                        load.kind, 0, load.displacement, 24 if isa == "aarch64" else 16, recipe.template)
                    encoded = (ctypes.c_ubyte * 128).from_buffer_copy(record)
                    for stub, spill, policy in ((0x100000, 0x204ff8, 0x300800),
                                                (0x400000, 0x300800, 0x2047f8),
                                                (0x100002 if isa == "riscv64" else 0x100004, 0x108800, 0x0ff800)):
                        output, copied = (ctypes.c_ubyte * 128)(), ctypes.c_size_t()
                        targets = dict(spill=spill, policy=policy, rollback=0x180000, **{"return": stub - 500})
                        expected = resolve_template(template, stub, targets)
                        length = bridge(encoded, identifier, stub, spill, policy, stub - 500, 0x180000,
                                        output, ctypes.byref(copied))
                        self.assertEqual((length, copied.value, bytes(output[:length])),
                                         (len(expected), template.copy_offset, expected), (isa, hex(word), recipe, hex(stub)))
                        accepted += 1
                counts[isa] = (accepted, rejected)
            self.assertEqual(counts, {"aarch64": (2592, 288), "riscv64": (336, 0)})


if __name__ == "__main__":
    unittest.main()
