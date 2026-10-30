"""C and Python guard-template emission parity (not timing/native proof)."""
import ctypes
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


from teapot.fault_risc import (ORIG, choose_recipe, decode_load, guard_template,
                              ordinary_registers)


def runtime_source():
    root = Path(__file__).resolve().parents[1]
    choices = ([Path(os.environ["TEAPOT_RUNTIME_SOURCE"])] if "TEAPOT_RUNTIME_SOURCE" in os.environ
               else [root / "libcheckpoint", root.parent / "libcheckpoint"])
    for path in choices:
        if (path / "tests/fault_risc_template_bridge.c").is_file():
            return path
    raise AssertionError("RISC integration tests require the matching runtime checkout; set TEAPOT_RUNTIME_SOURCE")


class RiscPersistentFixtureTests(unittest.TestCase):
    maxDiff = None


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
                        length = bridge(encoded, identifier, stub, spill, policy, stub - 500, 0x180000,
                                        output, ctypes.byref(copied))
                        self.assertEqual((length, copied.value), (len(template.code), template.copy_offset))
                        self.assertEqual(bytes(output[copied.value:copied.value + 4]), load.code)
                        relocated = {r.offset for r in template.relocations}
                        for offset in range(0, length, 4):
                            if offset not in relocated:
                                self.assertEqual(bytes(output[offset:offset + 4]),
                                                 template.code[offset:offset + 4], (isa, hex(word), offset))
                        accepted += 1
                counts[isa] = (accepted, rejected)
            self.assertEqual(counts, {"aarch64": (2592, 288), "riscv64": (336, 0)})


if __name__ == "__main__":
    unittest.main()
