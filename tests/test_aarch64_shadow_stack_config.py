import json
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_rewriting.abi import _ABIS

from teapot.arch import get_arch
from teapot.configs.slots import AARCH64_SHADOW_STACK_LAYOUT, _check_aarch64_shadow_stack_layout
from teapot.pipeline import InstrumentationOptions
from teapot.runtime_contract import RuntimeContractError, load_runtime_contract


ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "libcheckpoint/include/aarch64_shadow_stack.h"


class AArch64ShadowStackConfigTests(unittest.TestCase):
    @unittest.skipUnless(HEADER.is_file(), "requires the libcheckpoint checkout")
    def test_table_matches_the_runtime_header(self):
        definitions = dict(re.findall(r"^#define AARCH64_SHADOW_STACK_([A-Z_]+) ([0-9]+)$",
                                      HEADER.read_text(), re.MULTILINE))
        self.assertEqual({name.lower(): int(value) for name, value in definitions.items()},
                         AARCH64_SHADOW_STACK_LAYOUT)

    def test_unencodable_or_unaligned_size_is_rejected(self):
        for size in (0, 4097, 16777216):
            with self.subTest(size=size):
                with self.assertRaisesRegex(ValueError, "shadow stack size"):
                    _check_aarch64_shadow_stack_layout(dict(AARCH64_SHADOW_STACK_LAYOUT, size=size))
        for name, offset in (("control_offset", 512), ("report_offset", 420)):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, name):
                    _check_aarch64_shadow_stack_layout(dict(AARCH64_SHADOW_STACK_LAYOUT, **{name: offset}))

    @unittest.skipUnless(shutil.which("cmake"), "requires CMake")
    def test_cmake_uses_same_header_and_rejects_independent_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "shadow_stack.h"
            header.write_text(HEADER.read_text().replace(
                "AARCH64_SHADOW_STACK_SIZE 8388608", "AARCH64_SHADOW_STACK_SIZE 4194304"))
            build = root / "build"
            command = ["cmake", "-S", str(ROOT / "libcheckpoint"), "-B", str(build),
                       "-DBUILD_TESTING=OFF", "-DCHECKPOINT_ARCH=x86_64",
                       "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DTEAPOT_BUILD_DIFT_MATH_WRAPPERS=ON",
                       f"-DTEAPOT_AARCH64_SHADOW_STACK_CONFIG={header}"]
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((build / "include/aarch64_shadow_stack.h").read_bytes(),
                             header.read_bytes())
            prefix = root / "install"
            result = subprocess.run(
                ["cmake", "--install", str(build), "--prefix", str(prefix),
                 "--component", "checkpoint-config"], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((prefix / "include/aarch64_shadow_stack.h").read_bytes(), header.read_bytes())
            for entry in json.loads((build / "compile_commands.json").read_text()):
                if Path(entry["file"]).name not in ("checkpoint.c", "dift_math_wrappers.c"):
                    continue
                arguments = shlex.split(entry["command"])
                output_index = arguments.index("-o")
                del arguments[output_index:output_index + 2]
                arguments.remove("-c")
                result = subprocess.run(arguments + ["-E", "-dM", "-include", "checkpoint.h"],
                                        cwd=entry["directory"],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                definition = next((line for line in result.stdout.splitlines()
                                   if line.startswith("#define AARCH64_SHADOW_STACK_SIZE ")), None)
                self.assertEqual(definition, "#define AARCH64_SHADOW_STACK_SIZE 4194304", entry["file"])
            result = subprocess.run(command + ["-DTEAPOT_AARCH64_SHADOW_STACK_SIZE=8388608"],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TEAPOT_AARCH64_SHADOW_STACK_CONFIG", result.stderr)

    @unittest.skipUnless(shutil.which("cmake") and shutil.which("aarch64-linux-gnu-gcc"),
                         "requires CMake and an AArch64 cross compiler")
    def test_alternate_header_is_a_named_contract_mismatch(self):
        # Teapot no longer reads the header: a runtime built with another one
        # carries other slots in its contract, and the rewrite is refused.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "shadow_stack.h"
            header.write_text(HEADER.read_text().replace(
                "AARCH64_SHADOW_STACK_SIZE 8388608", "AARCH64_SHADOW_STACK_SIZE 4194304"))
            build = root / "build"
            result = subprocess.run(
                ["cmake", "-S", str(ROOT / "libcheckpoint"), "-B", str(build), "-DBUILD_TESTING=OFF",
                 "-DCMAKE_SYSTEM_NAME=Linux", "-DCMAKE_SYSTEM_PROCESSOR=aarch64",
                 "-DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc", "-DCMAKE_ASM_COMPILER=aarch64-linux-gnu-gcc",
                 "-DCHECKPOINT_ARCH=aarch64", f"-DTEAPOT_AARCH64_SHADOW_STACK_CONFIG={header}"],
                text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            contract = load_runtime_contract(build / "libcheckpoint.contract.json")
            self.assertEqual(contract.abi["aarch64.shadow_stack.size"], 4194304)
            arch = get_arch(gtirb.Module(name="probe", isa=gtirb.Module.ISA.ARM64))
            abi = arch.register_abi(_ABIS)
            with self.assertRaisesRegex(RuntimeContractError,
                                        r"abi\.aarch64\.shadow_stack\.size: runtime 4194304, Teapot emits 8388608"):
                contract.check(arch, abi, InstrumentationOptions())


if __name__ == "__main__":
    unittest.main()
