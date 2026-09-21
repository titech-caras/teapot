import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "libcheckpoint/include/aarch64_shadow_stack.h"


class AArch64ShadowStackConfigTests(unittest.TestCase):
    def inspect_config(self, path):
        return subprocess.run(
            ["python3", "-B", "-c", """
import json
from teapot.configs.slots import AArch64ShadowStackSlots as slots
from teapot.arch.aarch64.spill import AArch64ShadowStackMixin
print(json.dumps([slots.SIZE, slots.CONTROL, slots.REPORT,
                  AArch64ShadowStackMixin.shadow_stack_adjust_reg('sub', 'sp')]))
"""], cwd=ROOT, text=True, capture_output=True,
            env=dict(os.environ, TEAPOT_AARCH64_SHADOW_STACK_CONFIG=str(path)))

    def test_default_and_alternate_size_and_slots(self):
        for size, control, report in ((8388608, 320, 416), (4194304, 336, 432)):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "shadow_stack.h"
                path.write_text(HEADER.read_text().replace(
                    "AARCH64_SHADOW_STACK_SIZE 8388608",
                    f"AARCH64_SHADOW_STACK_SIZE {size}").replace(
                    "AARCH64_SHADOW_STACK_CONTROL_OFFSET 320",
                    f"AARCH64_SHADOW_STACK_CONTROL_OFFSET {control}").replace(
                    "AARCH64_SHADOW_STACK_REPORT_OFFSET 416",
                    f"AARCH64_SHADOW_STACK_REPORT_OFFSET {report}"))
                result = self.inspect_config(path)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), [
                    size, control, report, f"sub sp, sp, #{size // 4096}, lsl #12"])

    def test_unencodable_or_unaligned_size_is_rejected(self):
        for size in (0, 4097, 16777216, "01024000"):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "shadow_stack.h"
                path.write_text(HEADER.read_text().replace(
                    "AARCH64_SHADOW_STACK_SIZE 8388608",
                    f"AARCH64_SHADOW_STACK_SIZE {size}"))
                result = self.inspect_config(path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("shadow stack size", result.stderr)

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
            installed_header = prefix / "include/aarch64_shadow_stack.h"
            self.assertEqual(installed_header.read_bytes(), header.read_bytes())

            # A Python installation has no adjacent libcheckpoint checkout.
            package_root = root / "site-packages"
            for name in ("configs", "datacls"):
                shutil.copytree(ROOT / "teapot" / name, package_root / "teapot" / name)
            result = subprocess.run([sys.executable, "-I", "-B", "-c", """
import json
import sys
sys.path.insert(0, sys.argv[1])
from teapot.configs.slots import AArch64ShadowStackSlots
from teapot.datacls.dift_layout import get_dift_layout
print(json.dumps([AArch64ShadowStackSlots.SIZE, get_dift_layout('aarch64').arch]))
""", str(package_root)], cwd=root, text=True, capture_output=True,
                env=dict(os.environ,
                         TEAPOT_AARCH64_SHADOW_STACK_CONFIG=str(installed_header),
                         TEAPOT_DIFT_LAYOUT_FILE=str(
                             prefix / "share/libcheckpoint/DiftLayoutData.cmake")))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [4194304, "aarch64"])
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

    def test_missing_header_names_the_required_override(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.inspect_config(Path(directory) / "missing.h")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Set TEAPOT_AARCH64_SHADOW_STACK_CONFIG", result.stderr)


if __name__ == "__main__":
    unittest.main()
