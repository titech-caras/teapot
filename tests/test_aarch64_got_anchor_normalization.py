"""Real A64 DSO ADR-anchored loader GOT load, not optional --emit-relocs evidence."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import PassManager

from teapot.passes.preprocessing.normalize_aarch64_got_anchors_pass import (
    NormalizeAArch64GotAnchorsPass, record_got_relocations,
)
from tools.sharedlib.convert import inspect

TOOLS = ("aarch64-linux-gnu-gcc", "ddisasm", "gtirb-pprinter", "qemu-aarch64", "ld.lld")

ASM = """
.text
.globl got_read
.type got_read,%function
got_read:
    adr x1, anchor
    {extra}
    ldr x1, [x1, :gotpage_lo15:provider_value]
    ldr x0, [x1]
    ldr x2, [x1]
    add x0, x0, x2
    ret
.size got_read,.-got_read
.section .data.rel.ro,"aw"
.balign 4096
.type anchor,%object
anchor: .xword 0
.size anchor,8
.section .note.GNU-stack,"",%progbits
"""
MAIN = """
#include <stdio.h>
unsigned long provider_value = 21;
extern unsigned long got_read(void);
int main(void) { unsigned long value = got_read(); printf("%lu\\n", value); return value != 42; }
"""


@contextmanager
def artifact_directory(name):
    output = os.environ.get("TEAPOT_AARCH64_GOT_E2E_OUTPUT")
    if output:
        root = Path(output) / name
        root.mkdir(parents=True)
        yield root
    else:
        with tempfile.TemporaryDirectory(prefix="teapot-a64-got-") as output:
            yield Path(output)


@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS), "real A64 ELF/lift/print/run tools required")
class AArch64GotAnchorE2ETests(unittest.TestCase):
    def stage(self, root, name, argv):
        argv = list(map(str, argv))
        (root / (name + ".command.json")).write_text(json.dumps(argv) + "\n")
        result = subprocess.run(argv, capture_output=True, timeout=120)
        (root / (name + ".stdout")).write_bytes(result.stdout)
        (root / (name + ".stderr")).write_bytes(result.stderr)
        (root / (name + ".exit.txt")).write_text(str(result.returncode) + "\n")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result

    def fixture(self, root, extra=""):
        (root / "input.S").write_text(ASM.format(extra=extra))
        (root / "main.c").write_text(MAIN)
        cc = "aarch64-linux-gnu-gcc"
        self.stage(root, "COMPILE-DSO", [cc, "-B/usr/lib/llvm-18/bin/", "-fuse-ld=lld",
            "-shared", "-nostdlib", "-g", "-Wl,-z,separate-code", "-Wl,-soname,libanchor.so",
            root / "input.S", "-o", root / "libanchor.so"])
        item = inspect(root / "libanchor.so", "selected")
        self.assertEqual([row[1] for row in item["aarch64_got_relocations"]], [1025])
        self.assertTrue(item["aarch64_got_relocations"][0][4])
        (root / "loader-relocations.json").write_text(json.dumps(item["aarch64_got_relocations"]) + "\n")
        self.stage(root, "LINK-MAIN", [cc, "-g", "-no-pie", "-rdynamic", root / "main.c",
            "-L" + str(root), "-lanchor", "-o", root / "main"])
        prefix = ["qemu-aarch64", "-R", "0x40000000000", "-L", "/usr/aarch64-linux-gnu",
                  "-E", "LD_LIBRARY_PATH=" + str(root)]
        baseline = self.stage(root, "RUN-BASELINE", prefix + [root / "main"])
        self.assertEqual(baseline.stdout, b"42\n")
        self.stage(root, "LIFT", ["ddisasm", root / "libanchor.so", "--ir", root / "input.gtirb", "-j", "1"])
        ir = gtirb.IR.load_protobuf(root / "input.gtirb")
        module = ir.modules[0]
        record_got_relocations(module, item)
        function = next(module.symbols_named("got_read")).referent
        decoded = list(GtirbInstructionDecoder(module.isa).get_instructions(function))
        self.assertEqual(decoded[0].mnemonic, "adr", "fixture must genuinely exercise ADR, not ADRP")
        return ir, prefix, baseline

    def test_real_adr_got_load_prints_links_and_runs(self):
        with artifact_directory("positive") as root:
            ir, prefix, baseline = self.fixture(root)
            normalization = NormalizeAArch64GotAnchorsPass(GtirbInstructionDecoder(ir.modules[0].isa))
            manager = PassManager()
            manager.add(normalization)
            manager.run(ir)
            self.assertEqual(normalization.normalized, 1)
            ir.save_protobuf(root / "normalized.gtirb")
            self.stage(root, "PRINT", ["gtirb-pprinter", "--ir", root / "normalized.gtirb",
                "--asm", root / "normalized.S", "--policy", "complete", "--shared", "yes", "--layout"])
            assembly = (root / "normalized.S").read_text()
            self.assertIn(":got:provider_value", assembly)
            self.assertIn(":got_lo12:provider_value", assembly)
            self.stage(root, "ASSEMBLE", ["aarch64-linux-gnu-gcc", "-c",
                root / "normalized.S", "-o", root / "normalized.o"])
            normalized = root / "rewritten"
            normalized.mkdir()
            self.stage(root, "LINK-DSO", ["aarch64-linux-gnu-gcc", "-B/usr/lib/llvm-18/bin/",
                "-fuse-ld=lld", "-shared", "-nostdlib", "-Wl,-soname,libanchor.so",
                root / "normalized.o", "-o", normalized / "libanchor.so"])
            prefix[-1] = "LD_LIBRARY_PATH=" + str(normalized)
            rewritten = self.stage(root, "RUN-NORMALIZED", prefix + [root / "main"])
            self.assertEqual((rewritten.stdout, rewritten.stderr), (baseline.stdout, baseline.stderr))
            print("[test] real ADR/GLOB_DAT DSO normalize/print/assemble/link/run PASS", flush=True)

    def test_real_two_use_adr_is_refused_before_rewrite(self):
        with artifact_directory("two-use") as root:
            ir, _, _ = self.fixture(root, "mov x3, x1")
            before = ir.modules[0].sections
            original = {bi.uuid: bi.contents for section in before for bi in section.byte_intervals}
            normalization = NormalizeAArch64GotAnchorsPass(GtirbInstructionDecoder(ir.modules[0].isa))
            manager = PassManager()
            manager.add(normalization)
            with self.assertRaisesRegex(ValueError, "A64_GOT_ANCHOR_MULTIPLE_USES") as error:
                manager.run(ir)
            self.assertEqual(normalization.normalized, 0)
            self.assertEqual({bi.uuid: bi.contents for bi in ir.modules[0].byte_intervals}, original)
            (root / "refusal.txt").write_text(str(error.exception) + "\n")
            print("[test] real two-use ADR refusal PASS: " + str(error.exception), flush=True)


if __name__ == "__main__":
    unittest.main()
