"""The combined PAC+BTI activation marker has an explicit, repeatable anchor."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb

from teapot.arch.aarch64.bti_pac import AArch64BTIPACArchitecture
from teapot.datacls.linked_component import LinkedComponent
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.preprocess.copy_section import create_section_bounds
from teapot.utils.serialization import compact_for_pprinter, save_protobuf_ordered
from runtime_contract_support import fixture_contract


MARKER = "teapot_aarch64_bti_pac_rewrite_marker"


def finalizer_fixture(component):
    module = gtirb.Module(name="marker-fixture", isa=gtirb.Module.ISA.ARM64,
                          file_format=gtirb.Module.FileFormat.ELF)
    gtirb.IR(modules=[module])
    section = gtirb.Section(name=".text", module=module)
    interval = gtirb.ByteInterval(address=0x1000, contents=bytes.fromhex("00008052c0035fd6"), section=section)
    entry = gtirb.CodeBlock(size=8, byte_interval=interval)
    gtirb.Symbol(name="main", payload=entry, module=module)
    transient = gtirb.Section(name=".teapot_transient", module=module)
    gtirb.ByteInterval(address=0x2000, contents=bytes.fromhex("c0035fd6"), section=transient)
    bounds = (*create_section_bounds(section, "text"), *create_section_bounds(transient, "transient"))
    linked = LinkedComponent("a" * 16, frozenset({"main"}), frozenset({"main"})) if component else None
    module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
        {}, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
    active = linked.bounds(module) if linked else bounds
    pipeline = SimpleNamespace(module=module, text_section=section, local_section_bounds=bounds,
                               linked_component=linked, text_section_start_symbol=active[0],
                               text_section_end_symbol=active[1], transient_section_start_symbol=active[2],
                               transient_section_end_symbol=active[3])
    return pipeline, entry


@contextmanager
def evidence_directory():
    # CI normally uses a temporary directory. A review run can retain the exact
    # compiler input, single frozen lift, listings and subprocess diagnostics.
    if os.environ.get("TEAPOT_MARKER_EVIDENCE"):
        root = Path(os.environ["TEAPOT_MARKER_EVIDENCE"])
        root.mkdir(parents=True, exist_ok=False)
        yield root
    else:
        with tempfile.TemporaryDirectory() as directory:
            yield Path(directory)


class AArch64MarkerReproducibilityTests(unittest.TestCase):
    def test_marker_uses_local_anchor_under_both_tied_iteration_orders(self):
        for component in (False, True):
            for entry_first in (False, True):
                with self.subTest(component=component, entry_first=entry_first):
                    pipeline, entry = finalizer_fixture(component)
                    anchor = pipeline.local_section_bounds[0].referent
                    blocks = [entry, anchor] if entry_first else [anchor, entry]
                    original = gtirb.Section.code_blocks
                    # Deterministically expose both orders of the actual old
                    # address/offset tie; do not rely on ASLR to fail the test.
                    with patch.object(gtirb.Section, "code_blocks", property(
                            lambda section: iter(blocks) if section is pipeline.text_section
                            else original.fget(section))):
                        AArch64BTIPACArchitecture.finalize_bti_layout(pipeline)
                    marker = next(pipeline.module.symbols_named(MARKER))
                    self.assertIs(marker.referent, anchor)
                    self.assertFalse(marker.at_end)
                    self.assertEqual(pipeline.module.aux_data["elfSymbolInfo"].data[marker],
                                     (0, "NOTYPE", "WEAK", "DEFAULT", 0))
                    if component:
                        self.assertIsInstance(pipeline.text_section_start_symbol.referent, gtirb.ProxyBlock)

    def test_marker_follows_the_anchor_when_final_pinning_moves_it(self):
        for component in (False, True):
            with self.subTest(component=component):
                pipeline, _ = finalizer_fixture(component)
                anchor = pipeline.local_section_bounds[0].referent
                anchor.offset = 4  # A rewrite may leave the empty label behind inserted entry code.
                AArch64BTIPACArchitecture.finalize_bti_layout(pipeline)
                marker = next(pipeline.module.symbols_named(MARKER))
                self.assertIs(marker.referent, anchor)
                TeapotPipeline._pin_section_bounds(pipeline)
                self.assertEqual(marker.referent.offset, 0)

    def test_external_or_nonempty_anchor_is_refused(self):
        for invalid in ("external", "nonempty", "other-section", "at-end"):
            with self.subTest(invalid=invalid):
                pipeline, entry = finalizer_fixture(True)
                anchor = pipeline.local_section_bounds[0]
                if invalid == "external":
                    anchor.referent = gtirb.ProxyBlock(module=pipeline.module)
                elif invalid == "nonempty":
                    anchor.referent = entry
                elif invalid == "other-section":
                    anchor.referent = pipeline.local_section_bounds[2].referent
                else:
                    anchor.at_end = True
                with self.assertRaisesRegex(ValueError, "local text-start anchor"):
                    AArch64BTIPACArchitecture.finalize_bti_layout(pipeline)

    @unittest.skipUnless(all(shutil.which(tool) for tool in (
        "aarch64-linux-gnu-gcc", "ddisasm", "gtirb-pprinter")), "AArch64 compiler/frontend/printer required")
    def test_exact_markers_and_full_listings_across_heap_and_hash_seeds(self):
        with evidence_directory() as root:
            source = Path(__file__).parent / "fixtures/aarch64_marker_repro.c"
            shutil.copyfile(source, root / "input.c")
            commands = (["aarch64-linux-gnu-gcc", "-O1", "-fno-pie", "-no-pie", "-nostdlib",
                         "-fno-stack-protector", "-Wl,-e,main", "input.c", "-o", "input"],
                        ["ddisasm", "input", "--ir", "input.gtirb", "-j", "1"])
            for index, command in enumerate(commands):
                self.run_checked(root, f"prepare-{index}", command)
            for component in (False, True):
                listings, markers = [], []
                for index, (nodes, seed) in enumerate(((0, 0), (997, 0), (3001, 42), (7919, 1))):
                    label = f"component{int(component)}-{index}"
                    command = [sys.executable, "-B", __file__, "--rewrite", str(nodes),
                               str(root / "input.gtirb"), str(root / label), str(int(component))]
                    self.run_checked(root, label, command, seed=seed)
                    listings.append((root / label / "listing.S").read_bytes())
                    markers.append((root / label / "markers.json").read_bytes())
                self.assertIn(MARKER.encode() + b":", listings[0])
                self.assertIn(b".teapot_bti_normal", listings[0])
                # No label, marker, whitespace, UUID or directive normalization.
                # Any unexpected output difference is a test failure.
                for index in range(len(listings)):
                    with self.subTest(component=component, repeat=index):
                        record = json.loads(markers[index])
                        self.assertEqual(record["marker_referent_uuid"], record["anchor_uuid"])
                        self.assertEqual(record["marker_offset"], 0)
                        self.assertFalse(record["at_end"])
                        self.assertEqual(markers[0], markers[index])
                        self.assertEqual(listings[0], listings[index])

    def run_checked(self, root, label, command, seed=0):
        (root / (label + ".command.json")).write_text(json.dumps({"argv": command, "hashseed": seed}) + "\n")
        result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                env={**os.environ, "PYTHONHASHSEED": str(seed)}, timeout=300)
        (root / (label + ".stdout")).write_text(result.stdout)
        (root / (label + ".stderr")).write_text(result.stderr)
        (root / (label + ".exit-status")).write_text(str(result.returncode) + "\n")
        self.assertEqual(result.returncode, 0, f"{command}\n{result.stdout}\n{result.stderr}")


def rewrite(nodes, input_path, output, component):
    # Keep these nodes live until after the rewrite, moving object-identity
    # hashes without changing a byte or UUID in the frozen input.
    heap = [(gtirb.Section(name=""), gtirb.ByteInterval(), gtirb.CodeBlock(), gtirb.Symbol(name=""))
            for _ in range(nodes)]
    ir = gtirb.IR.load_protobuf(input_path)
    names = frozenset({"main", "marker_step"})
    linked = LinkedComponent("a" * 16, names, names) if component else None
    pipeline = TeapotPipeline(ir, "aarch64-vma42", InstrumentationOptions(target_identification="aarch64-bti-pac"),
                              linked_component=linked,
                              runtime_contract=fixture_contract("aarch64", target_identification="aarch64-bti-pac"))
    pipeline.run()
    module = pipeline.module
    marker = next(module.symbols_named(MARKER))
    anchor = pipeline.local_section_bounds[0].referent
    assert anchor.offset == 0 and anchor.size == 0 and anchor.section is pipeline.text_section
    pair = bytes(pipeline.arch.nop_bytes)
    occurrences = []
    for section in (pipeline.text_section, pipeline.transient_section):
        for interval in sorted(section.byte_intervals, key=lambda value: value.address):
            for offset in range(0, len(interval.contents) - len(pair) + 1, 4):
                if interval.contents[offset:offset + len(pair)] == pair:
                    occurrences.append([section.name, interval.address, offset, pair.hex()])
    assert occurrences
    output.mkdir()
    (output / "markers.json").write_text(json.dumps({
        "marker": MARKER, "anchor_uuid": str(anchor.uuid), "anchor_offset": anchor.offset,
        "marker_referent_uuid": str(marker.referent.uuid), "marker_offset": marker.referent.offset,
        "at_end": marker.at_end, "elf_info": module.aux_data["elfSymbolInfo"].data[marker],
        "marker_pairs": occurrences}, sort_keys=True, indent=2) + "\n")
    compact_for_pprinter(ir)
    save_protobuf_ordered(ir, output / "instrumented.gtirb")
    subprocess.run(["gtirb-pprinter", "--ir", str(output / "instrumented.gtirb"),
                    "--asm", str(output / "listing.S")], check=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--rewrite":
        rewrite(int(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), bool(int(sys.argv[5])))
    else:
        unittest.main()
