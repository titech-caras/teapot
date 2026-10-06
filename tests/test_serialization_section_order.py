"""Section insertion order must not perturb the printer's local aliases."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import gtirb
from gtirb.proto.IR_pb2 import IR as IRMessage

from teapot.utils.serialization import save_protobuf_ordered


def fixture():
    module = gtirb.Module(name="section-order", isa=gtirb.Module.ISA.ARM64,
                          file_format=gtirb.Module.FileFormat.ELF,
                          byte_order=gtirb.Module.ByteOrder.Little)
    ir = gtirb.IR(modules=[module])
    info = {}
    for index, name in enumerate((".text", ".rodata", ".teapot_transient", ".data")):
        section = gtirb.Section(name=name, module=module, flags={
            gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable,
            gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
        # Deliberately overlap sections so that the printer must relayout,
        # rebuilding its referent index, just as in the retained failing IR.
        interval = gtirb.ByteInterval(address=0x1000, section=section,
                                     contents=bytes.fromhex("1f2003d5") * 64)
        for offset in range(0, 256, 8):
            block = gtirb.CodeBlock(offset=offset, size=8, byte_interval=interval)
            for prefix in (".LBB", ".Lfunc_end"):
                symbol = gtirb.Symbol(name=f"{prefix}_{index}_{offset}", payload=block, module=module)
                info[symbol] = (0, "NOTYPE", "LOCAL", "DEFAULT", 0)
    module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
        info, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
    for name in ("functionEntries", "functionBlocks"):
        module.aux_data[name] = gtirb.AuxData({}, "mapping<UUID,set<UUID>>")
    module.aux_data["functionNames"] = gtirb.AuxData({}, "mapping<UUID,UUID>")
    module.aux_data["sectionProperties"] = gtirb.AuxData(
        {section: (1, 6) for section in module.sections}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
    return ir


def shuffled_message(ir, seed):
    message = ir._to_protobuf()
    for module in message.modules:
        names = [section.name for section in module.sections]
        random.Random(seed).shuffle(names)
        module.sections.sort(key=lambda section: names.index(section.name))
    return message


@contextmanager
def evidence_directory(label):
    if os.environ.get("TEAPOT_ALIAS_EVIDENCE"):
        root = Path(os.environ["TEAPOT_ALIAS_EVIDENCE"]) / label
        root.mkdir(parents=True, exist_ok=False)
        yield root
    else:
        with tempfile.TemporaryDirectory() as directory:
            yield Path(directory)


class SerializationSectionOrderTests(unittest.TestCase):
    def test_serialized_order_is_fixed_and_no_section_payload_changes(self):
        ir = fixture()
        expected = ir._to_protobuf()
        names = sorted(section.name for section in ir.modules[0].sections)
        sections = {section.uuid: copy.deepcopy(section) for section in expected.modules[0].sections}
        with evidence_directory("payloads") as directory:
            for seed in range(12):
                with self.subTest(seed=seed):
                    message = shuffled_message(ir, seed)
                    path = Path(directory) / f"{seed}.gtirb"
                    with patch.object(ir, "_to_protobuf", return_value=message):
                        save_protobuf_ordered(ir, path)
                    actual = IRMessage()
                    actual.ParseFromString(path.read_bytes()[8:])
                    self.assertEqual([section.name for section in actual.modules[0].sections], names)
                    self.assertEqual({section.uuid: section for section in actual.modules[0].sections}, sections)
            # Serialization must not reorder/mutate the in-memory module or its
            # addresses, UUIDs, instructions, expressions or aux data.
            self.assertEqual(ir._to_protobuf(), expected)

    def test_duplicate_names_use_address_then_uuid_not_set_order(self):
        module = gtirb.Module(name="duplicate-sections")
        ir = gtirb.IR(modules=[module])
        for identity, address in ((4, None), (3, 0x2000), (2, 0x1000), (1, 0x1000)):
            section = gtirb.Section(name=".same", uuid=uuid.UUID(int=identity), module=module)
            gtirb.ByteInterval(address=address, contents=b"x", section=section)
        with evidence_directory("duplicates") as directory:
            path = Path(directory) / "ordered.gtirb"
            for reverse in (False, True):
                message = ir._to_protobuf()
                message.modules[0].sections.sort(key=lambda section: section.uuid, reverse=reverse)
                with patch.object(ir, "_to_protobuf", return_value=message):
                    save_protobuf_ordered(ir, path)
                actual = IRMessage()
                actual.ParseFromString(path.read_bytes()[8:])
                self.assertEqual([uuid.UUID(bytes=section.uuid).int for section in actual.modules[0].sections],
                                 [1, 2, 3, 4])

    @unittest.skipUnless(shutil.which("gtirb-pprinter"), "gtirb-pprinter required")
    def test_complete_assembly_matches_under_forced_section_permutations(self):
        ir = fixture()
        listings = []
        with evidence_directory("listings") as directory:
            root = Path(directory)
            ir.save_protobuf(root / "input.gtirb")
            for seed in range(8):
                message = shuffled_message(ir, seed)
                path, listing = root / f"{seed}.gtirb", root / f"{seed}.S"
                with patch.object(ir, "_to_protobuf", return_value=message):
                    save_protobuf_ordered(ir, path)
                command = ["gtirb-pprinter", "--ir", str(path), "--asm", str(listing)]
                result = subprocess.run(command,
                                        capture_output=True, text=True, timeout=60)
                (root / f"{seed}.command.json").write_text(json.dumps({"argv": command, "exit": result.returncode}) + "\n")
                (root / f"{seed}.stdout").write_text(result.stdout)
                (root / f"{seed}.stderr").write_text(result.stderr)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                listings.append(listing.read_bytes())
            self.assertIn(b".LBB_2_0:", listings[0])
            self.assertIn(b".Lfunc_end_2_0:", listings[0])
            for listing in listings[1:]:
                self.assertEqual(listings[0], listing)  # Literal bytes, no normalization.


if __name__ == "__main__":
    unittest.main()
