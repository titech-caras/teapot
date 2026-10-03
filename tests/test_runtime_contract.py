import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_rewriting.abi import _ABIS

from teapot.arch import get_arch
from teapot.pipeline import InstrumentationOptions
from teapot.preprocess.contract_record import (
    ANCHOR_OFFSET, NOTE_OWNER, NOTE_SECTION, NOTE_TYPE_RECORD, RECORD_AUX_DATA, RECORD_HEADER_SIZE,
    RECORD_KIND_MODULE, RECORD_MAGIC, RECORD_SECTION, add_contract_record)
from teapot.runtime_contract import (
    RuntimeContractError, abi_fingerprint, capability_bits, contract_anchor, load_runtime_contract)
from runtime_contract_support import FIXTURES, fixture_contract, fixture_contract_path, runtime_contract

ROOT = Path(__file__).resolve().parents[1]
ISAS = {"x64": gtirb.Module.ISA.X64, "aarch64": gtirb.Module.ISA.ARM64, "riscv64": gtirb.Module.ISA.RISCV64}


def arch_and_abi(name):
    arch = get_arch(gtirb.Module(name="probe", isa=ISAS[name]))
    return arch, arch.register_abi(_ABIS)


def edited_contract(directory, name, edit, *, refingerprint=True):
    """A copy of a fixture contract, changed by ``edit(data)``."""
    data = json.loads(fixture_contract_path(name).read_text())
    edit(data)
    if refingerprint:
        data["fingerprint"] = abi_fingerprint(data["abi"])
        data["anchor"] = contract_anchor(data["version"], data["fingerprint"])
    path = Path(directory) / "edited.contract.json"
    path.write_text(json.dumps(data))
    return path


class RuntimeContractLoadTests(unittest.TestCase):
    def test_fixtures_load_with_their_fingerprints(self):
        for path in sorted(FIXTURES.glob("*.contract.json")):
            with self.subTest(path=path.name):
                contract = load_runtime_contract(path)
                data = json.loads(path.read_text())
                self.assertEqual(contract.fingerprint, data["fingerprint"])
                self.assertEqual(contract.anchor, data["anchor"])

    def test_unusable_files_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            cases = (
                ("missing or malformed ABI field dift.layout", lambda data: data["abi"].pop("dift.layout"), True),
                ("runtime values must be integers",
                 lambda data: data["runtime"].update({"max_checkpoints": "1"}), True),
                ("not a libcheckpoint runtime contract", lambda data: data.update(schema="other"), True),
                ("contract version 2", lambda data: data.update(version=2), True),
                ("is not the hash of its ABI section",
                 lambda data: data["abi"].update({"memlog.entry_size": 32}), False),
                ("capability_bits disagrees", lambda data: data.update(capability_bits=0), True),
                ("unknown or missing capabilities", lambda data: data["capabilities"].update(future=True), True),
                ("ABI values must be integers or strings",
                 lambda data: data["abi"].update({"little_endian": True}), True),
            )
            for message, edit, refingerprint in cases:
                with self.subTest(message=message):
                    path = edited_contract(directory, "x64", edit, refingerprint=refingerprint)
                    with self.assertRaisesRegex(RuntimeContractError, message):
                        load_runtime_contract(path)
            with self.assertRaisesRegex(RuntimeContractError, "cannot read the runtime contract"):
                load_runtime_contract(Path(directory) / "missing.contract.json")


class RuntimeContractCheckTests(unittest.TestCase):
    def test_every_fixture_matches_what_teapot_emits(self):
        for name, isa, options in (
                ("x64", "x64", InstrumentationOptions()),
                ("aarch64", "aarch64", InstrumentationOptions()),
                ("aarch64-bti", "aarch64", InstrumentationOptions(target_identification="aarch64-bti-pac")),
                ("aarch64-mte", "aarch64", InstrumentationOptions(aarch64_tag_storage="mte")),
                ("riscv64", "riscv64", InstrumentationOptions())):
            for nested in (False, True):
                with self.subTest(runtime=name, nested=nested):
                    arch, abi = arch_and_abi(isa)
                    contract = runtime_contract(name, nested=nested)
                    options_here = InstrumentationOptions(**{**options.__dict__,
                                                             "enable_nested_speculation": nested})
                    bits, layout = contract.check(arch, abi, options_here)
                    self.assertEqual(layout.name, contract.abi["dift.layout"])
                    expected = {"dift_runtime"} | ({"nested"} if nested else set())
                    expected |= {"x64_vector_full"} if isa == "x64" else set()
                    expected |= ({"aarch64_bti_pac"} if options.target_identification == "aarch64-bti-pac"
                                 else set())
                    expected |= {"riscv64_float_state"} if isa == "riscv64" else set()
                    self.assertEqual(bits, capability_bits(expected))

    def assertRefused(self, name, options, pattern, *, edit=None, isa=None, dift_layout_name=None):
        isa = isa or name.split("-")[0]
        arch, abi = arch_and_abi(isa)
        with tempfile.TemporaryDirectory() as directory:
            contract = (load_runtime_contract(edited_contract(directory, name, edit)) if edit
                        else runtime_contract(name))
            with self.assertRaisesRegex(RuntimeContractError, pattern):
                contract.check(arch, abi, options, dift_layout_name)

    def test_abi_differences_name_each_field(self):
        options = InstrumentationOptions()
        self.assertRefused("x64", options, r"abi\.memlog\.entry_size: runtime 32, Teapot emits 24",
                           edit=lambda data: data["abi"].update({"memlog.entry_size": 32}))
        self.assertRefused("aarch64", options,
                           r"abi\.target_metadata\.scratch_reg: runtime 56, Teapot emits 24",
                           edit=lambda data: data["abi"].update({"target_metadata.scratch_reg": 56}))
        self.assertRefused("riscv64", options, r"abi\.dift\.reg\.t0: runtime 6, Teapot emits 5",
                           edit=lambda data: data["abi"].update({"dift.reg.t0": 6}))
        self.assertRefused("x64", options, r"abi\.future\.field: the runtime has 1, which this Teapot does not know",
                           edit=lambda data: data["abi"].update({"future.field": 1}))
        self.assertRefused("x64", options, r"abi\.dift\.tag\.secret: Teapot emits 16; the runtime has no such field",
                           edit=lambda data: data["abi"].pop("dift.tag.secret"))

    def test_options_the_archive_cannot_serve(self):
        self.assertRefused("x64", InstrumentationOptions(), "describes a x64 runtime; this module is aarch64",
                           isa="aarch64")
        self.assertRefused("x64", InstrumentationOptions(enable_nested_speculation=True),
                           "capability nested: nested speculation needs the nested runtime")
        self.assertRefused("aarch64", InstrumentationOptions(target_identification="aarch64-bti-pac"),
                           "capability aarch64_bti_pac")
        self.assertRefused("aarch64-mte", InstrumentationOptions(), "tag storage: the runtime uses mte")
        self.assertRefused("aarch64", InstrumentationOptions(aarch64_tag_storage="mte"),
                           "tag storage: the runtime uses shadow")
        self.assertRefused("x64", InstrumentationOptions(), "--dift-layout asks for x64-la48",
                           dift_layout_name="x64-la48")
        self.assertRefused("x64", InstrumentationOptions(), "capability dift_runtime",
                           edit=lambda data: data.update(
                               capabilities=dict(data["capabilities"], dift_runtime=False),
                               capability_bits=data["capability_bits"] & ~capability_bits({"dift_runtime"})))
        self.assertRefused("x64", InstrumentationOptions(), "capability x64_vector_full",
                           edit=lambda data: data.update(
                               capabilities=dict(data["capabilities"], x64_vector_full=False),
                               capability_bits=data["capability_bits"] & ~capability_bits({"x64_vector_full"})))
        # A rewrite that asks less of the runtime still links with one that provides more.
        arch, abi = arch_and_abi("x64")
        bits, _ = runtime_contract("x64", nested=True).check(
            arch, abi, InstrumentationOptions(enable_dift=False, enable_port_gadgets=False,
                                              x64_vector_state="xmm0-7"))
        self.assertEqual(bits, 0)
        bits, _ = runtime_contract("x64", nested=True).check(
            arch, abi, InstrumentationOptions(enable_dift=False, enable_port_gadgets=False,
                                              x64_vector_state="sse"))
        self.assertEqual(bits, capability_bits({"x64_vector_sse"}))
        # The x64 and AArch64 port-contention policies read the DIFT shadow without
        # DIFT propagation too; the RISC-V one reads register tags only.
        bits, _ = runtime_contract("x64").check(arch, abi, InstrumentationOptions(enable_dift=False))
        self.assertEqual(bits, capability_bits({"dift_runtime", "x64_vector_full"}))
        riscv, riscv_abi = arch_and_abi("riscv64")
        bits, _ = runtime_contract("riscv64").check(riscv, riscv_abi, InstrumentationOptions(enable_dift=False))
        self.assertEqual(bits, capability_bits({"riscv64_float_state"}))

    def test_application_range_fields_are_checked_on_load(self):
        cases = (
            ("dift.app_range_count must be an integer from 1 to 5",
             lambda abi: abi.update({"dift.app_range_count": 0})),
            ("dift.app_range_count must be an integer from 1 to 5",
             lambda abi: abi.update({"dift.app_range_count": 6})),
            ("dift.app_range_count must be an integer from 1 to 5",
             lambda abi: abi.update({"dift.app_range_count": "5"})),
            ("missing or malformed ABI field dift.app_range4.end", lambda abi: abi.pop("dift.app_range4.end")),
            ("dift.app_range4.start is past dift.app_range_count but not zero",
             lambda abi: abi.update({"dift.app_range_count": 4})),
        )
        with tempfile.TemporaryDirectory() as directory:
            for message, change in cases:
                with self.subTest(message=message), self.assertRaisesRegex(RuntimeContractError, message):
                    load_runtime_contract(edited_contract(directory, "x64", lambda data: change(data["abi"])))

    def test_riscv_checkpoints_need_the_float_state(self):
        # Without the FP state a rollback leaves the FP registers and FCSR as the
        # speculative path left them; nothing proves a module free of them.
        self.assertRefused("riscv64-nofp", InstrumentationOptions(),
                           "capability riscv64_float_state: a rollback would not restore the floating-point "
                           "registers and FCSR; build the runtime with -DTEAPOT_ENABLE_RISCV_FLOAT_STATE=ON",
                           isa="riscv64")
        riscv, abi = arch_and_abi("riscv64")
        bits, _ = runtime_contract("riscv64").check(riscv, abi, InstrumentationOptions())
        self.assertTrue(bits & capability_bits({"riscv64_float_state"}))
        # Without checkpoints nothing rolls back.
        bits, _ = runtime_contract("riscv64-nofp").check(riscv, abi, InstrumentationOptions(enable_checkpoints=False))
        self.assertFalse(bits & capability_bits({"riscv64_float_state"}))

    def test_application_ranges_are_fingerprinted(self):
        # The ranges come from the runtime and enter the fingerprint, so an archive
        # whose shadow covers other ranges under the same layout name has another
        # anchor and cannot be linked in its place.
        contract = runtime_contract("x64")
        layout = contract.dift_layout()
        self.assertEqual(len(layout.app_ranges), contract.abi["dift.app_range_count"])
        self.assertEqual(layout.app_ranges[-1], (contract.abi["dift.app_range4.start"],
                                                 contract.abi["dift.app_range4.end"]))
        arch, abi = arch_and_abi("x64")
        with tempfile.TemporaryDirectory() as directory:
            narrower = load_runtime_contract(edited_contract(directory, "x64", lambda data: data["abi"].update(
                {"dift.app_range4.end": data["abi"]["dift.app_range4.end"] - 0x1000})))
            self.assertNotEqual(narrower.anchor, contract.anchor)
            _, checked = narrower.check(arch, abi, InstrumentationOptions())
            self.assertEqual(checked.app_ranges[-1][1], contract.abi["dift.app_range4.end"] - 0x1000)
            with self.assertRaisesRegex(RuntimeContractError, "not the hash of its ABI section"):
                load_runtime_contract(edited_contract(directory, "x64", lambda data: data["abi"].update(
                    {"dift.app_range4.end": 0}), refingerprint=False))

    def test_x64_vector_state_matrix(self):
        # A runtime built with a forced TEAPOT_X64_VECTOR_STATE saves that much
        # whatever the rewrite asks for, so it serves a rewrite only if that is
        # at least what the rewrite needs; auto needs the full state.
        order = {"xmm0-7": 1, "sse": 2, "avx": 3, "full": 4, "auto": 4}
        provides = {0: {"x64_vector_sse", "x64_vector_avx", "x64_vector_full"},
                    1: set(), 2: {"x64_vector_sse"}, 3: {"x64_vector_sse", "x64_vector_avx"},
                    4: {"x64_vector_sse", "x64_vector_avx", "x64_vector_full"}}
        arch, abi = arch_and_abi("x64")
        vector = {"x64_vector_sse", "x64_vector_avx", "x64_vector_full"}
        with tempfile.TemporaryDirectory() as directory:
            for forced, names in provides.items():
                def edit(data, names=names):
                    capabilities = {name: (value if name not in vector else name in names)
                                    for name, value in data["capabilities"].items()}
                    data.update(capabilities=capabilities, capability_bits=capability_bits(
                        name for name, value in capabilities.items() if value))
                contract = load_runtime_contract(edited_contract(directory, "x64", edit))
                for state, level in order.items():
                    options = InstrumentationOptions(x64_vector_state=state)
                    with self.subTest(forced=forced, state=state):
                        if forced == 0 or forced >= level:
                            contract.check(arch, abi, options)
                        else:
                            with self.assertRaisesRegex(RuntimeContractError, "capability x64_vector_"):
                                contract.check(arch, abi, options)


class ContractRecordTests(unittest.TestCase):
    def test_module_record_layout(self):
        contract = fixture_contract("aarch64")
        module = gtirb.Module(name="probe", isa=gtirb.Module.ISA.ARM64)
        anchor = gtirb.Symbol(name=contract.anchor, payload=gtirb.ProxyBlock(module=module), module=module)
        options = InstrumentationOptions(enable_nested_speculation=True)
        bits = capability_bits({"nested", "dift_runtime"})
        block = add_contract_record(module, contract, bits, options)

        section = block.byte_interval.section
        self.assertEqual(section.name, RECORD_SECTION)
        self.assertNotIn(gtirb.Section.Flag.Writable, section.flags)
        contents = bytes(block.byte_interval.contents)
        self.assertEqual(len(contents) % 8, 0)
        magic, version, kind, header_size, json_size, fingerprint, required = \
            struct.unpack_from("<IHHIIQQ", contents)
        self.assertEqual((magic, version, kind, header_size), (RECORD_MAGIC, 1, RECORD_KIND_MODULE,
                                                               RECORD_HEADER_SIZE))
        self.assertEqual((f"{fingerprint:016x}", required), (contract.fingerprint, bits))
        self.assertEqual(contents[ANCHOR_OFFSET:ANCHOR_OFFSET + 8], bytes(8))
        expression = block.byte_interval.symbolic_expressions[ANCHOR_OFFSET]
        self.assertIs(expression.symbol, anchor)
        self.assertEqual(module.aux_data["symbolicExpressionSizes"].data[
            gtirb.Offset(block.byte_interval, ANCHOR_OFFSET)], 8)
        record = json.loads(contents[header_size:header_size + json_size])
        self.assertEqual(record["requirements"], ["nested", "dift_runtime"])
        self.assertEqual(record["abi"], dict(contract.abi))
        self.assertEqual(record["policy"]["options"]["enable_nested_speculation"], True)
        self.assertEqual(json.loads(module.aux_data[RECORD_AUX_DATA].data), record)
        self.assertFalse(any(contents[header_size + json_size:]))
        self.assertNotIn("component", record)
        # A note refers to the record, so section GC keeps it.
        note = next(s for s in module.sections if s.name == NOTE_SECTION)
        interval = next(iter(note.byte_intervals))
        namesz, descsz, kind = struct.unpack_from("<III", bytes(interval.contents))
        self.assertEqual((namesz, descsz, kind), (len(NOTE_OWNER), 8, NOTE_TYPE_RECORD))
        (offset, expression), = interval.symbolic_expressions.items()
        self.assertEqual(offset, 12 + 12)
        self.assertIs(expression.symbol.referent, block)

    def test_component_record_names_its_component(self):
        contract = fixture_contract("x64")
        module = gtirb.Module(name="probe", isa=gtirb.Module.ISA.X64)
        gtirb.Symbol(name=contract.anchor, payload=gtirb.ProxyBlock(module=module), module=module)
        block = add_contract_record(module, contract, 0, InstrumentationOptions(), "ab" * 8)
        contents = bytes(block.byte_interval.contents)
        _, _, _, header_size, json_size, _, _ = struct.unpack_from("<IHHIIQQ", contents)
        self.assertEqual(json.loads(contents[header_size:header_size + json_size])["component"], "ab" * 8)

    def test_record_needs_the_imported_anchor(self):
        module = gtirb.Module(name="probe", isa=gtirb.Module.ISA.X64)
        with self.assertRaisesRegex(ValueError, "was not imported"):
            add_contract_record(module, fixture_contract("x64"), 0, InstrumentationOptions())


@unittest.skipUnless(shutil.which("cmake") and (ROOT / "libcheckpoint/CMakeLists.txt").is_file(),
                     "requires CMake and the libcheckpoint checkout")
class FixtureRegenerationTests(unittest.TestCase):
    """The checked-in contracts are what the pinned runtime generates."""

    CONFIGURATIONS = {
        "x64": ("gcc", "x86_64", []),
        "aarch64": ("aarch64-linux-gnu-gcc", "aarch64", ["-DTEAPOT_DIFT_LAYOUT=aarch64-vma42"]),
        "aarch64-bti": ("aarch64-linux-gnu-gcc", "aarch64",
                        ["-DTEAPOT_DIFT_LAYOUT=aarch64-vma42", "-DTEAPOT_EXPERIMENTAL_AARCH64_BTI=ON"]),
        "aarch64-mte": ("aarch64-linux-gnu-gcc", "aarch64",
                        ["-DTEAPOT_DIFT_LAYOUT=aarch64-vma42", "-DTEAPOT_AARCH64_TAG_STORAGE=mte"]),
        "riscv64": ("riscv64-linux-gnu-gcc", "riscv64", ["-DTEAPOT_ENABLE_RISCV_FLOAT_STATE=ON"]),
        "riscv64-nofp": ("riscv64-linux-gnu-gcc", "riscv64", []),
    }

    def test_fixtures_match_the_runtime(self):
        for name, (compiler, processor, options) in self.CONFIGURATIONS.items():
            with self.subTest(runtime=name):
                if not shutil.which(compiler):
                    self.skipTest(f"requires {compiler}")
                with tempfile.TemporaryDirectory() as directory:
                    command = ["cmake", "-S", str(ROOT / "libcheckpoint"), "-B", directory,
                               "-DBUILD_TESTING=OFF", "-DTEAPOT_BUILD_NESTED_RUNTIME=ON",
                               f"-DCHECKPOINT_ARCH={processor}", *options]
                    if processor != "x86_64":
                        command += ["-DCMAKE_SYSTEM_NAME=Linux", f"-DCMAKE_SYSTEM_PROCESSOR={processor}",
                                    f"-DCMAKE_C_COMPILER={compiler}", f"-DCMAKE_ASM_COMPILER={compiler}"]
                    result = subprocess.run(command, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    # Editing a probed header must configure again.
                    depends = (Path(directory) / "CMakeFiles/Makefile.cmake").read_text()
                    for header in ("checkpoint.h", "config.h", "dift_support.h", "runtime_contract.h"):
                        self.assertIn(f"libcheckpoint/include/{header}", depends)
                    for nested in (False, True):
                        archive = "libcheckpoint_nested" if nested else "libcheckpoint"
                        generated = json.loads((Path(directory) / f"{archive}.contract.json").read_text())
                        fixture = json.loads(fixture_contract_path(name, nested=nested).read_text())
                        for field in ("version", "fingerprint", "abi", "capabilities", "runtime"):
                            self.assertEqual(generated[field], fixture[field],
                                             f"{name}{' nested' if nested else ''}: {field}; regenerate "
                                             "tests/fixtures/runtime_contracts from libcheckpoint")


if __name__ == "__main__":
    unittest.main()
