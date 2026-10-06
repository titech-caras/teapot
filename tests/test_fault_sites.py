"""Fault metadata survives address movement and fails closed at final link."""
from dataclasses import replace
import uuid
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
from teapot.preprocess.contract_record import add_contract_record, FAULT_SITES_OFFSET
from teapot.preprocess.fault_sites import add_fault_site_table, HEADER_SIZE, ENTRY_SIZE
from teapot.preprocess.copy_section import set_elf_section_properties
from teapot.fault_sites import access_reader, access_bytes, resolve, validate_table, validate_module_tables
from teapot.runtime_contract import capability_bits, RuntimeContractError
from runtime_contract_support import fixture_contract
from test_runtime_contract import edited_contract
from teapot.runtime_contract import load_runtime_contract


class Section(dict):
    def __init__(self, name, start, size, flags, data=b"", section_type="SHT_PROGBITS"):
        super().__init__(sh_addr=start, sh_size=size, sh_flags=flags, sh_type=section_type)
        self.name, self.contents = name, data
    def data(self): return self.contents


class Elf(dict):
    elfclass, little_endian = 64, True
    def __init__(self, edit=None, machine="EM_X86_64"):
        super().__init__(e_machine=machine)
        length = 7 if machine == "EM_X86_64" else 4
        values = [0x53465054, 2, 112, 16, 2, 1, 2,
                  *(target - (0x2000 + 24 + 8 * i) for i, target in enumerate(
                      (0x1000, 0x1080, 0x1000, 0x1080, 0x3000, 0x3008, 0x3008, 0x3010))), 0, 0, 0]
        entries = [(0x1000 - 0x2070, 0x1060 - 0x2074, 0x1060 - 0x2078, length, 0),
                   (0x1020 - 0x2080, 0x1040 - 0x2084, 0x1040 - 0x2088, length, 0)]
        if edit: edit(values, entries)
        contents = struct.pack("<IHHIIII8q3Q", *values) + b"".join(struct.pack("<iiiHH", *e) for e in entries)
        access = {"EM_X86_64": bytes.fromhex("488b8700000000"), "EM_AARCH64": bytes.fromhex("000040f9"),
                  "EM_RISCV": bytes.fromhex("03350500")}[machine]
        text = bytearray(0x80)
        for offset in (0, 0x20, 0x40, 0x60): text[offset:offset + len(access)] = access
        self.sections = [Section(".text", 0x1000, 0x80, 6, bytes(text)),
                         Section("teapot_fault_sites", 0x2000, len(contents), 2, contents),
                         Section("teapot_protected_bss", 0x3000, 16, 3, section_type="SHT_NOBITS")]
        self.segments = [dict(p_type="PT_LOAD", p_vaddr=s["sh_addr"], p_memsz=s["sh_size"], p_flags=f)
                         for s, f in zip(self.sections, (5, 4, 6))]
    def iter_sections(self): return iter(self.sections)
    def iter_segments(self): return iter(self.segments)


class FaultAccessReaderTests(unittest.TestCase):
    def test_recreated_sections_are_read_once_per_validation(self):
        elf = Elf()
        original_sections = tuple(elf.sections)
        reads = []

        def sections():
            for original in original_sections:
                copy = Section(original.name, original["sh_addr"], original["sh_size"],
                               original["sh_flags"], original.contents, original["sh_type"])
                def data(original=original):
                    reads.append(original.name)
                    return original.data()
                copy.data = data
                yield copy

        elf.iter_sections = sections
        reader = access_reader(elf)
        for offset, length in ((0, 7), (0x20, 7), (0x40, 5), (0x7f, 1), (0, 0x80)):
            self.assertEqual(reader(0x1000 + offset, length),
                             original_sections[0].contents[offset:offset + length])
        self.assertEqual(reads, [".text"])
        self.assertEqual(access_reader(elf)(0x1000, 7), reader(0x1000, 7))
        self.assertEqual(reads, [".text", ".text"])

    def test_cached_bytes_do_not_bypass_extent_permissions_or_storage(self):
        edits = (
            lambda elf: elf.sections[0].__setitem__("sh_flags", 7),
            lambda elf: elf.segments[0].__setitem__("p_flags", 7),
            lambda elf: elf.sections[0].__setitem__("sh_type", "SHT_NOBITS"),
            lambda elf: elf.sections.append(elf.sections[0]),
        )
        for edit in edits:
            with self.subTest(edit=edit):
                elf = Elf(); reader = access_reader(elf)
                reader(0x1000, 7)
                edit(elf)
                with self.assertRaises(ValueError):
                    reader(0x1000, 7)
        elf = Elf(); reader = access_reader(elf)
        reader(0x1000, 7)
        for address, length in ((0xfff, 7), (0x107f, 2), (0x1080, 1), (0x1000, 0)):
            with self.subTest(address=address, length=length), self.assertRaises(ValueError):
                reader(address, length)

    def test_truncated_access_is_not_padded_by_the_cache(self):
        elf = Elf(); elf.sections[0].contents = b"\x90" * 3
        reader = access_reader(elf)
        self.assertEqual(reader(0x1000, 3), b"\x90" * 3)
        for read in (reader, lambda pc, size: access_bytes(elf, pc, size)):
            with self.assertRaisesRegex(ValueError, "truncated access"):
                read(0x1000, 7)

    def test_separate_sections_and_elves_do_not_share_bytes(self):
        elf = Elf()
        elf.sections.append(Section(".trampolines", 0x4000, 7, 6, b"\x91" * 7))
        elf.segments.append(dict(p_type="PT_LOAD", p_vaddr=0x4000, p_memsz=7, p_flags=5))
        reader = access_reader(elf)
        self.assertEqual(reader(0x4000, 7), b"\x91" * 7)
        self.assertEqual(reader(0x1000, 7), elf.sections[0].contents[:7])
        other = Elf(); other.sections[0].contents = b"\x92" * 0x80
        self.assertEqual(access_reader(other)(0x1000, 7), b"\x92" * 7)
        self.assertEqual(reader(0x1000, 7), elf.sections[0].contents[:7])


class FaultElfTests(unittest.TestCase):
    def test_valid_table_on_three_isas_and_thresholds(self):
        for machine in ("EM_X86_64", "EM_AARCH64", "EM_RISCV"):
            for threshold in (0, 1, 2, 255):
                table = validate_table(Elf(lambda v, e: v.__setitem__(6, threshold), machine), 0x2000)
                self.assertEqual(table["threshold"], threshold)
                length = 7 if machine == "EM_X86_64" else 4
                self.assertEqual(table["entries"], [(0x1000, 0x1060, 0x1060, length),
                                                    (0x1020, 0x1040, 0x1040, length)])

    def test_relative_overflow(self):
        self.assertEqual(resolve(10, -10), 0)
        self.assertEqual(resolve(1 << 63, -(1 << 63)), 0)
        for address, offset in ((0, -1), (0xffffffffffffffff, 1), (-1, 0)):
            with self.assertRaisesRegex(ValueError, "overflow"): resolve(address, offset)

    def test_malformed_table_and_duplicate_or_unsorted_pc(self):
        mutations = (
            lambda v, e: v.__setitem__(0, 0), lambda v, e: v.__setitem__(1, 99),
            lambda v, e: v.__setitem__(2, 111), lambda v, e: v.__setitem__(3, 8),
            lambda v, e: v.__setitem__(4, 3), lambda v, e: v.__setitem__(5, 0),
            lambda v, e: v.__setitem__(6, 256), lambda v, e: v.__setitem__(15, 1),
            lambda v, e: v.__setitem__(7, -(1 << 63)),
            lambda v, e: v.__setitem__(12, v[12] + 8),
            lambda v, e: e.__setitem__(1, (0x1000 - 0x2080, *e[1][1:])),
            lambda v, e: e.__setitem__(1, (0x0ffc - 0x2080, *e[1][1:])),
            lambda v, e: e.__setitem__(1, (e[1][0], 0x1080 - 0x2084, *e[1][2:])),
            lambda v, e: e.__setitem__(1, (*e[1][:2], 0x1080 - 0x2088, *e[1][3:])),
            lambda v, e: e.__setitem__(1, (*e[1][:3], 4, 0)),
            lambda v, e: e.__setitem__(1, (*e[1][:4], 1)),
        )
        for edit in mutations:
            with self.subTest(edit=edit), self.assertRaises(ValueError): validate_table(Elf(edit), 0x2000)
        for address in (0x2004, 0x2070):
            with self.assertRaises(ValueError): validate_table(Elf(), address)

    def test_access_and_copy_validation(self):
        mutations = (
            ("copy bytes", lambda elf: setattr(elf.sections[0], "contents", elf.sections[0].contents[:0x40] +
                                                b"\x90" + elf.sections[0].contents[0x41:])),
            ("overlapping copies", lambda v, e: e.__setitem__(1, (*e[1][:2], 0x1060 - 0x2088, *e[1][3:]))),
            ("copy is original", lambda v, e: e.__setitem__(1, (*e[1][:2], 0x1000 - 0x2088, *e[1][3:]))),
        )
        for name, edit in mutations:
            elf = Elf()
            if name == "copy bytes": edit(elf)
            else: elf = Elf(edit)
            with self.subTest(name=name), self.assertRaises(ValueError): validate_table(elf, 0x2000)
        for code in (bytes.fromhex("488b0500000000"), bytes.fromhex("488b8500000000"), b"\x90" * 7):
            elf = Elf(); text = bytearray(elf.sections[0].contents)
            for offset in (0, 0x20, 0x40, 0x60): text[offset:offset + 7] = code
            elf.sections[0].contents = bytes(text)
            with self.subTest(code=code.hex()), self.assertRaises(ValueError): validate_table(elf, 0x2000)
        for machine in ("EM_AARCH64", "EM_RISCV"):
            elf = Elf(lambda v, e: e.__setitem__(0, (e[0][0] + 2, *e[0][1:])), machine)
            with self.assertRaisesRegex(ValueError, "alignment"): validate_table(elf, 0x2000)
        elf = Elf(machine="EM_RISCV"); text = bytearray(elf.sections[0].contents)
        for offset in (0, 0x20, 0x40, 0x60): text[offset:offset + 4] = bytes.fromhex("01000100")
        elf.sections[0].contents = bytes(text)
        with self.assertRaises(ValueError): validate_table(elf, 0x2000)

    def test_section_and_segment_permissions_are_both_enforced(self):
        for index in range(3):
            elf = Elf(); elf.sections[index]["sh_flags"] ^= 1
            with self.assertRaises(ValueError): validate_table(elf, 0x2000)
            elf = Elf(); elf.segments[index]["p_flags"] ^= 2
            with self.assertRaises(ValueError): validate_table(elf, 0x2000)
        elf = Elf(); elf.sections[2]["sh_type"] = "SHT_PROGBITS"
        with self.assertRaises(ValueError): validate_table(elf, 0x2000)

    def test_module_table_capability_and_policy(self):
        record = dict(fault_sites=0x2000, capabilities=capability_bits({"fault_training"}),
                      contract={"policy": {"fault_training": True}})
        self.assertEqual(len(validate_module_tables(Elf(), [record])), 1)
        for field, value in (("fault_sites", 0), ("capabilities", 0), ("contract", {"policy": {}})):
            with self.assertRaises(ValueError): validate_module_tables(Elf(), [dict(record, **{field: value})])
        with self.assertRaisesRegex(ValueError, "overlapping module"):
            validate_module_tables(Elf(), [record, record])


class FaultEmissionTests(unittest.TestCase):
    def module(self):
        module = gtirb.Module(name="fault", isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name=".teapot_transient", module=module,
            flags={gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable,
                   gtirb.Section.Flag.Initialized})
        set_elf_section_properties(section, 1, 6)
        # The printer canonicalizes a forced disp32 of zero back to three
        # bytes. Use a real disp32 here; final validation must reject shortening.
        interval = gtirb.ByteInterval(address=0x1000, contents=(bytes.fromhex("488b8756341200") + b"\x90") * 4,
                                     section=section)
        blocks = [gtirb.CodeBlock(size=8, offset=i * 8, byte_interval=interval) for i in range(4)]
        symbols = [gtirb.Symbol(name=f"site{i}", payload=b, module=module) for i, b in enumerate(blocks)]
        end = gtirb.Symbol(name="text_end", payload=blocks[-1], at_end=True, module=module)
        function = uuid.uuid4()
        module.aux_data["functionEntries"] = gtirb.AuxData({function: {blocks[0]}}, "mapping<UUID,set<UUID>>")
        module.aux_data["functionBlocks"] = gtirb.AuxData({function: set(blocks)}, "mapping<UUID,set<UUID>>")
        module.aux_data["functionNames"] = gtirb.AuxData({function: symbols[0]}, "mapping<UUID,UUID>")
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            {s: (32, "FUNC", "GLOBAL", "DEFAULT", 0) if s is symbols[0] else
             (0, "NOTYPE", "LOCAL", "DEFAULT", 0) for s in symbols + [end]},
            "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
        return module, symbols, end

    def test_table_entries_are_self_relative_sorted_and_counters_nobits(self):
        module, symbols, end = self.module()
        table = add_fault_site_table(module, [(symbols[2], symbols[3], symbols[3], 7),
                                             (symbols[0], symbols[1], symbols[1], 7)], 2, symbols[0], end)
        interval = table.referent.byte_interval
        for offset in (HEADER_SIZE, HEADER_SIZE + ENTRY_SIZE):
            expression = interval.symbolic_expressions[offset]
            self.assertIsInstance(expression, gtirb.SymAddrAddr)
            self.assertEqual(expression.symbol2.referent.address, interval.address + offset)
        self.assertIs(interval.symbolic_expressions[HEADER_SIZE].symbol1, symbols[0])
        protected = next(s for s in module.sections if s.name == "teapot_protected_bss")
        self.assertEqual(module.aux_data["sectionProperties"].data[protected], (8, 3))
        self.assertEqual(next(iter(protected.byte_intervals)).size, 16)
        self.assertFalse(next(iter(protected.byte_intervals)).contents)

    def test_bad_threshold_duplicate_and_out_of_range_are_refused(self):
        for threshold in (-1, 256, True):
            module, s, end = self.module()
            with self.assertRaises(ValueError): add_fault_site_table(module, [(s[0], s[1], s[1], 7)], threshold, s[0], end)
        module, s, end = self.module()
        bad_sites = ([(s[0], s[1], s[1], 7), (s[0], s[2], s[2], 7)], [(s[0], end, s[1], 7)],
                     [(s[0], s[1], s[1], 4)], [(s[0], s[1], s[1], 7), (s[2], s[1], s[1], 7)],
                     [(s[0], s[1], s[0], 7)], [(s[0], s[1])])
        for sites in bad_sites:
            with self.subTest(sites=sites), self.assertRaises(ValueError): add_fault_site_table(module, sites, 2, s[0], end)

    def test_missing_runtime_capability_is_refused_and_record_retains_table(self):
        module, symbols, end = self.module()
        arch = get_arch(module); abi = arch.register_abi(_ABIS)
        options = InstrumentationOptions(enable_fault_training=True)
        contract = fixture_contract("x64")
        with self.assertRaisesRegex(RuntimeContractError, "fault_training"):
            contract.check(arch, abi, options)
        contract = replace(contract, capabilities=contract.capabilities | {"fault_training"})
        required, _ = contract.check(arch, abi, options)
        gtirb.Symbol(name=contract.anchor, payload=gtirb.ProxyBlock(module=module), module=module)
        table = add_fault_site_table(module, [(symbols[0], symbols[1], symbols[1], 7)], 2, symbols[0], end)
        record = add_contract_record(module, contract, required, options, fault_sites=table)
        self.assertIs(record.byte_interval.symbolic_expressions[FAULT_SITES_OFFSET].symbol, table)
        with self.assertRaisesRegex(ValueError, "disagree"):
            add_contract_record(module, contract, required, options)

    def test_training_mode_has_a_different_anchor_and_component_cache_identity(self):
        from experiments.reusable_libraries.rewrite_components import contract_identity
        def enable(data):
            data["abi"]["fault_training"] = 1
            data["capabilities"]["fault_training"] = True
            data["capability_bits"] |= capability_bits({"fault_training"})
        with tempfile.TemporaryDirectory() as directory:
            enabled = load_runtime_contract(edited_contract(directory, "x64", enable))
            disabled = fixture_contract("x64")
            self.assertNotEqual(enabled.anchor, disabled.anchor)
            self.assertNotEqual(contract_identity(enabled), contract_identity(disabled))
            self.assertTrue(contract_identity(enabled)["fault_training_capable"])
            self.assertEqual(contract_identity(enabled)["fault_sites_version"], 2)
            module, _, _ = self.module(); arch = get_arch(module)
            bits, _ = enabled.check(arch, arch.register_abi(_ABIS), InstrumentationOptions(enable_fault_training=True))
            self.assertTrue(bits & capability_bits({"fault_training"}))
            for wrong in (lambda data: data["abi"].update(fault_training=1),
                          lambda data: data["abi"].update(fault_training=2)):
                with self.assertRaises(RuntimeContractError):
                    load_runtime_contract(edited_contract(directory, "x64", wrong))

    @unittest.skipUnless(shutil.which("gtirb-pprinter") and shutil.which("gcc"), "requires printer/linker")
    def test_printed_relative_table_links_and_validates(self):
        from elftools.elf.elffile import ELFFile
        module, symbols, end = self.module()
        module.entry_point = symbols[0].referent
        add_fault_site_table(module, [(symbols[2], symbols[3], symbols[3], 7),
                                     (symbols[0], symbols[1], symbols[1], 7)], 2, symbols[0], end)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module.ir.save_protobuf(root / "input.gtirb")
            for command in (["gtirb-pprinter", "--ir", "input.gtirb", "--asm", "fixed.S", "--shared", "no"],
                            ["gcc", "-nostdlib", "-no-pie", "fixed.S", "-Wl,-e,site0", "-o", "linked"]):
                result = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with (root / "linked").open("rb") as stream:
                elf = ELFFile(stream)
                table = elf.get_section_by_name("teapot_fault_sites")
                validated = validate_table(elf, table["sh_addr"])
                self.assertEqual(validated["count"], 2)
                self.assertFalse(any(s["sh_type"] in ("SHT_REL", "SHT_RELA") for s in elf.iter_sections()))


if __name__ == "__main__": unittest.main()
