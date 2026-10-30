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
from teapot.runtime_contract import capability_bits, RuntimeContractError
from runtime_contract_support import fixture_contract
from test_runtime_contract import edited_contract
from teapot.runtime_contract import load_runtime_contract










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
    def test_printed_relative_table_links(self):
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
                self.assertEqual(table["sh_size"], HEADER_SIZE + 2 * ENTRY_SIZE)
                self.assertFalse(any(s["sh_type"] in ("SHT_REL", "SHT_RELA") for s in elf.iter_sections()))


if __name__ == "__main__": unittest.main()
