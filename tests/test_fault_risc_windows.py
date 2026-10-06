"""Source/GTIRB gates; final printer/linker/native gates are separate."""
import struct
import unittest

import gtirb

from teapot.arch import AArch64Architecture, RISCV64Architecture
from teapot.fault_risc import DEAD, DESTINATION, MEMLOG, origin_marker
from teapot.fault_risc_assembly import AUX, _scope_markers
from teapot.fault_x64 import mark_input
from teapot.liveness import LiveRegisterManager
from teapot.preprocess.copy_section import create_section_bounds, set_elf_section_properties
from teapot.preprocess.fault_risc_windows import add_risc_fault_windows
from test_live_register_preservation import make_module


class RiscWindowEmissionTests(unittest.TestCase):
    def fixture(self, isa, dead=True, fp=False):
        if isa == "aarch64":
            arch, gtisa = AArch64Architecture(), gtirb.Module.ISA.ARM64
            code = bytes.fromhex("410440f9210440f9c0035fd6")
            alias_offset, scratch = 4, "x17"
        else:
            arch, gtisa = RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported
            code = bytes.fromhex("0100886083b5850067800000")
            if fp:
                # Existing C.FSDSP before and C.FLDSP after both scalar loads.
                # These remain uncovered and need the normal RV64GC decoder.
                code = bytes.fromhex("02aa886083b58500522067800000")
            alias_offset, scratch = 4, "t1"
        _, module, block, abi, registers = make_module(arch, gtisa, code)
        block.section.name = ".teapot_transient"
        set_elf_section_properties(block.section, 1, 6)
        module.aux_data.setdefault("elfSymbolInfo", gtirb.AuxData({},
            "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"))
        for symbol in module.symbols:
            module.aux_data["elfSymbolInfo"].data[symbol] = (0, "FUNC", "LOCAL", "DEFAULT", 0)
        manager = LiveRegisterManager(module, abi)
        if dead:
            live = (1 << len(registers)) - 1
            manager.masks[gtirb.Offset(block, alias_offset)] = live & ~(1 << registers.index(abi.get_register(scratch)))
        mark_input(block.section, manager.decoder)
        bounds = create_section_bounds(block.section, "risc_fixture")
        return module, block.section, bounds, manager, code

    def test_v4_recipes_halfword_widening_and_island_scope(self):
        for isa in ("aarch64", "riscv64"):
            module, section, bounds, manager, original = self.fixture(isa)
            table = add_risc_fault_windows(module, section, bounds, manager, isa)
            data = table.referent.byte_interval.contents
            self.assertEqual(struct.unpack_from("<IHHIIII", data), (0x53465054, 4, 112, 128, 2, 2, 2))
            self.assertEqual([struct.unpack_from("<H", data, 112 + 128 * i + 74)[0] for i in range(2)],
                             [DESTINATION, DEAD])
            sites = [next(module.symbols_named(f".L__teapot_fault_site_{i}")).referent for i in range(2)]
            self.assertTrue(all(isinstance(site, gtirb.DataBlock) and site.size == 4 for site in sites))
            interval, = section.byte_intervals
            self.assertEqual(module.aux_data["alignment"].data[interval], 65536)
            self.assertEqual(interval.size % 65536, 0)
            self.assertEqual(bounds[1].referent.offset, interval.size)
            self.assertEqual(module.aux_data["alignment"].data[bounds[1].referent], 65536)
            if isa == "riscv64":
                self.assertEqual([site.offset for site in sites], [2, 6])
                self.assertEqual(interval.contents[:2], original[:2])  # input c.nop; none added
                self.assertEqual(len(module.aux_data[AUX].data), 1)      # one scope for adjacent stubs
                self.assertEqual(len(_scope_markers(module)), 2)
                self.assertTrue(all(module.aux_data["alignment"].data[site] == 2 for site in sites))
            else:
                self.assertNotIn(AUX, module.aux_data)

    def test_no_original_dead_proof_leaves_alias_uncovered(self):
        for isa in ("aarch64", "riscv64"):
            module, section, bounds, manager, _ = self.fixture(isa, dead=False)
            table = add_risc_fault_windows(module, section, bounds, manager, isa)
            self.assertEqual(struct.unpack_from("<I", table.referent.byte_interval.contents, 12)[0], 1)

    def test_fp_before_and_after_scalar_loads_remains_uncovered(self):
        module, section, bounds, manager, original = self.fixture("riscv64", fp=True)
        table = add_risc_fault_windows(module, section, bounds, manager, "riscv64")
        self.assertEqual(struct.unpack_from("<I", table.referent.byte_interval.contents, 12)[0], 2)
        interval, = section.byte_intervals
        self.assertEqual(interval.contents[:2], original[:2])
        self.assertEqual(interval.contents[10:12], original[8:10])

    def test_final_emitter_does_not_relayout_unrelated_raw_relaxed_interval(self):
        for isa in ("aarch64", "riscv64"):
            module, section, bounds, manager, _ = self.fixture(isa)
            normal = gtirb.Section(name=".text", module=module, flags={
                gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable,
                gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
            set_elf_section_properties(normal, 1, 6)
            interval = gtirb.ByteInterval(address=0x18000, contents=bytes(range(16)), section=normal)
            first = gtirb.CodeBlock(size=8, offset=0, byte_interval=interval)
            second = gtirb.CodeBlock(size=8, offset=8, byte_interval=interval)
            alignment = module.aux_data.setdefault("alignment", gtirb.AuxData({}, "mapping<UUID,uint64_t>")).data
            alignment[first] = alignment[second] = 16
            before = (interval.address, interval.size, interval.contents, first.offset, second.offset,
                      alignment[first], alignment[second])
            add_risc_fault_windows(module, section, bounds, manager, isa)
            self.assertEqual((interval.address, interval.size, interval.contents, first.offset, second.offset,
                              alignment[first], alignment[second]), before)

    def test_disabled_producer_markers_are_empty(self):
        for arch in (AArch64Architecture(), RISCV64Architecture()):
            self.assertEqual(origin_marker(arch, MEMLOG), "")
            object.__setattr__(arch, "fault_memlog_markers", True)
            first, second = origin_marker(arch, MEMLOG), origin_marker(arch, MEMLOG)
            self.assertTrue(first.startswith(".L__teapot_fault_memlog_"))
            self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
