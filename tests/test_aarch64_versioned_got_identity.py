"""Independent source-level reproduction using real GTIRB and Capstone."""
import unittest
from pathlib import Path
import tempfile
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from teapot.passes.preprocessing.normalize_aarch64_got_anchors_pass import (
    NormalizeAArch64GotAnchorsPass, record_got_relocations, GOT_RELOCATIONS)
from tools.sharedlib.convert import resolve_selected_symbol_versions


def fixture():
    module = gtirb.Module(name="libcaller.so", isa=gtirb.Module.ISA.ARM64,
                         file_format=gtirb.Module.FileFormat.ELF,
                         byte_order=gtirb.Module.ByteOrder.Little)
    gtirb.IR(modules=[module])
    text = gtirb.Section(name=".text", module=module,
        flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Readable})
    # ADR X1,0x2000; LDR X1,[X1,#8]; RET. The pointer load kills its anchor.
    code = gtirb.ByteInterval(address=0x1000, section=text,
        contents=b"".join(w.to_bytes(4, "little") for w in (0x10008001, 0xf9400421, 0xd65f03c0)))
    gtirb.CodeBlock(size=12, byte_interval=code)
    got = gtirb.Section(name=".got", module=module)
    data = gtirb.ByteInterval(address=0x2000, section=got, contents=bytes(16))
    base = gtirb.Symbol("anchor", payload=gtirb.DataBlock(size=8, byte_interval=data), module=module)
    slot = gtirb.Symbol("slot", payload=gtirb.DataBlock(size=8, offset=8, byte_interval=data), module=module)
    imported = gtirb.Symbol("provider_value", payload=gtirb.ProxyBlock(module=module), module=module)
    code.symbolic_expressions[0] = gtirb.SymAddrConst(0, base)
    code.symbolic_expressions[4] = gtirb.SymAddrAddr(1, 0, slot, base)
    data.symbolic_expressions[8] = gtirb.SymAddrConst(0, imported)
    module.aux_data["elfSymbolInfo"] = gtirb.AuxData({
        base: (8, "OBJECT", "LOCAL", "DEFAULT", 2),
        slot: (8, "OBJECT", "LOCAL", "DEFAULT", 2),
        imported: (0, "OBJECT", "GLOBAL", "DEFAULT", 0)},
        "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
    module.aux_data["symbolForwarding"] = gtirb.AuxData({slot: imported}, "mapping<UUID,UUID>")
    module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
        ({}, {"libprovider.so": {2: "PROVIDER_1"}}, {imported: (2, False)}),
        "tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,mapping<string,mapping<uint16_t,string>>,mapping<UUID,tuple<uint16_t,bool>>>")
    item = {"path": "/fixture/libcaller.so", "machine": "EM_AARCH64", "role": "selected",
        "soname": "libcaller.so", "aarch64_got_relocations": [(0x2008, 1025, "provider_value", 0, True)],
        "resolve_selected_versions": True}
    record_got_relocations(module, item)
    return module, item, imported


class Capture:
    def __init__(self): self.calls = []
    def replace_at(self, *args): self.calls.append(args)


class VersionedGotIdentityTests(unittest.TestCase):
    def normalize(self, module):
        context = Capture()
        NormalizeAArch64GotAnchorsPass(GtirbInstructionDecoder(module.isa)).begin_module(module, [], context)
        return context

    def test_selected_version_import_remaps_got_identity(self):
        module, item, imported = fixture()
        self.assertEqual(len(self.normalize(module).calls), 2)
        original = imported.name
        changes = resolve_selected_symbol_versions(module, item, {"libprovider.so"})
        self.assertEqual(changes[0]['name'], original)
        self.assertEqual(changes[0]['linker_name'], imported.name)
        self.assertNotEqual(imported.name, original)
        self.assertEqual({fact[1] for fact in module.aux_data[GOT_RELOCATIONS].data.values()}, {imported.name})
        self.assertEqual(len(self.normalize(module).calls), 2)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'resolved.gtirb'
            module.ir.save_protobuf(path)
            restored = gtirb.IR.load_protobuf(path).modules[0]
            self.assertEqual(len(self.normalize(restored).calls), 2)

    def test_wrong_loader_name_still_refuses(self):
        module, item, imported = fixture()
        facts = module.aux_data[GOT_RELOCATIONS].data
        for offset, (kind, name, addend, undefined) in list(facts.items()):
            facts[offset] = (kind, 'different_import', addend, undefined)
        resolve_selected_symbol_versions(module, item, {"libprovider.so"})
        with self.assertRaisesRegex(ValueError, 'A64_GOT_FORWARDING_MISMATCH'):
            self.normalize(module)

    def test_wrong_slot_target_still_refuses(self):
        module, item, imported = fixture()
        data = next(bi for bi in module.byte_intervals if bi.address == 0x2000)
        other = gtirb.Symbol('other_import', payload=gtirb.ProxyBlock(module=module), module=module)
        data.symbolic_expressions[8] = gtirb.SymAddrConst(0, other)
        resolve_selected_symbol_versions(module, item, {"libprovider.so"})
        with self.assertRaisesRegex(ValueError, 'A64_GOT_FORWARDING_MISMATCH'):
            self.normalize(module)


if __name__ == '__main__':
    unittest.main()
