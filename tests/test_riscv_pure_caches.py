"""Pure cold/warm cache control flow; ABI/profile remains part of the key."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb

from teapot.riscv_profile import PURE, PURE_ABI, RiscvProfileError
from test_riscv_pure_profile import elf_fixture, module_fixture
from tools.sharedlib import convert


class PureCacheTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.module, interval, _ = module_fixture()
        interval.address = 0
        self.module.aux_data['elfSymbolInfo'] = gtirb.AuxData({}, 'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
        self.module.aux_data['liveRegisterSets'] = gtirb.AuxData({}, 'mapping<Offset,set<string>>')
        self.module.aux_data['liveRegisterNames'] = gtirb.AuxData({}, 'mapping<uint64_t,string>')
        self.input = self.root / 'library.so'
        self.input.write_bytes(elf_fixture(elf_type=3))
        self.object_bytes = elf_fixture()
        self.item = dict(path=str(self.input), sha256=convert.sha(self.input), role='selected',
                         machine='EM_RISCV', symbols=[], application_fdes=[], soname='library.so',
                         riscv_profile=PURE)

    def test_converter_warm_hit_and_profile_identity(self):
        args = SimpleNamespace(cache_context={'allow_ambiguous_data_pointers': False},
            allow_ambiguous_data_pointers=False, tool_identities={'ddisasm': {'sha256': 'frontend'}},
            source_provenance_data={}, jobs=1, cache=convert.ArtifactCache(self.root / 'cache'),
            ddisasm='declared-frontend', pprinter='declared-printer', cc='declared-gcc',
            selected_sonames=set(), resolve_selected_versions=False, preserve_selected_lifecycle=False)
        calls = []
        def fake_stage(directory, name, command):
            calls.append(name)
            log = directory / name; log.mkdir()
            (log / 'stdout').write_bytes(b''); (log / 'stderr').write_bytes(b'')
            convert.dump(log / 'command.json', [str(x) for x in command])
            convert.dump(log / 'result.json', {'exit': 0})
            if name == 'lift':
                self.module.ir.save_protobuf(directory / 'lift.gtirb')
            elif name == 'print':
                (directory / 'reconstructed.S').write_text('# unit control-flow fixture; no real printer\n')
            elif name == 'assemble':
                (directory / 'reconstructed.o').write_bytes(self.object_bytes)
            else:
                raise AssertionError(name)
        cold, warm = self.root / 'cold', self.root / 'warm'; cold.mkdir(); warm.mkdir()
        with patch.object(convert, 'run', side_effect=fake_stage), \
             patch.object(convert, 'eh_cfi_entries', return_value=[]):
            first = convert.reconstruct(self.item, args, cold, priority=100)
            second = convert.reconstruct(self.item, args, warm, priority=100)
            self.assertEqual(calls, ['lift', 'print', 'assemble'])
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(json.loads((warm / 'selected-000/cache.json').read_text())['object'], 'hit')
        recipe = convert.ordinary_object_recipe(self.item, args.cache_context, 100)
        self.assertEqual(recipe['context']['riscv_abi'], PURE_ABI)
        self.assertEqual(recipe['context']['riscv_profile'], PURE)
        default = dict(self.item); default.pop('riscv_profile')
        self.assertNotEqual(convert.content_key(recipe), convert.content_key(
            convert.ordinary_object_recipe(default, {'allow_ambiguous_data_pointers': False}, 100)))


if __name__ == '__main__':
    unittest.main()
