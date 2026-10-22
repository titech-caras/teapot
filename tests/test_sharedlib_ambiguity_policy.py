"""Explicit N52 opt-in, diagnostic retention and all three cache boundaries."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb

from tools.sharedlib import convert as converter
from experiments.reusable_libraries import rewrite_components as driver
from frontend_diagnostic_support import lift_record, component_frontend_fields


WARNING = (converter.AMBIGUOUS_POINTER_WARNING + '\n'
           '\ttable: 2 word(s); first at 0x401000 (8 bytes, value 0x402000)\n'
           '\t.data: 1 word(s); first at 0x403000 (4 bytes, value 0x401000)\n'
           + converter.AMBIGUOUS_POINTER_FOOTER + '\n')


def item(role='executable'):
    return dict(path='/input/' + ('main' if role == 'executable' else 'libtest.so'),
                sha256='a' * 64, machine='EM_X86_64', role=role, entry=0,
                symbols=[], application_fdes=[], soname=None)


def args(policy, cache=None):
    return SimpleNamespace(allow_runtime_symbol_lookup=False, allow_ambiguous_data_pointers=policy, ddisasm='ddisasm', jobs=1,
                           cache=cache, cache_context={'allow_ambiguous_data_pointers': policy, 'allow_runtime_symbol_lookup': False},
                           tool_identities={'ddisasm': {'sha256': 'frontend'}},
                           source_provenance_data={}, preserve_selected_lifecycle=False)


class AmbiguityDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.module = gtirb.Module(name='fixture', isa=gtirb.Module.ISA.X64)
        self.item = item()

    def test_strict_default_and_nonboolean_policy_refuse(self):
        with self.assertRaises(converter.Unsupported):
            converter.validate_frontend_diagnostics(self.module, self.item, WARNING)
        for policy in (0, 1, None, 'true'):
            with self.subTest(policy=policy), self.assertRaises(converter.Unsupported):
                converter.validate_frontend_diagnostics(self.module, self.item, WARNING, policy)

    def test_exact_warning_requires_optin_and_is_not_data_proof(self):
        with patch.object(converter, 'frontend_data_warning_proof', side_effect=AssertionError('not a proof')):
            records = converter.validate_frontend_diagnostics(self.module, self.item, WARNING, True)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['evidence'], 'unproven heuristic')
        self.assertEqual([row['word_count'] for row in records[0]['objects']], [2, 1])
        self.assertEqual(records[0]['raw_diagnostic'] + '\n', WARNING)
        self.assertIn('not a full per-word inventory', records[0]['inventory_kind'])


    def test_malformed_group_footer_and_unexpected_diagnostics_refuse(self):
        bad = [WARNING.replace('2 word(s)', '0 word(s)'),
               'garbage prefix ' + WARNING,
               WARNING.replace(converter.AMBIGUOUS_POINTER_WARNING, converter.AMBIGUOUS_POINTER_WARNING + ' '),
               WARNING.replace('2 word(s)', '-1 word(s)'),
               WARNING.replace('(8 bytes', '(3 bytes'),
               WARNING.replace('0x402000', '0xgg'),
               WARNING.replace('\ttable:', 'table:'),
               WARNING.replace('\t.data:', '\ttable:'),
               WARNING.replace('0x402000', '0x10000000000000000'),
               WARNING.replace('These words', 'Those words'),
               WARNING.replace('program data.', 'program data. harmless'),
               WARNING.replace(converter.AMBIGUOUS_POINTER_FOOTER, ''),
               converter.AMBIGUOUS_POINTER_WARNING + '\n' + converter.AMBIGUOUS_POINTER_FOOTER,
               WARNING.replace(converter.AMBIGUOUS_POINTER_FOOTER, 'unexpected text\n' + converter.AMBIGUOUS_POINTER_FOOTER),
               WARNING.replace('\t.data:', '\tWARNING:'),
               WARNING + 'WARNING: unrelated\n', WARNING + 'ERROR: unrelated\n', WARNING + WARNING,
               converter.AMBIGUOUS_POINTER_FOOTER]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(converter.Unsupported):
                converter.validate_frontend_diagnostics(self.module, self.item, text, True)

    def test_raw_stderr_retained_and_guesses_never_enter_proven_sidecar(self):
        text = 'disassembly progress\n' + WARNING + 'analysis finished\n'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            module = lift_record(directory, self.item, True, text)
            record = json.loads((directory / 'frontend-diagnostics.json').read_text())
            self.assertEqual(record['raw_diagnostics'], text)
            self.assertEqual((directory / 'lift/stderr').read_text(), text)
            self.assertEqual(json.loads((directory / 'proven-data-decoder-warnings.json').read_text()), [])
            converter.record_frontend_diagnostics(module, self.item, directory, True, verify=True)
            with self.assertRaises(converter.Unsupported):
                converter.record_frontend_diagnostics(module, self.item, directory, False, verify=True)
            record.pop('allow_ambiguous_data_pointers')
            converter.dump(directory / 'frontend-diagnostics.json', record)
            with self.assertRaises(converter.Unsupported):
                converter.record_frontend_diagnostics(module, self.item, directory, True, verify=True)

class AmbiguityCacheTests(unittest.TestCase):
    def test_all_three_layers_separate_policies(self):
        source = item('selected')
        self.assertNotEqual(converter.content_key(converter.recovered_ir_recipe(source, args(False))),
                            converter.content_key(converter.recovered_ir_recipe(source, args(True))))
        self.assertNotEqual(converter.content_key(converter.ordinary_object_recipe(source, args(False).cache_context)),
                            converter.content_key(converter.ordinary_object_recipe(source, args(True).cache_context)))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            keys = []
            def build(request, conv, source, key_data, key, selected, priority, directory):
                driver.dump(directory / 'key.json', key_data)
                result = {'component_id': key, 'coverage': False,
                          **component_frontend_fields(directory, source, request.allow_ambiguous_data_pointers)}
                driver.dump(directory / 'component.json', result)
                return result
            with patch.object(driver, 'build_component', side_effect=build), patch.object(driver, 'validate_object'):
                for policy in (False, True):
                    request = args(policy, root)
                    context = {'bindings': [], 'selected_libraries': [], 'runtime_contract': {'coverage': False},
                               'allow_ambiguous_data_pointers': policy}
                    cold = driver.cached_component(request, converter, source, context, frozenset(), 100)
                    warm = driver.cached_component(request, converter, source, context, frozenset(), 100)
                    keys.append(cold['component_id'])
                    self.assertFalse(cold['cache_hit'])
                    self.assertTrue(warm['cache_hit'])
                    self.assertIs(warm['allow_ambiguous_data_pointers'], policy)
            self.assertNotEqual(*keys)

    def populate_object(self, root, policy):
        source = item()
        cache = converter.ArtifactCache(root / 'cache')
        request = args(policy, cache)
        artifacts = root / 'artifacts'
        artifacts.mkdir()
        lift_record(artifacts, source, policy, WARNING if policy else '')
        (artifacts / 'reconstructed.o').write_bytes(b'ordinary object fixture')
        recipe = converter.ordinary_object_recipe(source, request.cache_context)
        cache.store('objects', recipe, artifacts, [path.name for path in artifacts.iterdir()])
        return source, request, recipe

    def populate_ir(self, root, policy):
        source = item()
        request = args(policy, converter.ArtifactCache(root / 'cache'))
        artifacts = root / 'artifacts'
        artifacts.mkdir()
        module = gtirb.Module(name='fixture', isa=gtirb.Module.ISA.X64,
                              file_format=gtirb.Module.FileFormat.ELF)
        module.aux_data['liveRegisterSets'] = gtirb.AuxData({}, 'mapping<Offset,uint64_t>')
        module.aux_data['liveRegisterNames'] = gtirb.AuxData([], 'sequence<string>')
        module.aux_data['elfSymbolInfo'] = gtirb.AuxData(
            {}, 'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
        lift_record(artifacts, source, policy, WARNING if policy else '', module)
        recipe = converter.recovered_ir_recipe(source, request)
        request.cache.store('ir', recipe, artifacts, [path.name for path in artifacts.iterdir()])
        return source, request, recipe

if __name__ == '__main__':
    unittest.main()
