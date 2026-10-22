"""Explicit N52 opt-in, diagnostic retention and all three cache boundaries."""
import copy
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

    def test_both_drivers_use_policy_argv_for_every_role(self):
        for role in ('executable', 'selected'):
            for policy in (False, True):
                with self.subTest(role=role, policy=policy), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    request, source = args(policy), item(role)
                    commands = []
                    def fake_run(directory, name, command):
                        self.assertEqual(name, 'lift')
                        commands.append(command)
                        lift_record(directory, source, policy)
                    with patch.object(converter, 'run', side_effect=fake_run):
                        with self.assertRaisesRegex(converter.Unsupported, 'MISSING_FRONTEND_LIVENESS'):
                            converter.reconstruct(source, request, root)
                    component = root / 'component'
                    component.mkdir()
                    with patch.object(driver, 'run', side_effect=fake_run):
                        with self.assertRaisesRegex(ValueError, 'liveRegisterSets'):
                            driver.build_component(request, converter, source, {}, 'component', frozenset(), 100, component)
                    self.assertEqual(len(commands), 2)
                    for command in commands:
                        self.assertEqual(command.count('--allow-ambiguous-data-pointers'), int(policy))
                        self.assertNotIn('--ignore-errors', command)


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

    def test_strict_object_hit_revalidates_and_retains_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, request, recipe = self.populate_object(root, False)
            out = root / 'hit'
            out.mkdir()
            with patch.object(converter, 'run', side_effect=AssertionError('a hit must not lift')):
                converter.reconstruct(source, request, out)
            record = json.loads((out / 'executable/cache.json').read_text())
            self.assertEqual(record['object'], 'hit')
            self.assertIs(record['allow_ambiguous_data_pointers'], False)
            self.assertEqual((out / 'executable/lift/stderr').read_text(), '')

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

    def test_ir_hits_revalidate_both_policies_before_mocked_object_generation(self):
        for policy in (False, True):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, request, recipe = self.populate_ir(root, policy)
                request.resolve_selected_versions = False
                request.pprinter, request.cc = 'gtirb-pprinter', 'gcc'
                out = root / 'hit'
                out.mkdir()
                commands = []
                def fake_run(directory, label, command):
                    commands.append(label)
                    if label == 'print':
                        (directory / 'reconstructed.S').write_text('.text\n')
                    elif label == 'assemble':
                        (directory / 'reconstructed.o').write_bytes(b'unit object fixture')
                    else:
                        self.fail('IR hit must not lift: ' + label)
                table = SimpleNamespace(iter_symbols=lambda: iter(()))
                elf = {'e_type': 'ET_REL', 'e_machine': 'EM_X86_64'}
                elf = type('UnitELF', (dict,), {
                    'get_section_by_name': lambda self, name: table})(elf)
                with patch.object(converter, 'run', side_effect=fake_run), \
                        patch.object(converter, 'ELFFile', return_value=elf), \
                        patch.object(converter, 'eh_cfi_entries', return_value=[]), \
                        patch.object(converter, 'record_frontend_diagnostics',
                                     wraps=converter.record_frontend_diagnostics) as verify:
                    result = converter.reconstruct(source, request, out)
                self.assertTrue(result.is_file())
                self.assertEqual(commands, ['print', 'assemble'])
                self.assertTrue(verify.call_args.kwargs['verify'])
                self.assertIs(verify.call_args.args[3], policy)
                record = json.loads((out / 'executable/cache.json').read_text())
                self.assertEqual(record['lift'], 'hit')
                self.assertEqual(record['object'], 'miss')
                self.assertIs(record['allow_ambiguous_data_pointers'], policy)

    def test_override_ir_is_not_reused_on_strict_miss_or_miskeyed_hit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, override, recipe = self.populate_ir(root, True)
            strict = args(False, override.cache)
            out = root / 'strict'
            out.mkdir()
            with patch.object(converter, 'run', side_effect=RuntimeError('strict frontend refused')) as run:
                with self.assertRaisesRegex(RuntimeError, 'strict frontend refused'):
                    converter.reconstruct(source, strict, out)
            self.assertNotIn('--allow-ambiguous-data-pointers', run.call_args.args[2])
            strict_recipe = converter.recovered_ir_recipe(source, strict)
            override.cache.store('ir', strict_recipe, root / 'artifacts',
                                 [path.name for path in (root / 'artifacts').iterdir()])
            another = root / 'strict-wrong-hit'
            another.mkdir()
            with self.assertRaisesRegex(converter.Unsupported, 'FRONTEND_POLICY'):
                converter.reconstruct(source, strict, another)

    def test_ir_and_object_record_policy_mutation_refuses_even_with_updated_cache_hash(self):
        for stage in ('ir', 'objects'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, request, recipe = (self.populate_ir(root, True) if stage == 'ir'
                                            else self.populate_object(root, True))
                entry = request.cache.root / stage / converter.content_key(recipe)
                record_path = entry / 'artifacts/frontend-diagnostics.json'
                record = json.loads(record_path.read_text())
                record['allow_ambiguous_data_pointers'] = False
                converter.dump(record_path, record)
                manifest_path = entry / 'manifest.json'
                manifest = json.loads(manifest_path.read_text())
                manifest['files']['frontend-diagnostics.json'] = converter.sha(record_path)
                converter.dump(manifest_path, manifest)
                out = root / 'hit'
                out.mkdir()
                with self.assertRaisesRegex(converter.Unsupported, 'FRONTEND_DIAGNOSTIC_RECORD'):
                    converter.reconstruct(source, request, out)

    def test_override_object_is_not_reused_on_strict_hit_or_miss(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, override, recipe = self.populate_object(root, True)
            strict = args(False, override.cache)
            out = root / 'strict'
            out.mkdir()
            with patch.object(converter, 'run', side_effect=RuntimeError('strict frontend refused')) as run:
                with self.assertRaisesRegex(RuntimeError, 'strict frontend refused'):
                    converter.reconstruct(source, strict, out)
            self.assertNotIn('--allow-ambiguous-data-pointers', run.call_args.args[2])
            # Misplacing/rekeying override artifacts under a strict key still
            # cannot bypass policy validation before returning the object.
            strict_recipe = converter.ordinary_object_recipe(source, strict.cache_context)
            override.cache.store('objects', strict_recipe, root / 'artifacts',
                                 [path.name for path in (root / 'artifacts').iterdir()])
            another = root / 'strict-wrong-hit'
            another.mkdir()
            with self.assertRaisesRegex(converter.Unsupported, 'FRONTEND_POLICY'):
                converter.reconstruct(source, strict, another)

    def test_ir_and_object_diagnostic_mutation_and_missing_policy_refuse(self):
        for stage in ('ir', 'objects'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, request, object_recipe = self.populate_object(root, True)
                recipe = converter.recovered_ir_recipe(source, request) if stage == 'ir' else object_recipe
                if stage == 'ir':
                    request.cache.store(stage, recipe, root / 'artifacts',
                                        [path.name for path in (root / 'artifacts').iterdir()])
                entry = request.cache.root / stage / converter.content_key(recipe)
                (entry / 'artifacts/lift/stderr').write_text(WARNING + 'changed progress\n')
                destination = root / 'hit'
                destination.mkdir()
                with self.assertRaisesRegex(converter.Unsupported, 'CACHE_INTEGRITY'):
                    request.cache.restore(stage, recipe, destination)
        with self.assertRaisesRegex(converter.Unsupported, 'explicit boolean policy'):
            converter.ordinary_object_recipe(item(), {})

    def test_component_missing_wrong_policy_hash_and_raw_mutation_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = item()
            result = component_frontend_fields(directory, source, True)
            for value in (None, False, 1):
                changed = copy.deepcopy(result)
                if value is None:
                    changed.pop('allow_ambiguous_data_pointers')
                else:
                    changed['allow_ambiguous_data_pointers'] = value
                with self.subTest(policy=value), self.assertRaisesRegex(ValueError, 'frontend policy'):
                    driver.verify_component_frontend(converter, source, directory, changed, True)
            changed = copy.deepcopy(result)
            changed['files'].pop('lift/stderr')
            with self.assertRaisesRegex(ValueError, 'checksummed frontend diagnostic'):
                driver.verify_component_frontend(converter, source, directory, changed, True)
            (directory / 'lift/stderr').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'cached artifact hash mismatch'):
                driver.verify_component_frontend(converter, source, directory, result, True)

    def test_component_miss_cannot_publish_mislabelled_builder_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, source = Path(temporary), item()
            def build(request, conv, source, key_data, key, selected, priority, directory):
                driver.dump(directory / 'key.json', key_data)
                return {'allow_ambiguous_data_pointers': True, 'files': {}}
            context = {'bindings': [], 'selected_libraries': [], 'runtime_contract': {'coverage': False},
                       'allow_ambiguous_data_pointers': False}
            with patch.object(driver, 'build_component', side_effect=build):
                with self.assertRaisesRegex(ValueError, 'frontend policy'):
                    driver.cached_component(args(False, root), converter, source, context, frozenset(), 0)
            self.assertFalse(any(path.is_dir() and '.building-' not in path.name for path in root.iterdir()))


if __name__ == '__main__':
    unittest.main()
