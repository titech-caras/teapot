import unittest

import gtirb

from tools.sharedlib import convert as converter


class DecoderDiagnosticsTests(unittest.TestCase):
    def fixture(self, data=((0, 8),), code=()):
        module = gtirb.Module(name='input', isa=gtirb.Module.ISA.ARM64,
                              file_format=gtirb.Module.FileFormat.ELF)
        gtirb.IR(modules=[module])
        section = gtirb.Section(name='.text', module=module)
        interval = gtirb.ByteInterval(address=0x1000, contents=bytes(16), section=section)
        for offset, size in data:
            gtirb.DataBlock(offset=offset, size=size, byte_interval=interval)
        for offset, size in code:
            gtirb.CodeBlock(offset=offset, size=size, byte_interval=interval)
        item = {'machine': 'EM_AARCH64', 'path': 'fixture.so', 'role': 'selected', 'entry': 0,
                'input_data_regions': [{'start': 0x1000, 'end': 0x1008,
                                        'source': 'STT_OBJECT', 'name': 'table', 'section': 1}]}
        return module, item

    def test_object_and_recovered_data_agree(self):
        module, item = self.fixture()
        evidence = converter.validate_frontend_diagnostics(module, item,
            '  disassembly load WARNING: unhandled operand at 4096, op type:72\n')
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]['input_witness']['name'], 'table')
        self.assertEqual(evidence[0]['recovered_data_blocks'], [(4096, 8)])

    def test_exact_cimm_pair_has_addressed_proof(self):
        module, item = self.fixture()
        evidence = converter.validate_frontend_diagnostics(module, item,
            'WARNING: unsupported CIMM operand\n'
            'WARNING: unhandled operand at 4096, op type:64\n')
        self.assertEqual(len(evidence), 2)
        self.assertEqual({r['address'] for r in evidence}, {4096})

    def test_code_even_partly_overlapping_is_rejected(self):
        for data, code in (((), ((0, 4),)), (((0, 8),), ((2, 1),))):
            with self.subTest(data=data, code=code):
                module, item = self.fixture(data, code)
                with self.assertRaisesRegex(converter.Unsupported, 'FRONTEND_DIAGNOSTIC'):
                    converter.validate_frontend_diagnostics(module, item,
                        'WARNING: unhandled operand at 4096, op type:72')

    def test_incomplete_data_coverage_is_rejected(self):
        for data in ((), ((0, 3),), ((0, 2), (3, 1))):
            with self.subTest(data=data):
                module, item = self.fixture(data)
                self.assertIsNone(converter.frontend_data_warning_proof(module, item, 4096))

    def test_adjacent_data_blocks_cover_whole_word(self):
        module, item = self.fixture(((0, 2), (2, 2)))
        self.assertIsNotNone(converter.frontend_data_warning_proof(module, item, 4096))

    def test_independent_input_witness_and_full_word_are_required(self):
        module, item = self.fixture()
        for regions in ([], [{'start': 4096, 'end': 4099}], [{'start': 4097, 'end': 4104}]):
            item['input_data_regions'] = regions
            self.assertIsNone(converter.frontend_data_warning_proof(module, item, 4096))

    def test_other_architecture_or_unaligned_address_is_rejected(self):
        module, item = self.fixture()
        self.assertIsNone(converter.frontend_data_warning_proof(module, item, 4097))
        item['machine'] = 'EM_RISCV'
        self.assertIsNone(converter.frontend_data_warning_proof(module, item, 4096))

    def test_unknown_unpaired_and_error_diagnostics_still_reject(self):
        module, item = self.fixture()
        for text in ('WARNING: unsupported CIMM operand',
                     'WARNING: unsupported CIMM operand\nWARNING: unhandled operand at 4096, op type:72',
                     'WARNING: unknown instruction at 4096',
                     'ERROR: unhandled operand at 4096, op type:72',
                     'WARNING: unhandled operand at 4096, op type:72 ERROR: bad'):
            with self.subTest(text=text), self.assertRaises(converter.Unsupported):
                converter.validate_frontend_diagnostics(module, item, text)

    def test_no_entry_warning_is_only_allowed_for_entryless_library(self):
        module, item = self.fixture()
        text = 'transform WARNING: Failed to set module entry point.'
        self.assertEqual(converter.validate_frontend_diagnostics(module, item, text), [])
        item['role'] = 'executable'
        with self.assertRaises(converter.Unsupported):
            converter.validate_frontend_diagnostics(module, item, text)

    def test_input_mapping_bounds_and_conflicts(self):
        class ELF(dict):
            def iter_sections(self):
                return iter([{}, {'sh_addr': 4096, 'sh_size': 16, 'sh_flags': 6},
                             {'sh_addr': 8192, 'sh_size': 8, 'sh_flags': 6}])
        def symbol(name, address, section=1, size=0, kind='STT_NOTYPE'):
            return dict(name=name, address=address, section=section, size=size,
                        type=kind, binding='STB_LOCAL')
        symbols = [symbol('$d', 4096), symbol('$x.1', 4100),
                   symbol('$d.2', 4104), symbol('$x.2', 4104),  # contradictory
                   symbol('$d', 8192, 2),
                   symbol('zero_size', 4096, size=0, kind='STT_OBJECT'),
                   symbol('outside', 4108, size=8, kind='STT_OBJECT'),
                   symbol('bounded', 4096, size=4, kind='STT_OBJECT')]
        regions = converter.arm64_input_data_regions(ELF(e_machine='EM_AARCH64'), symbols)
        self.assertEqual([(r['start'], r['end']) for r in regions if r['source'] == '$d'],
                         [(4096, 4100), (8192, 8200)])
        self.assertEqual([r['name'] for r in regions if r['source'] == 'STT_OBJECT'], ['bounded'])
        self.assertEqual(converter.arm64_input_data_regions(ELF(e_machine='EM_RISCV'), symbols), [])


if __name__ == '__main__':
    unittest.main()
