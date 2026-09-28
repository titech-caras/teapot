from types import SimpleNamespace
import unittest
import gtirb
from teapot.arch import module_isa_name
from teapot.arch.aarch64.architecture import AArch64Architecture
from teapot.arch.riscv64.architecture import RISCV64Architecture
from teapot.arch.x64.architecture import X64Architecture
from experiments.reusable_libraries.targets import TARGETS, MODES, for_machine, mode_metadata, target_for
from teapot.arch.aarch64.bti import AArch64BTIArchitecture
from experiments.reusable_libraries.validate_link import validate_dynamic_symbol_names, validate_mode_contract
from unittest.mock import Mock


class ComponentArchitecturesTests(unittest.TestCase):
    def test_manifest_derives_mode_and_rejects_mixed_objects(self):
        for mode, spec in MODES.items():
            contract = mode_metadata(spec['isa'], mode)
            manifest = dict(contract, components=[dict(contract, component_id='test')])
            with self.subTest(mode=mode):
                self.assertEqual(validate_mode_contract(manifest), (spec['isa'], mode))
                for wrong_mode in MODES:
                    if mode != wrong_mode:
                        with self.assertRaisesRegex(ValueError, 'mode mismatch'):
                            validate_mode_contract(manifest, mode=wrong_mode)
                wrong_isa = 'X64' if spec['isa'] != 'X64' else 'ARM64'
                with self.assertRaisesRegex(ValueError, 'ISA mismatch'):
                    validate_mode_contract(manifest, isa=wrong_isa)
                for field, wrong in (('dift_layout', 'other'), ('tag_storage', 'other'), ('mode', 'other')):
                    mixed = dict(manifest, components=[dict(manifest['components'][0], **{field: wrong})])
                    with self.assertRaisesRegex(ValueError, 'component build mode mismatch'):
                        validate_mode_contract(mixed)
        with self.assertRaisesRegex(ValueError, 'no complete build mode'):
            validate_mode_contract({'components': []})

    def test_bti_contract_rejects_software_objects_and_other_isas(self):
        contract = mode_metadata('ARM64', 'aarch64-vma48', 'aarch64-bti')
        manifest = dict(contract, components=[dict(contract, component_id='library')])
        self.assertEqual(validate_mode_contract(manifest, target_identification='aarch64-bti'),
                         ('ARM64', 'aarch64-vma48'))
        with self.assertRaisesRegex(ValueError, 'target identification mismatch'):
            validate_mode_contract(manifest, target_identification='software')
        manifest['components'][0]['target_identification'] = 'software'
        with self.assertRaisesRegex(ValueError, 'component build mode mismatch'):
            validate_mode_contract(manifest)
        for isa in ('X64', 'RISCV64'):
            with self.assertRaisesRegex(ValueError, 'require AArch64'):
                mode_metadata(isa, target_identification='aarch64-bti')
        self.assertEqual(target_for('ARM64', 'aarch64-bti')['marker'],
                         AArch64BTIArchitecture().nop_bytes)

    def test_dynamic_symbol_name_bounds_are_checked_before_execution(self):
        for strings, offset, valid in ((b'\0api\0', 1, True),
                                       (b'\0api\0', 5, False),
                                       (b'\0api', 1, False)):
            with self.subTest(strings=strings, offset=offset):
                elf = Mock()
                elf.get_section_by_name.return_value = table = Mock()
                table.__getitem__ = Mock(return_value=2)
                table.iter_symbols.return_value = [{'st_name': offset}]
                elf.get_section.return_value.data.return_value = strings
                if valid:
                    validate_dynamic_symbol_names(elf)
                else:
                    with self.assertRaisesRegex(AssertionError, 'dynamic symbol name'):
                        validate_dynamic_symbol_names(elf)

    def test_riscv_uses_the_frontends_archinfo_contract(self):
        module = gtirb.Module(name='rv64', isa=gtirb.Module.ISA.ValidButUnsupported)
        module.aux_data['archInfo'] = gtirb.AuxData({'ISA': 'RISCV64'}, 'mapping<string,string>')
        self.assertEqual(module_isa_name(module), 'RISCV64')

    def test_marker_and_machine_contracts_match_emitters(self):
        for isa, arch in [('ARM64', AArch64Architecture()), ('RISCV64', RISCV64Architecture())]:
            self.assertEqual(TARGETS[isa]['marker'], arch.nop_bytes)
            self.assertEqual(for_machine(TARGETS[isa]['machine'])[0], isa)

    def test_coverage_relocates_only_the_opt_in_index(self):
        # Only the recorded coverage index moves with a linked component; the guard list does not.
        for arch, registers, ordinary_index, linked_index in (
                (X64Architecture(), ('rax',), 'mov dword ptr [rax], 3',
                 'mov dword ptr [rax], OFFSET component_base + 3'),
                (AArch64Architecture(), ('x0', 'x1'), 'mov w0, #3', '.word component_base+3'),
                (RISCV64Architecture(), ('t0', 't1'), 'li t0, 3', '%hi(component_base+3)')):
            with self.subTest(arch=arch.name):
                context = SimpleNamespace(scratch_registers=registers)
                ordinary = arch.coverage_patch(3)(context)
                linked = arch.coverage_patch(3, index_base_symbol=gtirb.Symbol(name='component_base'))(context)
                self.assertIn(ordinary_index, ordinary)
                self.assertNotIn('component_base', ordinary)
                self.assertIn(linked_index, linked)


if __name__ == '__main__':
    unittest.main()
