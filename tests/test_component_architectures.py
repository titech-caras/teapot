from types import SimpleNamespace
import unittest
import gtirb
from teapot.arch import module_isa_name
from teapot.arch.aarch64.architecture import AArch64Architecture
from teapot.arch.riscv64.architecture import RISCV64Architecture
from experiments.reusable_libraries.targets import TARGETS, for_machine
from experiments.reusable_libraries.validate_link import validate_dynamic_symbol_names
from unittest.mock import Mock


class ComponentArchitecturesTests(unittest.TestCase):
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

    def test_coverage_relocates_index_not_guard_address(self):
        for arch, registers, expected in (
                (AArch64Architecture(), ('x0', 'x1'), '.word component_base+3'),
                (RISCV64Architecture(), ('t0', 't1'), '%hi(component_base+3)')):
            context = SimpleNamespace(scratch_registers=registers)
            ordinary = arch.coverage_patch(3)(context)
            linked = arch.coverage_patch(3, index_base_symbol=gtirb.Symbol(name='component_base'))(context)
            self.assertNotIn('component_base', ordinary)
            self.assertIn(expected, linked)


if __name__ == '__main__':
    unittest.main()
