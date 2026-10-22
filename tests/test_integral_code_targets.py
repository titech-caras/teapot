"""An ABS alias at a function entry must not become a call displacement."""
import unittest

import gtirb

from teapot.arch import RISCV64Architecture
from teapot.preprocess.integral_code_targets import normalize_integral_code_targets
from test_live_register_preservation import make_module


class IntegralCodeTargetTest(unittest.TestCase):
    def test_absolute_direct_target_and_data_reference(self):
        def fixture(instruction='ef008000', labels=True):
            _, module, caller, _, _ = make_module(RISCV64Architecture(),
                gtirb.Module.ISA.ValidButUnsupported, bytes.fromhex(instruction + '6780000067800000'))
            caller.size = 4
            interval = caller.byte_interval
            target = gtirb.CodeBlock(size=4, offset=8, byte_interval=interval)
            absolute = gtirb.Symbol('_PROCEDURE_LINKAGE_TABLE_', payload=target.address, module=module)
            label = gtirb.Symbol('callee', payload=target, module=module) if labels else None
            mapping = gtirb.Symbol('$xrv64i2p1_m2p0_a2p1', payload=target, module=module)
            module.aux_data['elfSymbolInfo'] = gtirb.AuxData(
                {absolute: (0, 'OBJECT', 'LOCAL', 'DEFAULT', 0xfff1),
                 mapping: (0, 'NOTYPE', 'LOCAL', 'DEFAULT', 1),
                 **({label: (0, 'FUNC', 'LOCAL', 'DEFAULT', 1)} if label else {})},
                'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
            interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, absolute, set())
            data = gtirb.ByteInterval(address=0x2000, contents=bytes(8), section=gtirb.Section(
                name='.data', module=module, flags={gtirb.Section.Flag.Readable}))
            data.symbolic_expressions[0] = gtirb.SymAddrConst(0, absolute, set())
            return module, caller, target, absolute, label, data

        # JAL call, J tail, and conditional branch use the same rule.
        for instruction in ('ef008000', '6f008000', '63040000'):
            with self.subTest(instruction=instruction):
                module, caller, target, absolute, label, data = fixture(instruction)
                self.assertEqual(normalize_integral_code_targets(module), 1)
                self.assertIs(caller.byte_interval.symbolic_expressions[0].symbol, label)
                self.assertIs(data.symbolic_expressions[0].symbol, absolute)
                self.assertEqual(absolute.value, 0x1008)
                target.byte_interval.address = 0x3000
                self.assertEqual(caller.byte_interval.symbolic_expressions[0].symbol.referent.address, 0x3008)
                self.assertEqual(normalize_integral_code_targets(module), 0)
        module, caller, target, absolute, _, _ = fixture(labels=False)
        self.assertEqual(normalize_integral_code_targets(module), 1)
        label = caller.byte_interval.symbolic_expressions[0].symbol
        self.assertIs(label.referent, target)
        self.assertTrue(label.name.startswith('.L__integral_code_target'))
        self.assertEqual(module.aux_data['elfSymbolInfo'].data[label][1:3], ('NOTYPE', 'LOCAL'))
        for count in (0, 2):
            with self.subTest(target_blocks=count):
                module, _, target, _, _, _ = fixture()
                if count == 0:
                    target.byte_interval = None
                else:
                    gtirb.CodeBlock(size=4, offset=target.offset, byte_interval=target.byte_interval)
                with self.assertRaisesRegex(ValueError, f'has {count} executable CodeBlocks'):
                    normalize_integral_code_targets(module)


if __name__ == '__main__':
    unittest.main()
