"""A relinked CRT handle changes binding, never its data or placement."""
import unittest

import gtirb

from teapot.pipeline import _export_static_dso_handle


class StaticDsoHandleTest(unittest.TestCase):
    def test_exact_local_object_and_invalid_definitions(self):
        module = gtirb.Module(name='crt', isa=gtirb.Module.ISA.RISCV64,
                              file_format=gtirb.Module.FileFormat.ELF)
        _export_static_dso_handle(module)  # A missing CRT object is never invented.
        self.assertFalse(list(module.symbols_named('__dso_handle')))
        section = gtirb.Section(name='.sdata', module=module)
        interval = gtirb.ByteInterval(address=0xc1220, contents=bytes(8), section=section)
        block = gtirb.DataBlock(size=8, byte_interval=interval)
        symbol = gtirb.Symbol(name='__dso_handle', payload=block, module=module)
        module.aux_data['elfSymbolInfo'] = gtirb.AuxData(
            {symbol: (0, 'OBJECT', 'LOCAL', 'DEFAULT', 0)},
            'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
        info = module.aux_data['elfSymbolInfo'].data
        _export_static_dso_handle(module)
        self.assertEqual(info[symbol], (0, 'OBJECT', 'GLOBAL', 'HIDDEN', 0))
        self.assertIs(symbol.referent, block)
        self.assertIs(block.section, section)
        self.assertEqual((block.address, bytes(interval.contents)), (0xc1220, bytes(8)))
        _export_static_dso_handle(module)  # An existing GLOBAL/HIDDEN stays unchanged.
        self.assertEqual(info[symbol], (0, 'OBJECT', 'GLOBAL', 'HIDDEN', 0))
        for kind in ('FUNC', 'NOTYPE'):
            with self.subTest(kind=kind):
                info[symbol] = (0, kind, 'LOCAL', 'DEFAULT', 0)
                with self.assertRaises(ValueError):
                    _export_static_dso_handle(module)
        info[symbol] = (0, 'OBJECT', 'LOCAL', 'DEFAULT', 0)
        duplicate = gtirb.Symbol(name='__dso_handle', payload=block, module=module)
        info[duplicate] = info[symbol]
        with self.assertRaises(ValueError):
            _export_static_dso_handle(module)


if __name__ == '__main__':
    unittest.main()
