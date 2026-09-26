"""Direct branches must not follow the normal-copy jump-table base exception."""
import unittest

import gtirb

from teapot.preprocess.copy_section import copy_section


class CopySectionControlFlowTests(unittest.TestCase):
    def case(self, isa, call=False):
        if isa == gtirb.Module.ISA.ARM64:
            # adr x0, base; b/bl base; two nops; base: ret; other: ret
            contents = bytes.fromhex('80000010' + ('03000094' if call else '03000014') +
                                     '1f2003d51f2003d5c0035fd6c0035fd6')
            source_size, materialization_offset, transfer_offset = 8, 0, 4
        else:
            # lea rax,[rip+base]; jmp/call base; four nops; base: ret; other: ret
            contents = bytes.fromhex('488d0509000000' + ('e8' if call else 'e9') +
                                     '0400000090909090c3c3')
            source_size, materialization_offset, transfer_offset = 12, 3, 8
        module = gtirb.Module(name='copy-control-flow', isa=isa,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        ir = gtirb.IR(modules=[module])
        section = gtirb.Section(name='.text', module=module)
        interval = gtirb.ByteInterval(address=0x1000, contents=contents, section=section)
        source = gtirb.CodeBlock(offset=0, size=source_size, byte_interval=interval)
        size = 4 if isa == gtirb.Module.ISA.ARM64 else 1
        target = gtirb.CodeBlock(offset=16, size=size, byte_interval=interval)
        other = gtirb.CodeBlock(offset=16 + size, size=size, byte_interval=interval)
        base = gtirb.Symbol(name='table_base_and_branch_target', payload=target, module=module)
        item = gtirb.Symbol(name='table_destination', payload=other, module=module)
        attrs = {gtirb.SymbolicExpression.Attribute.PCREL}
        for offset in (materialization_offset, transfer_offset):
            interval.symbolic_expressions[offset] = gtirb.SymAddrConst(0, base, attrs)
        data_section = gtirb.Section(name='.rodata', module=module)
        table = gtirb.ByteInterval(address=0x2000, contents=bytes(4), section=data_section)
        gtirb.DataBlock(size=4, byte_interval=table)
        table.symbolic_expressions[0] = gtirb.SymAddrAddr(1, 0, item, base)
        ir.cfg.add(gtirb.Edge(source, target, gtirb.Edge.Label(
            type=gtirb.Edge.Type.Call if call else gtirb.Edge.Type.Branch, direct=True)))
        for name, type_name in (
            ('functionEntries', 'mapping<UUID,set<UUID>>'),
            ('functionBlocks', 'mapping<UUID,set<UUID>>'),
            ('functionNames', 'mapping<UUID,UUID>')):
            module.aux_data[name] = gtirb.AuxData({}, type_name)
        transient, _, _, mapping = copy_section(section, '.teapot_transient')
        copied = next(iter(transient.byte_intervals))
        # Only address computation keeps the normal base of the uncopied table.
        self.assertIs(copied.symbolic_expressions[materialization_offset].symbol, base)
        # A direct transfer is code, even when the same symbol names that base.
        expr = copied.symbolic_expressions[transfer_offset]
        self.assertIs(expr.symbol.referent, mapping.code_blocks_map[target.uuid])
        self.assertEqual(expr.attributes, attrs)
        self.assertIs(table.symbolic_expressions[0].symbol2, base)
        copied_source = mapping.code_blocks_map[source.uuid]
        self.assertEqual({e.target for e in copied_source.outgoing_edges},
                         {mapping.code_blocks_map[target.uuid]})

    def test_branch_or_call_to_jump_table_base_stays_transient(self):
        for isa in (gtirb.Module.ISA.ARM64, gtirb.Module.ISA.X64):
            for call in (False, True):
                with self.subTest(isa=isa.name, call=call):
                    self.case(isa, call)


if __name__ == '__main__':
    unittest.main()
