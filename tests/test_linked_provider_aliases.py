"""A direct callee relocation takes precedence over incidental PLT labels."""
from types import SimpleNamespace
import unittest

import gtirb

from teapot.arch.riscv64.architecture import RISCV64Architecture
from teapot.arch.x64.architecture import X64Architecture
from teapot.passes.transient.transient_insert_restore_points_pass import TransientInsertRestorePointsPass


class LinkedProviderAliasTests(unittest.TestCase):
    def target(self, *, isa='rv', name='provider', addend=0, direct=True,
               expression=True, conflicting_expression=False):
        module = gtirb.Module(name='plt-alias', file_format=gtirb.Module.FileFormat.ELF,
                              isa=gtirb.Module.ISA.RISCV64 if isa == 'rv' else gtirb.Module.ISA.X64)
        gtirb.IR(modules=[module])
        text = gtirb.Section(name='.text', module=module)
        # JAL ra,0 or CALL rel32: the last instruction has one callee expression.
        contents = bytes.fromhex('ef000000') if isa == 'rv' else bytes.fromhex('e800000000')
        interval = gtirb.ByteInterval(address=0x1000, contents=contents, section=text)
        block = gtirb.CodeBlock(size=len(contents), byte_interval=interval)
        plt = gtirb.Section(name='.plt', module=module)
        target_interval = gtirb.ByteInterval(address=0x2000, contents=bytes(16), section=plt)
        target = gtirb.CodeBlock(size=16, byte_interval=target_interval)
        entry = gtirb.Symbol(name='FUN_2000', payload=target, module=module)
        # DDisasm also names the AUIPC at this PLT entry. It is not a callee.
        gtirb.Symbol(name='.L_pcrel_2000', payload=target, module=module)
        provider = gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        module.aux_data['symbolForwarding'] = gtirb.AuxData({entry: provider}, 'mapping<UUID,UUID>')
        if expression:
            interval.symbolic_expressions[0 if isa == 'rv' else 1] = gtirb.SymAddrConst(addend, entry)
        if conflicting_expression:
            other = gtirb.Symbol(name='unselected', payload=gtirb.ProxyBlock(module=module), module=module)
            interval.symbolic_expressions[2] = gtirb.SymAddrConst(0, other)
        edge = gtirb.Edge(block, target, gtirb.Edge.Label(type=gtirb.EdgeType.Call, direct=direct))
        arch = RISCV64Architecture() if isa == 'rv' else X64Architecture()
        visitor = TransientInsertRestorePointsPass(None, text, text, None, arch,
                                                   linked_function_symbols={'provider'})
        instructions = [SimpleNamespace(address=0x1000, size=len(contents))]
        return visitor._targets_linked_component(block, instructions, edge)

    def test_forwarded_direct_callee_is_not_vetoed_by_plt_anchor(self):
        for isa in ('rv', 'x64'):
            with self.subTest(isa=isa):
                self.assertTrue(self.target(isa=isa))

    def test_unselected_or_interior_callee_remains_external(self):
        for options in ({'name': 'puts'}, {'addend': 4}, {'addend': -4}):
            with self.subTest(options=options):
                self.assertFalse(self.target(**options))

    def test_unresolved_or_indirect_target_is_not_promoted_by_alias(self):
        self.assertFalse(self.target(expression=False))
        self.assertFalse(self.target(direct=False))

    def test_conflicting_instruction_expression_stays_rejected(self):
        self.assertFalse(self.target(conflicting_expression=True))


if __name__ == '__main__':
    unittest.main()
