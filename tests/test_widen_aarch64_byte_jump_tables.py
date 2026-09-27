import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting._modify.edit import edit_byte_interval

from teapot.arch import AArch64Architecture
from teapot.passes.preprocessing.widen_aarch64_byte_jump_tables_pass import WidenAArch64ByteJumpTablesPass
from test_live_register_preservation import make_module


class WidenByteJumpTablesTests(unittest.TestCase):
    def loop_fixture(self, partial=False, register=10):
        # Hoist ADRP x12 / ADD x10 before a guarded loop. The consumer uses
        # x10, not ADRP's destination; its backedge does not redefine x10.
        # register selects the hoisted base (x10 by default): ADD Rd and LDRB Rn.
        words = [0xb000000c, 0x91000180 | register, 0xd503201f,
                 0x7100051f, 0x540000c8,
                 0x38684809 | register << 5, 0x1000006b, 0x8b298969, 0xd61f0120,
                 0x17fffffa, 0x17fffff9]
        ir, module, setup, _, _ = make_module(AArch64Architecture(), gtirb.Module.ISA.ARM64,
                                              b''.join(w.to_bytes(4, 'little') for w in words))
        setup.size = 12
        interval = setup.byte_interval
        guard = gtirb.CodeBlock(offset=12, size=8, byte_interval=interval)
        dispatch = gtirb.CodeBlock(offset=20, size=16, byte_interval=interval)
        cases = [gtirb.CodeBlock(offset=36 + i * 4, size=4, byte_interval=interval) for i in range(2)]
        targets = [gtirb.Symbol('loop_case%d' % i, payload=b, module=module) for i, b in enumerate(cases)]
        members = {setup, guard, dispatch, *cases}
        function = next(iter(module.aux_data['functionBlocks'].data))
        module.aux_data['functionBlocks'].data[function] = members
        def edge(a, b, kind, conditional=False, direct=True):
            ir.cfg.add(gtirb.Edge(a, b, gtirb.Edge.Label(kind, conditional, direct)))
        edge(setup, guard, gtirb.Edge.Type.Fallthrough)
        edge(guard, dispatch, gtirb.Edge.Type.Fallthrough, True)
        edge(guard, cases[1], gtirb.Edge.Type.Branch, True)
        for case in cases:
            edge(dispatch, case, gtirb.Edge.Type.Branch, direct=False)
            edge(case, guard, gtirb.Edge.Type.Branch)
        section = gtirb.Section(name='.rodata', module=module)
        data = gtirb.ByteInterval(address=0x2000, contents=b'\0\1end', section=section)
        entries = [gtirb.DataBlock(offset=i, size=1, byte_interval=data) for i in range(2)]
        suffix = gtirb.DataBlock(offset=2, size=3, byte_interval=data)
        table = gtirb.Symbol('loop_table', payload=entries[0], module=module)
        interval.symbolic_expressions.update({0: gtirb.SymAddrConst(0, table),
            4: gtirb.SymAddrConst(0, table, {gtirb.SymbolicExpression.Attribute.LO12}),
            24: gtirb.SymAddrConst(0, targets[0])})
        data.symbolic_expressions.update({i: gtirb.SymAddrAddr(4, 0, target, targets[0])
                                         for i, target in enumerate(targets) if not partial or i})
        module.aux_data['symbolicExpressionSizes'] = gtirb.AuxData(
            {gtirb.Offset(data, i): 1 for i in range(2) if not partial or i}, 'mapping<Offset,uint64_t>')
        if partial:
            module.aux_data['encodings'] = gtirb.AuxData({entries[0]: 'ascii'}, 'mapping<UUID,string>')
        return ir, module, setup, guard, dispatch, data, entries, cases, suffix

    def test_hoisted_base_across_guard_and_loop_backedge(self):
        _, module, _, _, dispatch, data, entries, _, suffix = self.loop_fixture()
        # Rewriting preparation can leave zero-size symbol markers in .plt.
        # They must survive without being decoded or hiding a real table.
        plt = gtirb.Section(name='.plt', module=module)
        interval = gtirb.ByteInterval(address=0x3000,
                                      contents=bytes.fromhex('1f2003d5'), section=plt)
        marker = gtirb.CodeBlock(offset=4, size=0, byte_interval=interval)
        symbol = gtirb.Symbol('plt_end', payload=marker, module=module)
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual([b.size for b in entries], [4, 4])
        instructions = list(GtirbInstructionDecoder(module.isa).get_instructions(dispatch))
        self.assertEqual(instructions[0].mnemonic, 'ldr')
        self.assertIn('uxtw #2', instructions[0].op_str)
        self.assertIn('sxtw #2', instructions[2].op_str)
        self.assertEqual(suffix.offset, 18)
        self.assertIs(symbol.referent, marker)
        self.assertEqual((marker.address, marker.size), (0x3004, 0))

    def test_bound_and_cfg_recover_missing_symbolic_entry(self):
        _, module, _, _, _, data, entries, _, _ = self.loop_fixture(partial=True)
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual([b.size for b in entries], [4, 4])
        self.assertEqual(sorted(data.symbolic_expressions), [0, 4])
        self.assertNotIn(entries[0], module.aux_data['encodings'].data)

    def test_hoisted_base_redefinition_is_not_ignored(self):
        _, module, setup, _, _, data, _, _, _ = self.loop_fixture()
        setup.byte_interval.contents[8:12] = (0x910003ea).to_bytes(4, 'little')  # mov x10,sp
        before = bytes(data.contents), bytes(setup.contents)
        with self.assertRaisesRegex(ValueError, 'unproved.*base'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(setup.contents)), before)

    def test_partial_table_requires_all_cfg_targets(self):
        ir, module, setup, _, dispatch, data, _, cases, _ = self.loop_fixture(partial=True)
        for edge in list(dispatch.outgoing_edges):
            if edge.target is cases[0]:
                ir.cfg.discard(edge)
        # Do not leave an unreachable predecessor of the guard: that would
        # independently (and correctly) fail the reaching-base proof first.
        for edge in list(cases[0].outgoing_edges):
            ir.cfg.discard(edge)
        before = bytes(data.contents), bytes(setup.byte_interval.contents)
        with self.assertRaisesRegex(ValueError, 'CFG'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(setup.byte_interval.contents)), before)

    def test_partial_table_requires_unsigned_index_guard(self):
        _, module, _, guard, _, data, _, _, _ = self.loop_fixture(partial=True)
        # B.GT does not exclude negative indexes.
        guard.byte_interval.contents[16:20] = (0x540000cc).to_bytes(4, 'little')
        before = bytes(data.contents)
        with self.assertRaisesRegex(ValueError, 'bound'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual(bytes(data.contents), before)

    def test_hoisted_base_cannot_cross_a_call(self):
        _, module, setup, _, _, data, _, _, _ = self.loop_fixture()
        setup.byte_interval.contents[8:12] = (0x94000000).to_bytes(4, 'little')
        before = bytes(data.contents), bytes(setup.byte_interval.contents)
        with self.assertRaisesRegex(ValueError, 'unproved.*base'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(setup.byte_interval.contents)), before)

    def test_all_reaching_definitions_must_agree(self):
        ir, module, setup, guard, _, data, _, _, _ = self.loop_fixture()
        interval = gtirb.ByteInterval(address=0x4000, section=setup.section,
                                     contents=bytes.fromhex('0a00001000000014'))  # ADR x10; B
        alternate = gtirb.CodeBlock(size=8, byte_interval=interval)
        table = setup.byte_interval.symbolic_expressions[0].symbol
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(1, table)
        function = next(iter(module.aux_data['functionBlocks'].data))
        for name in ('functionBlocks', 'functionEntries'):
            module.aux_data[name].data[function].add(alternate)
        ir.cfg.add(gtirb.Edge(alternate, guard, gtirb.Edge.Label(gtirb.Edge.Type.Branch)))
        before = bytes(data.contents), bytes(setup.byte_interval.contents)
        with self.assertRaisesRegex(ValueError, 'unproved.*base'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(setup.byte_interval.contents)), before)

    def test_hoisted_base_rejects_another_byte_stride_use(self):
        _, module, setup, _, _, data, _, _, _ = self.loop_fixture()
        setup.byte_interval.contents[8:12] = (0x39400140).to_bytes(4, 'little')  # LDRB w0,[x10]
        before = bytes(data.contents), bytes(setup.byte_interval.contents)
        with self.assertRaisesRegex(ValueError, 'unrecognized register use'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(setup.byte_interval.contents)), before)

    def call_exit_fixture(self, callee_words=None, *, reads_after=False, external=None, register=10):
        ir, module, setup, _, _, data, entries, cases, _ = self.loop_fixture(register=register)
        caller = cases[0]
        for edge in list(caller.outgoing_edges):
            ir.cfg.discard(edge)
        caller.byte_interval.contents[caller.offset:caller.offset + 4] = (0x94000000).to_bytes(4, 'little')
        if external:
            callee = gtirb.ProxyBlock(module=module)
            gtirb.Symbol(external, payload=callee, module=module)
        else:
            contents = b''.join(word.to_bytes(4, 'little') for word in callee_words)
            interval = gtirb.ByteInterval(address=0x4000, contents=contents, section=setup.section)
            callee = gtirb.CodeBlock(size=len(contents), byte_interval=interval)
        # Optionally read the base (LDRB w0,[xN]), then kill it (MOV xN,#0) and return.
        words = ([0x39400000 | register << 5] if reads_after else []) + [0xd2800000 | register, 0xd65f03c0]
        contents = b''.join(word.to_bytes(4, 'little') for word in words)
        interval = gtirb.ByteInterval(address=0x5000, contents=contents, section=setup.section)
        after = gtirb.CodeBlock(size=len(contents), byte_interval=interval)
        function = next(iter(module.aux_data['functionBlocks'].data))
        module.aux_data['functionBlocks'].data[function].add(after)
        ir.cfg.add(gtirb.Edge(caller, callee, gtirb.Edge.Label(gtirb.Edge.Type.Call)))
        ir.cfg.add(gtirb.Edge(caller, after, gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
        return module, data, entries

    def test_unused_base_killed_by_callee_is_safe(self):
        module, _, entries = self.call_exit_fixture([0xd280000a, 0xd65f03c0])  # MOV x10,#0; RET
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual([block.size for block in entries], [4, 4])

    def test_call_cannot_hide_a_table_read(self):
        module, data, _ = self.call_exit_fixture([0x39400140, 0xd65f03c0])  # LDRB w0,[x10]; RET
        before = bytes(data.contents)
        with self.assertRaisesRegex(ValueError, 'unproved call'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual(bytes(data.contents), before)

    def test_preserved_call_base_is_tracked_until_overwritten(self):
        for reads_after in (False, True):
            with self.subTest(reads_after=reads_after):
                module, data, entries = self.call_exit_fixture([0xd65f03c0], reads_after=reads_after)
                if reads_after:
                    before = bytes(data.contents)
                    with self.assertRaisesRegex(ValueError, 'unrecognized register use'):
                        WidenAArch64ByteJumpTablesPass().end_module(module, [])
                    self.assertEqual(bytes(data.contents), before)
                else:
                    WidenAArch64ByteJumpTablesPass().end_module(module, [])
                    self.assertEqual([block.size for block in entries], [4, 4])

    def test_noargument_errno_summary_keeps_other_registers_tracked(self):
        for reads_after in (False, True):
            with self.subTest(reads_after=reads_after):
                module, _, entries = self.call_exit_fixture(external='__errno_location', reads_after=reads_after)
                if reads_after:
                    with self.assertRaisesRegex(ValueError, 'unrecognized register use'):
                        WidenAArch64ByteJumpTablesPass().end_module(module, [])
                else:
                    WidenAArch64ByteJumpTablesPass().end_module(module, [])
                    self.assertEqual([block.size for block in entries], [4, 4])

    def interleaved_fixture(self, middle_word):
        # ADRP x12; <middle>; ADD x10,x12,#lo12 -- the scheduler split the pair.
        fixture = self.loop_fixture()
        interval = fixture[2].byte_interval
        add = bytes(interval.contents[4:8])
        interval.contents[4:8] = middle_word.to_bytes(4, 'little')
        interval.contents[8:12] = add
        interval.symbolic_expressions[8] = interval.symbolic_expressions.pop(4)
        return fixture

    def test_hoisted_base_with_interleaved_adrp_add(self):
        _, module, _, _, _, _, entries, _, _ = self.interleaved_fixture(0xaa0203e1)  # MOV x1, x2
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual([b.size for b in entries], [4, 4])

    def test_interleaved_write_of_adrp_register_is_rejected(self):
        _, module, setup, _, _, data, _, _, _ = self.interleaved_fixture(0xaa0203ec)  # MOV x12, x2
        before = bytes(data.contents), bytes(setup.byte_interval.contents)
        with self.assertRaisesRegex(ValueError, 'unproved.*base'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(setup.byte_interval.contents)), before)

    def test_callee_saved_base_path_ends_at_noreturn_call(self):
        # x21 base; case 0 ends in BL abort with only a call edge (no fallthrough).
        ir, module, setup, _, _, _, entries, cases, _ = self.loop_fixture(register=21)
        caller = cases[0]
        for edge in list(caller.outgoing_edges):
            ir.cfg.discard(edge)
        caller.byte_interval.contents[caller.offset:caller.offset + 4] = (0x94000000).to_bytes(4, 'little')
        callee = gtirb.ProxyBlock(module=module)
        gtirb.Symbol('abort', payload=callee, module=module)
        ir.cfg.add(gtirb.Edge(caller, callee, gtirb.Edge.Label(gtirb.Edge.Type.Call)))
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual([b.size for b in entries], [4, 4])

    def test_callee_saved_hoisted_base_crosses_a_call(self):
        # Same hoisted loop as test_hoisted_base_cannot_cross_a_call, but the base
        # is in callee-saved x21, which AAPCS64 preserves across the BL.
        _, module, setup, _, _, _, entries, _, _ = self.loop_fixture(register=21)
        setup.byte_interval.contents[8:12] = (0x94000000).to_bytes(4, 'little')
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual([b.size for b in entries], [4, 4])

    def test_callee_saved_base_survives_unknown_external_call(self):
        for reads_after in (False, True):
            with self.subTest(reads_after=reads_after):
                module, data, entries = self.call_exit_fixture(external='unknown_consumer',
                                                               reads_after=reads_after, register=21)
                if reads_after:
                    # Still tracked after the call: another byte-stride read is rejected.
                    before = bytes(data.contents)
                    with self.assertRaisesRegex(ValueError, 'unrecognized register use'):
                        WidenAArch64ByteJumpTablesPass().end_module(module, [])
                    self.assertEqual(bytes(data.contents), before)
                else:
                    WidenAArch64ByteJumpTablesPass().end_module(module, [])
                    self.assertEqual([block.size for block in entries], [4, 4])

    def test_caller_saved_base_still_cannot_cross_unknown_external_call(self):
        module, data, _ = self.call_exit_fixture(external='unknown_consumer', register=10)
        before = bytes(data.contents)
        with self.assertRaisesRegex(ValueError, 'unproved call'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual(bytes(data.contents), before)

    def test_unproved_returned_table_pointer_is_rejected(self):
        for register in (0, 1):
            with self.subTest(register=register):
                ir, module, setup, _, dispatch, data, _, cases, _ = self.loop_fixture()
                interval = setup.byte_interval
                low = int.from_bytes(interval.contents[4:8], 'little')
                interval.contents[4:8] = ((low & ~31) | register).to_bytes(4, 'little')
                load = int.from_bytes(dispatch.contents[:4], 'little')
                interval.contents[dispatch.offset:dispatch.offset + 4] = (
                    (load & ~(31 << 5)) | (register << 5)).to_bytes(4, 'little')
                case = cases[0]
                interval.contents[case.offset:case.offset + 4] = (0xd65f03c0).to_bytes(4, 'little')
                for edge in list(case.outgoing_edges):
                    ir.cfg.discard(edge)
                before = bytes(data.contents), bytes(interval.contents)
                with self.assertRaisesRegex(ValueError, 'return value'):
                    WidenAArch64ByteJumpTablesPass().end_module(module, [])
                self.assertEqual((bytes(data.contents), bytes(interval.contents)), before)

    def pointer_return_fixture(self, register=1):
        from teapot.utils.return_abi import POINTER_RETURNS, SCHEMA, function_fingerprint
        ir, module, setup, _, dispatch, data, entries, cases, _ = self.loop_fixture()
        interval = setup.byte_interval
        low = int.from_bytes(interval.contents[4:8], 'little')
        interval.contents[4:8] = ((low & ~31) | register).to_bytes(4, 'little')
        load = int.from_bytes(dispatch.contents[:4], 'little')
        interval.contents[dispatch.offset:dispatch.offset + 4] = (
            (load & ~(31 << 5)) | (register << 5)).to_bytes(4, 'little')
        case = cases[0]
        interval.contents[case.offset:case.offset + 4] = (0xd65f03c0).to_bytes(4, 'little')
        for edge in list(case.outgoing_edges):
            ir.cfg.discard(edge)
        function = next(iter(module.aux_data['functionBlocks'].data))
        module.aux_data[POINTER_RETURNS] = gtirb.AuxData(
            {function: (function_fingerprint(module, function), 'a' * 64)}, SCHEMA)
        return module, setup, data, entries

    def test_bound_pointer_return_allows_only_unused_x1(self):
        from teapot.utils.return_abi import POINTER_RETURNS
        module, _, _, entries = self.pointer_return_fixture()
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual([b.size for b in entries], [4, 4])
        self.assertNotIn(POINTER_RETURNS, module.aux_data)

    def test_pointer_signature_does_not_hide_an_x0_escape(self):
        module, setup, data, _ = self.pointer_return_fixture(register=0)
        before = bytes(data.contents), bytes(setup.byte_interval.contents)
        with self.assertRaisesRegex(ValueError, 'return value'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(setup.byte_interval.contents)), before)

    def test_pointer_signature_is_invalidated_by_body_changes(self):
        module, setup, data, _ = self.pointer_return_fixture()
        setup.byte_interval.contents[8:12] = (0x2a0803e8).to_bytes(4, 'little')  # MOV w8,w8
        before = bytes(data.contents), bytes(setup.byte_interval.contents)
        with self.assertRaisesRegex(ValueError, 'stale pointer-return ABI'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(setup.byte_interval.contents)), before)

    def test_pointer_signature_survives_uniform_function_relocation(self):
        from teapot.utils.return_abi import has_pointer_return_contract
        module, setup, _, _ = self.pointer_return_fixture()
        function = next(iter(module.aux_data['functionBlocks'].data))
        setup.byte_interval.address += 0x100000
        self.assertTrue(has_pointer_return_contract(module, function))

    def test_pointer_signature_rejects_independent_block_relocation(self):
        from teapot.utils.return_abi import has_pointer_return_contract
        module, setup, _, _ = self.pointer_return_fixture()
        function = next(iter(module.aux_data['functionBlocks'].data))
        block = next(b for b in module.aux_data['functionBlocks'].data[function] if b is not setup)
        relocated = gtirb.ByteInterval(address=block.address + 0x100000,
                                      contents=bytes(block.contents), section=block.section)
        block.byte_interval = relocated
        block.offset = 0
        with self.assertRaisesRegex(ValueError, 'stale pointer-return ABI'):
            has_pointer_return_contract(module, function)

    def test_recovered_target_gets_serializable_local_symbol(self):
        ir, module, _, _, _, data, _, cases, _ = self.loop_fixture()
        del data.symbolic_expressions[1]
        del module.aux_data['symbolicExpressionSizes'].data[gtirb.Offset(data, 1)]
        for symbol in list(cases[1].references):
            module.symbols.remove(symbol)
        module.aux_data['elfSymbolInfo'] = gtirb.AuxData(
            {}, 'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        symbol = data.symbolic_expressions[4].symbol1
        self.assertIs(symbol.module, module)
        self.assertIs(symbol.referent, cases[1])
        self.assertEqual(module.aux_data['elfSymbolInfo'].data[symbol], (0, 'NOTYPE', 'LOCAL', 'DEFAULT', 1))
        stream = io.BytesIO()
        ir.save_protobuf_file(stream)
        stream.seek(0)
        restored = gtirb.IR.load_protobuf_file(stream).modules[0]
        self.assertIsNotNone(next(restored.symbols_named(symbol.name)).referent)

    def fixture(self, signed=True, negative=False):
        add = 0x8b298909 if signed else 0x8b290909
        words = [0xb0000009, 0x91000129, 0x38684929, 0x10000068, add, 0xd61f0120,
                 0xd65f03c0, 0xd65f03c0]
        ir, module, source, _, _ = make_module(AArch64Architecture(), gtirb.Module.ISA.ARM64,
                                              b''.join(w.to_bytes(4, 'little') for w in words))
        source.size = 24
        interval = source.byte_interval
        cases = [gtirb.CodeBlock(offset=24 + i * 4, size=4, byte_interval=interval) for i in range(2)]
        targets = [gtirb.Symbol('case%d' % i, payload=case, module=module) for i, case in enumerate(cases)]
        base = targets[1 if negative else 0]
        section = gtirb.Section(name='.rodata', module=module)
        data = gtirb.ByteInterval(address=0x2000, contents=(b'\xff\0' if negative else b'\0\1') + b'end', section=section)
        entries = [gtirb.DataBlock(offset=i, size=1, byte_interval=data) for i in range(2)]
        suffix = gtirb.DataBlock(offset=2, size=3, byte_interval=data)
        table = gtirb.Symbol('table', payload=entries[0], module=module)
        after = gtirb.Symbol('after', payload=suffix, module=module)
        interval.symbolic_expressions.update({0: gtirb.SymAddrConst(0, table),
            4: gtirb.SymAddrConst(0, table, {gtirb.SymbolicExpression.Attribute.LO12}),
            12: gtirb.SymAddrConst(0, base)})
        data.symbolic_expressions.update({i: gtirb.SymAddrAddr(4, 0, target, base)
                                          for i, target in enumerate(targets)})
        module.aux_data['symbolicExpressionSizes'] = gtirb.AuxData(
            {gtirb.Offset(data, i): 1 for i in range(2)}, 'mapping<Offset,uint64_t>')
        return ir, module, source, data, entries, after

    def test_signed_unsigned_and_negative_tables(self):
        for signed, negative in ((True, False), (False, False), (True, True)):
            with self.subTest(signed=signed, negative=negative):
                ir, module, source, data, entries, after = self.fixture(signed, negative)
                WidenAArch64ByteJumpTablesPass().end_module(module, [])
                self.assertEqual([b.size for b in entries], [4, 4])
                self.assertEqual([b.offset for b in entries], [0, 4])
                self.assertEqual(after.referent.offset, 18)
                self.assertEqual(bytes(data.contents[8:18]), bytes(10))
                self.assertEqual(bytes(after.referent.contents), b'end')
                self.assertEqual(bytes(data.contents[:8]), b'\xff' * 4 + bytes(4) if negative else
                                 bytes(4) + b'\1\0\0\0')
                self.assertEqual({p: e.scale for p, e in data.symbolic_expressions.items()}, {0: 4, 4: 4})
                self.assertEqual({o.displacement: v for o, v in module.aux_data['symbolicExpressionSizes'].data.items()},
                                 {0: 4, 4: 4})
                instructions = list(GtirbInstructionDecoder(module.isa).get_instructions(source))
                self.assertEqual(instructions[2].mnemonic, 'ldr')
                self.assertIn('uxtw #2', instructions[2].op_str)
                self.assertIn(('sxtw' if signed else 'uxtw') + ' #2', instructions[4].op_str)
                stream = io.BytesIO()
                ir.save_protobuf_file(stream)
                stream.seek(0)
                self.assertEqual(len(list(gtirb.IR.load_protobuf_file(stream).modules[0].data_blocks)), 4)

    def test_linker_relaxed_nop_adr_materialization(self):
        _, module, source, data, entries, after = self.fixture()
        interval = source.byte_interval
        table = interval.symbolic_expressions[0].symbol
        interval.contents[:8] = bytes.fromhex('1f2003d509000010')  # NOP; ADR x9, ...
        del interval.symbolic_expressions[0]
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, table)
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual([b.size for b in entries], [4, 4])
        self.assertEqual(after.referent.offset, 18)
        instructions = list(GtirbInstructionDecoder(module.isa).get_instructions(source))
        self.assertEqual([i.mnemonic for i in instructions[:4]], ['nop', 'adr', 'ldr', 'adr'])
        self.assertIn('uxtw #2', instructions[2].op_str)
        self.assertIn('sxtw #2', instructions[4].op_str)

    def test_following_unannotated_scaled_load_alignment_is_preserved(self):
        _, module, _, data, _, after = self.fixture()
        data.contents = bytes(data.contents[:2]) + bytes(14) + bytes(range(16))
        data.size = len(data.contents)
        after.referent.offset, after.referent.size = 16, 16
        gtirb.DataBlock(offset=2, size=14, byte_interval=data)
        self.assertNotIn(after.referent, module.aux_data.get('alignment', gtirb.AuxData({}, 'mapping<UUID,uint64_t>')).data)
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual(after.referent.address % 16, 0)
        self.assertEqual(bytes(after.referent.contents), bytes(range(16)))

    def test_larger_explicit_suffix_alignment_is_preserved(self):
        _, module, _, data, _, after = self.fixture()
        data.contents = bytes(data.contents[:2]) + bytes(62) + b'end'
        data.size = len(data.contents)
        after.referent.offset = 64
        gtirb.DataBlock(offset=2, size=62, byte_interval=data)
        module.aux_data['alignment'] = gtirb.AuxData({after.referent: 64}, 'mapping<UUID,uint64_t>')
        WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual(after.referent.offset, 128)
        self.assertEqual(module.aux_data['alignment'].data[after.referent], 64)

    def test_other_table_reference_is_rejected_before_mutation(self):
        _, module, source, data, _, _ = self.fixture()
        data.symbolic_expressions[2] = gtirb.SymAddrConst(0, source.byte_interval.symbolic_expressions[0].symbol)
        before = bytes(data.contents), bytes(source.contents)
        with self.assertRaisesRegex(ValueError, 'unrecognized reference'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
        self.assertEqual((bytes(data.contents), bytes(source.contents)), before)

    def test_incorrect_original_expression_is_rejected(self):
        _, module, source, data, _, _ = self.fixture()
        data.contents[1] = 2
        with self.assertRaisesRegex(ValueError, 'disagrees with its original lookup'):
            WidenAArch64ByteJumpTablesPass().end_module(module, [])

    @unittest.skipUnless(all(shutil.which(x) for x in ('ddisasm', 'aarch64-linux-gnu-gcc', 'qemu-aarch64')),
                         'AArch64 frontend/toolchain required')
    def test_real_dispatch_survives_large_case_growth(self):
        self._run_real_dispatch()

    @unittest.skipUnless(all(shutil.which(x) for x in ('ddisasm', 'aarch64-linux-gnu-gcc', 'qemu-aarch64')),
                         'AArch64 frontend/toolchain required')
    def test_real_hoisted_partial_table_survives_large_case_growth(self):
        self._run_real_dispatch(hoisted=True)

    def _run_real_dispatch(self, hoisted=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly = root / 'input.S'
            text = '''
.text
.global _start
.type _start,%function
_start:
 adrp x10,constant
 ldr q0,[x10,:lo12:constant]
 ldr w8,[sp]
 cmp w8,#1
 b.hi case0
 adrp x9,table
 add x9,x9,:lo12:table
 ldrb w9,[x9,w8,uxtw]
 adr x8,case0
 add x9,x8,w9,sxtb #2
 br x9
case0:
 mov x0,#17
 mov x8,#93
 svc #0
case1:
 mov x0,#23
 mov x8,#93
 svc #0
.size _start,.-_start
.section .rodata
.type table,%object
table: .byte (case0-case0)/4,(case1-case0)/4
.size table,.-table
.balign 16
.type constant,%object
constant: .quad 1,2
.size constant,.-constant
.section .note.GNU-stack,"",%progbits
'''
            if hoisted:
                begin = text.index('_start:\n')
                end = text.index('.size _start,.-_start')
                text = text[:begin] + '''_start:
 adrp x15,constant
 ldr q0,[x15,:lo12:constant]
 adrp x12,table
 add x10,x12,:lo12:table
 ldr w8,[sp]
 mov w7,#2
 nop
guard:
 cmp w8,#1
 b.hi case0
dispatch:
 ldrb w9,[x10,w8,uxtw]
 adr x11,case0
 add x9,x11,w9,sxtb #2
 br x9
case0:
 mov x0,#17
 b next
case1:
 mov x0,#23
next:
 subs w7,w7,#1
 b.ne guard
 mov x10,#0
 mov x8,#93
 svc #0
''' + text[end:]
            assembly.write_text(text)
            flags = ['-nostdlib', '-static', '-no-pie', '-Wl,--build-id=none', '-Wa,--fatal-warnings']
            subprocess.run(['aarch64-linux-gnu-gcc', *flags, str(assembly), '-o', str(root / 'original')],
                           check=True, capture_output=True)
            subprocess.run(['ddisasm', str(root / 'original'), '--ir', str(root / 'input.gtirb'), '-j', '1'],
                           check=True, capture_output=True)
            ir = gtirb.IR.load_protobuf(root / 'input.gtirb')
            module = ir.modules[0]
            if hoisted:
                table = next(module.symbols_named('table')).referent
                self.assertIn(table.offset, table.byte_interval.symbolic_expressions)
                del table.byte_interval.symbolic_expressions[table.offset]
                del module.aux_data['symbolicExpressionSizes'].data[gtirb.Offset(table.byte_interval, table.offset)]
                module.aux_data.setdefault('encodings', gtirb.AuxData({}, 'mapping<UUID,string>')).data[table] = 'ascii'
            WidenAArch64ByteJumpTablesPass().end_module(module, [])
            # Model instrumentation growing a case beyond signed-byte range.
            block = next(module.symbols_named('case0')).referent
            edit_byte_interval(block.byte_interval, block.offset + 4, 0, bytes.fromhex('1f2003d5') * 512)
            ir.save_protobuf(root / 'grown.gtirb')
            subprocess.run([os.environ.get('PPRINTER_PATH', 'gtirb-pprinter'), '--ir', str(root / 'grown.gtirb'),
                            '--asm', str(root / 'grown.S')], check=True, capture_output=True)
            subprocess.run(['aarch64-linux-gnu-gcc', *flags, str(root / 'grown.S'), '-o', str(root / 'grown')],
                           check=True, capture_output=True)
            for argv, expected in (([], 23), (['extra'], 17)):
                result = subprocess.run(['qemu-aarch64', str(root / 'grown'), *argv], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)


if __name__ == '__main__':
    unittest.main()
