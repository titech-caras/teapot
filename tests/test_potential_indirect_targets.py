"""Normal-text blocks padded although the lift found no indirect edge to them."""
import io
from contextlib import redirect_stdout
from types import SimpleNamespace
import unittest
import unittest.mock
from unittest.mock import Mock
from uuid import uuid4

import gtirb
from gtirb_functions import Function
from gtirb_rewriting import Patch, RewritingContext, patch_constraints
from gtirb_rewriting.decoder import GtirbInstructionDecoder

from teapot.arch import X64Architecture
from teapot.passes.text.indirect_targets import potential_indirect_targets, unsymbolized_data_targets
from teapot.passes.text.text_indirect_branch_transform_pass import (
    DIRECT_ENTRY_PREFIX, TextIndirectBranchTransformPass)

CODE = bytes.fromhex(
    "c3"              # 0x1000 f:      ret                         (called directly only)
    "e8faffffff"      # 0x1001 caller: call f                      (the lift thinks f never returns)
    "c3"              # 0x1006 after:  ret                         (the site after that call)
    "c3"              # 0x1007 taken:  ret                         (its address is in .data)
    "ff24c500200000"  # 0x1008 jump:   jmp [rax*8 + 0x2000]        (a table the lift did not resolve)
    "c3"              # 0x100f later:  ret                         (same function as the jump)
    "5bffe0")         # 0x1010 tail:   pop rbx; jmp rax            (an indirect tail call)


def module_with_targets():
    module = gtirb.Module(name="targets", isa=gtirb.Module.ISA.X64,
                          file_format=gtirb.Module.FileFormat.ELF,
                          byte_order=gtirb.Module.ByteOrder.Little)
    ir = gtirb.IR(modules=[module])
    code = {gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable,
            gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized}
    data = {gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable,
            gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized}
    text = gtirb.Section(name=".text", flags=code, module=module)
    interval = gtirb.ByteInterval(section=text, address=0x1000, contents=CODE)
    blocks = {name: gtirb.CodeBlock(offset=offset, size=size, byte_interval=interval)
              for name, offset, size in (("f", 0, 1), ("caller", 1, 5), ("after", 6, 1),
                                         ("taken", 7, 1), ("jump", 8, 7), ("later", 15, 1),
                                         ("tail", 16, 3))}
    f = gtirb.Symbol(name="f", payload=blocks["f"], module=module)
    interval.symbolic_expressions[2] = gtirb.SymAddrConst(0, f)
    ir.cfg.add(gtirb.Edge(blocks["caller"], blocks["f"],
                          gtirb.Edge.Label(gtirb.Edge.Type.Call, direct=True)))
    ir.cfg.add(gtirb.Edge(blocks["jump"], gtirb.ProxyBlock(module=module),
                          gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)))
    ir.cfg.add(gtirb.Edge(blocks["jump"], blocks["later"],
                          gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
    ir.cfg.add(gtirb.Edge(blocks["tail"], gtirb.ProxyBlock(module=module),
                          gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)))

    data_section = gtirb.Section(name=".data", flags=data, module=module)
    words = (0).to_bytes(8, "little") + (0x100f).to_bytes(8, "little")
    data_interval = gtirb.ByteInterval(section=data_section, address=0x2000, contents=words)
    data_interval.symbolic_expressions[0] = gtirb.SymAddrConst(
        0, gtirb.Symbol(name="taken", payload=blocks["taken"], module=module))
    # Unwind metadata names code too, but nothing branches through it.
    eh_frame = gtirb.Section(name=".eh_frame", flags=data - {gtirb.Section.Flag.Writable}, module=module)
    eh_interval = gtirb.ByteInterval(section=eh_frame, address=0x3000, contents=bytes(8))
    eh_interval.symbolic_expressions[0] = gtirb.SymAddrConst(
        0, gtirb.Symbol(name="after_label", payload=blocks["after"], module=module))

    def named(name):
        return {gtirb.Symbol(name=name + "_fn", payload=blocks[name], module=module)}

    functions = [
        Function(uuid4(), {blocks["f"]}, {blocks["f"]}, {f}),
        Function(uuid4(), {blocks["caller"]}, {blocks["caller"], blocks["after"], blocks["taken"]},
                 named("caller")),
        Function(uuid4(), {blocks["jump"]}, {blocks["jump"], blocks["later"]}, named("jump")),
        Function(uuid4(), {blocks["tail"]}, {blocks["tail"]}, named("tail")),
    ]
    return ir, module, text, blocks, functions


class PotentialIndirectTargetTests(unittest.TestCase):
    def test_returns_and_symbol_targets_are_not_unresolved_jumps(self):
        from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder

        from teapot.arch import RISCV64Architecture
        from teapot.passes.text.indirect_targets import _unresolved_jump

        # The production decoder: it spells jr a0 as jalr zero, 0(a0), with
        # an immediate offset operand.
        module = gtirb.Module(name="m", isa=gtirb.Module.ISA.ValidButUnsupported,
                              file_format=gtirb.Module.FileFormat.ELF)
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
        ir = gtirb.IR(modules=[module])
        section = gtirb.Section(name=".text", module=module)
        interval = gtirb.ByteInterval(section=section, address=0x1000,
                                      contents=bytes.fromhex("67800000" "67000500" "8287"))
        decoder = CachedGtirbInstructionDecoder(module.isa)
        ret, jr, c_jr = (list(decoder.get_instructions(gtirb.CodeBlock(
            offset=offset, size=size, byte_interval=interval)))[-1]
            for offset, size in ((0, 4), (4, 4), (8, 2)))
        self.assertEqual(jr.mnemonic, "jalr")
        block = gtirb.CodeBlock(offset=0, size=4, byte_interval=interval)
        arch = RISCV64Architecture()
        # Capstone 6 puts RISC-V ret in the jump group.
        self.assertFalse(_unresolved_jump(block, ret, arch))
        self.assertTrue(_unresolved_jump(block, jr, arch))
        self.assertTrue(_unresolved_jump(block, c_jr, arch))
        external = gtirb.ProxyBlock(module=module)
        gtirb.Symbol(name="puts", payload=external, module=module)
        edge = gtirb.Edge(block, external, gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False))
        ir.cfg.add(edge)
        self.assertFalse(_unresolved_jump(block, jr, arch))
        ir.cfg.discard(edge)
        ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                              gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)))
        self.assertTrue(_unresolved_jump(block, jr, arch))

    def test_rules(self):
        _, module, text, blocks, functions = module_with_targets()
        rules = potential_indirect_targets(module, text, functions,
                                           GtirbInstructionDecoder(module.isa), X64Architecture())
        uuid = {name: block.uuid for name, block in blocks.items()}
        # A function entry is not a target by itself: f is only called directly.
        self.assertNotIn("function-entry", rules)
        # The direct call operand and the unwind metadata do not take an address.
        self.assertEqual(rules["address-taken"], {uuid["taken"]})
        # The table dispatch pads its function; the tail call does not.
        self.assertEqual(rules["unresolved-jump-function"], {uuid["jump"], uuid["later"]})
        # Only counted: an integer can equal an address.
        self.assertEqual(unsymbolized_data_targets(module, text), {uuid["later"]})

    def test_riscv_call_pairs_do_not_take_an_address(self):
        from teapot.arch import RISCV64Architecture

        # auipc ra,0; jalr ra,0(ra) calls f; auipc a0,0; addi a0,a0,0 loads g's
        # address; f: ret; g: ret.
        module = gtirb.Module(name="rv", isa=gtirb.Module.ISA.ValidButUnsupported,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        gtirb.IR(modules=[module])
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
        text = gtirb.Section(name=".text", module=module,
                             flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Loaded,
                                    gtirb.Section.Flag.Initialized, gtirb.Section.Flag.Readable})
        code = bytes.fromhex("97000000" "e7800000" "17050000" "13050500" "67800000" "67800000")
        interval = gtirb.ByteInterval(section=text, address=0x1000, contents=code)
        call = gtirb.CodeBlock(offset=0, size=8, byte_interval=interval)
        load = gtirb.CodeBlock(offset=8, size=12, byte_interval=interval)
        f = gtirb.CodeBlock(offset=16, size=4, byte_interval=interval)
        g = gtirb.CodeBlock(offset=20, size=4, byte_interval=interval)
        attrs = gtirb.SymbolicExpression.Attribute
        f_symbol = gtirb.Symbol(name="f", payload=f, module=module)
        g_symbol = gtirb.Symbol(name="g", payload=g, module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, f_symbol, {attrs.PLT})
        interval.symbolic_expressions[8] = gtirb.SymAddrConst(0, g_symbol, {attrs.PCREL, attrs.HI})
        interval.symbolic_expressions[12] = gtirb.SymAddrConst(0, g_symbol, {attrs.PCREL, attrs.LO})
        functions = [Function(uuid4(), {call}, {call, load}), Function(uuid4(), {f}, {f}),
                     Function(uuid4(), {g}, {g})]
        from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
        rules = potential_indirect_targets(module, text, functions,
                                           CachedGtirbInstructionDecoder(module.isa),
                                           RISCV64Architecture())
        self.assertEqual(rules["address-taken"], {g.uuid})
        # The %pcrel_lo half names the AUIPC's own block; that is not an address use.
        interval.symbolic_expressions[12] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name=".Lpcrel_hi", payload=load, module=module), {attrs.PCREL, attrs.LO})
        rules = potential_indirect_targets(module, text, functions,
                                           CachedGtirbInstructionDecoder(module.isa),
                                           RISCV64Architecture())
        self.assertEqual(rules["address-taken"], {g.uuid})

    def test_text_pass_pads_targets_and_no_return_call_sites(self):
        _, module, text, blocks, functions = module_with_targets()
        arch = X64Architecture()
        potential = {blocks[name].uuid for name in ("f", "taken")}
        flags_dead = {blocks[name].uuid for name in ("f", "after")}
        visitor = TextIndirectBranchTransformPass(
            text, SimpleNamespace(code_blocks_map={b.uuid: b for b in blocks.values()}),
            GtirbInstructionDecoder(module.isa), arch,
            potential_targets=potential, flags_dead_blocks=flags_dead)
        marker = patch_constraints()(lambda _ctx: "nop")
        visitor._indirect_transform_target_patch = Mock(return_value=marker)
        context = RewritingContext(module, functions)
        with redirect_stdout(io.StringIO()) as output:
            visitor.begin_module(module, functions, context)
        name = {block.uuid: key for key, block in blocks.items()}
        pads = {}
        for call in visitor._indirect_transform_target_patch.call_args_list:
            pads.setdefault(name[call.args[2].uuid], []).append(call.kwargs["flags_live"])
        # f, called directly only, is padded as a potential target; caller,
        # taken, jump and after have no predecessor at all; after is also the
        # site after the call, padded at the caller's end. Pads where the
        # flags are dead need no flag save.
        self.assertEqual(pads, {"f": [False], "caller": [True], "taken": [True], "jump": [True],
                                "tail": [True], "after": [False, False]})
        self.assertEqual(visitor.pad_counts["potential"], 1)
        self.assertEqual(visitor.pad_counts["no-predecessor"], 5)
        self.assertEqual(visitor.pad_counts["no-return-call-site"], 1)
        self.assertIn("normal-text pads:", output.getvalue())

    def test_direct_transfers_skip_the_pad(self):
        _, module, text, blocks, functions = module_with_targets()
        for name in ("checkpoint_cnt", "indirect_branch_flags_scratch"):
            gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        f = next(symbol for symbol in module.symbols if symbol.name == "f")
        pointers = gtirb.Section(name=".data.rel.ro", module=module, flags={
            gtirb.Section.Flag.Readable, gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
        pointer = gtirb.ByteInterval(section=pointers, address=0x4000, contents=bytes(8))
        pointer.symbolic_expressions[0] = gtirb.SymAddrConst(0, f)
        arch = X64Architecture()
        visitor = TextIndirectBranchTransformPass(
            text, SimpleNamespace(code_blocks_map={b.uuid: b for b in blocks.values()}),
            GtirbInstructionDecoder(module.isa), arch,
            potential_targets={blocks["f"].uuid}, flags_dead_blocks={blocks["f"].uuid})
        context = RewritingContext(module, functions)
        with redirect_stdout(io.StringIO()) as output:
            visitor.begin_module(module, functions, context)
            # Later entry instrumentation in the same round, such as stack poisoning.
            context.insert_at(blocks["f"], 0, Patch.from_function(patch_constraints()(lambda _ctx: "int3")))
            context.apply()
            visitor.end_module(module, functions)

        def code_at(symbol):
            block = symbol.referent
            offset = block.offset + (block.size if symbol.at_end else 0)
            return bytes(block.byte_interval.contents[offset:offset + len(arch.nop_bytes)])

        interval = next(iter(text.byte_intervals))
        direct = [expression for expression in interval.symbolic_expressions.values()
                  if isinstance(expression, gtirb.SymAddrConst) and
                  expression.symbol.name.startswith(DIRECT_ENTRY_PREFIX)]
        # The direct call lands after f's pad, on the later entry instrumentation.
        self.assertEqual(len(direct), 1)
        self.assertFalse(direct[0].symbol.at_end)
        self.assertEqual(code_at(direct[0].symbol)[:1], b"\xcc")
        calls = [edge for edge in module.ir.cfg if edge.label is not None and
                 edge.label.type == gtirb.Edge.Type.Call and edge.label.direct]
        self.assertEqual([edge.target for edge in calls], [direct[0].symbol.referent])
        # The pointer still names the pad.
        self.assertEqual(pointer.symbolic_expressions[0].symbol, f)
        self.assertEqual(code_at(f), arch.nop_bytes)
        self.assertIn("direct transfers past pads: 1 into 1 blocks", output.getvalue())

    def test_riscv_direct_call_pair_operand(self):
        from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder

        from teapot.arch import RISCV64Architecture

        # auipc ra,0; jalr ra,0(ra) calls f; f: ret.
        module = gtirb.Module(name="rv", isa=gtirb.Module.ISA.ValidButUnsupported,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        ir = gtirb.IR(modules=[module])
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
        text = gtirb.Section(name=".text", module=module,
                             flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Loaded,
                                    gtirb.Section.Flag.Initialized, gtirb.Section.Flag.Readable})
        interval = gtirb.ByteInterval(section=text, address=0x1000,
                                      contents=bytes.fromhex("97000000" "e7800000" "67800000"))
        call = gtirb.CodeBlock(offset=0, size=8, byte_interval=interval)
        f = gtirb.CodeBlock(offset=8, size=4, byte_interval=interval)
        expression = gtirb.SymAddrConst(0, gtirb.Symbol(name="f", payload=f, module=module),
                                        {gtirb.SymbolicExpression.Attribute.PLT})
        interval.symbolic_expressions[0] = expression
        ir.cfg.add(gtirb.Edge(call, f, gtirb.Edge.Label(gtirb.Edge.Type.Call, direct=True)))
        visitor = TextIndirectBranchTransformPass(
            text, SimpleNamespace(code_blocks_map={}), CachedGtirbInstructionDecoder(module.isa),
            RISCV64Architecture())
        # The target's symbol sits on the AUIPC, not on the JALR that ends the block.
        self.assertEqual(visitor._direct_operands(f), [expression])
        self.assertEqual(visitor._direct_operands(call), [])

    def test_riscv_pad_precedes_a_leading_auipc(self):
        from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
        from gtirb_rewriting.abi import _ABIS

        from teapot.arch import RISCV64Architecture

        arch = RISCV64Architecture()
        arch.register_abi(_ABIS)
        # dispatch: jr a5 (a jump table the lift resolved);
        # case: auipc a0,%pcrel_hi(g); addi a0,a0,%pcrel_lo(case); ret.
        module = gtirb.Module(name="rv", isa=gtirb.Module.ISA.ValidButUnsupported,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        ir = gtirb.IR(modules=[module])
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
        text = gtirb.Section(name=".text", module=module,
                             flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Loaded,
                                    gtirb.Section.Flag.Initialized, gtirb.Section.Flag.Readable})
        interval = gtirb.ByteInterval(section=text, address=0x1000, contents=bytes.fromhex(
            "67800700" "17050000" "13050500" "67800000"))
        dispatch = gtirb.CodeBlock(offset=0, size=4, byte_interval=interval)
        case = gtirb.CodeBlock(offset=4, size=12, byte_interval=interval)
        data = gtirb.Section(name=".data", module=module, flags={
            gtirb.Section.Flag.Readable, gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
        g = gtirb.Symbol(name="g", module=module, payload=gtirb.DataBlock(
            offset=0, size=8, byte_interval=gtirb.ByteInterval(section=data, address=0x2000,
                                                              contents=bytes(8))))
        attrs = gtirb.SymbolicExpression.Attribute
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, g, {attrs.PCREL, attrs.HI})
        interval.symbolic_expressions[8] = gtirb.SymAddrConst(
            0, gtirb.Symbol(name=".Lcase", payload=case, module=module), {attrs.PCREL, attrs.LO})
        ir.cfg.add(gtirb.Edge(dispatch, case, gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)))
        functions = [Function(uuid4(), {dispatch}, {dispatch, case},
                              {gtirb.Symbol(name="f", payload=dispatch, module=module)})]
        visitor = TextIndirectBranchTransformPass(
            text, SimpleNamespace(code_blocks_map={b.uuid: b for b in (dispatch, case)}),
            CachedGtirbInstructionDecoder(module.isa), arch)
        marker = patch_constraints()(lambda _ctx: "nop")
        visitor._indirect_transform_target_patch = Mock(return_value=marker)
        context = RewritingContext(module, functions)
        with unittest.mock.patch.object(context, "insert_at", wraps=context.insert_at) as insert_at, \
                redirect_stdout(io.StringIO()):
            visitor.begin_module(module, functions, context)
            # An indirect arrival tests the marker at the case's address.
            self.assertIn(unittest.mock.call(case, 0, unittest.mock.ANY), insert_at.call_args_list)
            context.apply()
            visitor.end_module(module, functions)
        # The rewriter re-anchored %pcrel_lo on the AUIPC, now after the pad.
        positions = {expression.attributes and frozenset(expression.attributes): position
                     for position, expression in interval.symbolic_expressions.items()}
        high = positions[frozenset({attrs.PCREL, attrs.HI})]
        low = interval.symbolic_expressions[positions[frozenset({attrs.PCREL, attrs.LO})]]
        # Each block now starts with its pad (the dispatch has no predecessor):
        # nop; jr a5; nop; auipc; addi; ret.
        self.assertEqual(bytes(interval.contents[8:12]), bytes.fromhex("13000000"))
        self.assertEqual(high, 12)
        self.assertEqual(low.symbol.referent.offset + (low.symbol.referent.size if low.symbol.at_end else 0),
                         high)


if __name__ == "__main__":
    unittest.main()
