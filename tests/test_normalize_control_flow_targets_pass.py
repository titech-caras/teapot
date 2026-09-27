import unittest
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import gtirb
from gtirb_rewriting.decoder import GtirbInstructionDecoder
from gtirb_rewriting import Pass, PassManager, Patch, patch_constraints

from teapot.passes.preprocessing.normalize_control_flow_targets_pass import (
    NormalizeControlFlowTargetsPass,
)
from teapot.preprocess.copy_section import copy_section


class _Decoder:
    def __init__(self, instructions):
        self.instructions = instructions

    def get_instructions(self, block):
        return self.instructions.get(block, ())


class _InsertNopsPass(Pass):
    def __init__(self, block, count=64):
        self.block = block
        self.count = count

    def begin_module(self, module, functions, rewriting_ctx):
        @patch_constraints()
        def nops(_):
            return "\n".join("nop" for _ in range(self.count))

        rewriting_ctx.insert_at(
            self.block,
            0,
            Patch.from_function(nops),
        )


class NormalizeControlFlowTargetsPassTests(unittest.TestCase):
    @unittest.skipUnless(all(shutil.which(tool) for tool in (
        "gtirb-pprinter", "aarch64-linux-gnu-gcc", "ld.lld", "qemu-aarch64")),
        "requires AArch64 assembler, printer and QEMU")
    def test_copied_got_function_links_and_executes_without_exporting_it(self):
        # A local target four bytes into the copied section exposes the GNU
        # assembler's folding of local GOT references to section+offset.
        for binding in ("GLOBAL", "WEAK"):
            with self.subTest(binding=binding), tempfile.TemporaryDirectory() as directory:
                ir = gtirb.IR()
                module = gtirb.Module(name="copied-got", ir=ir,
                    isa=gtirb.Module.ISA.ARM64, file_format=gtirb.Module.FileFormat.ELF,
                    byte_order=gtirb.Module.ByteOrder.Little)
                section = gtirb.Section(name=".text", module=module,
                    flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable,
                           gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
                # NOP; target: MOV W0,7; RET; entry: ADRP X1; LDR X1,[X1];
                # BLR X1; SUB X0,X0,7; MOV X8,93; SVC 0.
                words = (0xd503201f, 0x528000e0, 0xd65f03c0, 0x90000001,
                         0xf9400021, 0xd63f0020, 0xd1001c00, 0xd2800ba8, 0xd4000001)
                interval = gtirb.ByteInterval(address=0x1000, section=section,
                    contents=b"".join(word.to_bytes(4, "little") for word in words))
                unused = gtirb.CodeBlock(size=4, byte_interval=interval)
                target = gtirb.CodeBlock(size=8, offset=4, byte_interval=interval)
                entry = gtirb.CodeBlock(size=24, offset=12, byte_interval=interval)
                symbol = gtirb.Symbol("target", payload=target, module=module)
                gtirb.Symbol("unused", payload=unused, module=module)
                gtirb.Symbol("entry", payload=entry, module=module)
                for offset, attributes in ((12, {gtirb.SymbolicExpression.Attribute.GOT}),
                        (16, {gtirb.SymbolicExpression.Attribute.GOT, gtirb.SymbolicExpression.Attribute.LO12})):
                    interval.symbolic_expressions[offset] = gtirb.SymAddrConst(0, symbol, attributes)
                for name, data, schema in (
                    ("binaryType", ["EXEC"], "sequence<string>"),
                    ("sectionProperties", {section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>"),
                    ("elfSymbolInfo", {symbol: (8, "FUNC", binding, "DEFAULT", 1)},
                     "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"),
                    ("functionEntries", {}, "mapping<UUID,set<UUID>>"),
                    ("functionBlocks", {}, "mapping<UUID,set<UUID>>"),
                    ("functionNames", {}, "mapping<UUID,UUID>"),
                ):
                    module.aux_data[name] = gtirb.AuxData(data, schema)
                copy_section(section, ".teapot_transient")
                # The standalone fixture explicitly exposes its process entry;
                # the target under test must acquire its own binding in copy_section.
                module.aux_data["elfSymbolInfo"].data[next(module.symbols_named("entry__teapot__"))] = (
                    0, "FUNC", "GLOBAL", "HIDDEN", 0)
                root = Path(directory)
                lifted, assembly, obj, binary = (root / name for name in (
                    "copied.gtirb", "copied.S", "copied.o", "copied"))
                ir.save_protobuf(lifted)
                subprocess.run(["gtirb-pprinter", "--ir", str(lifted), "--asm", str(assembly)],
                               check=True, capture_output=True)
                subprocess.run(["aarch64-linux-gnu-gcc", "-c", str(assembly), "-o", str(obj)],
                               check=True, capture_output=True)
                linked = subprocess.run(["ld.lld", "-m", "aarch64elf", "-static",
                                         "-e", "entry__teapot__", str(obj), "-o", str(binary)],
                                        text=True, capture_output=True)
                self.assertEqual(linked.returncode, 0, linked.stderr)
                subprocess.run(["qemu-aarch64", str(binary)], check=True, timeout=10,
                               capture_output=True)
                symbols = subprocess.check_output(["readelf", "-Ws", str(obj)], text=True)
                self.assertRegex(symbols, r"FUNC\s+GLOBAL\s+HIDDEN\s+\d+\s+target__teapot__")
                self.assertRegex(symbols, r"NOTYPE\s+LOCAL\s+DEFAULT\s+\d+\s+unused__teapot__")
                self.assertEqual(module.aux_data["elfSymbolInfo"].data[symbol][2:],
                                 (binding, "DEFAULT", 1))

    @staticmethod
    def _add_rewriting_aux_data(module, section, interval):
        module.aux_data["binaryType"] = gtirb.AuxData(
            ["EXEC"], "sequence<string>"
        )
        module.aux_data["sectionProperties"] = gtirb.AuxData(
            {section: (1, 0x6)},
            "mapping<UUID,tuple<uint64_t,uint64_t>>",
        )
        module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData(
            {gtirb.Offset(interval, 4): 4},
            "mapping<Offset,uint64_t>",
        )
        module.aux_data["alignment"] = gtirb.AuxData(
            {}, "mapping<UUID,uint64_t>"
        )
        module.aux_data["comments"] = gtirb.AuxData(
            {}, "mapping<Offset,string>"
        )
        module.aux_data["cfiDirectives"] = gtirb.AuxData(
            {},
            "mapping<Offset,sequence<tuple<string,sequence<int64_t>,UUID>>>",
        )
        module.aux_data["padding"] = gtirb.AuxData(
            {}, "mapping<Offset,uint64_t>"
        )

    def _case(self, *, direct=True, attributes=None, expression_offset=0x10):
        module = gtirb.Module(
            name="control-flow-target-test",
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
        )
        section = gtirb.Section(
            name=".text",
            flags={
                gtirb.Section.Flag.Readable,
                gtirb.Section.Flag.Executable,
                gtirb.Section.Flag.Loaded,
                gtirb.Section.Flag.Initialized,
            },
            module=module,
        )
        interval = gtirb.ByteInterval(
            address=0x1000,
            contents=b"\x90" * 0x20,
            section=section,
        )
        source = gtirb.CodeBlock(size=6, offset=0, byte_interval=interval)
        fallthrough = gtirb.CodeBlock(size=4, offset=6, byte_interval=interval)
        target = gtirb.CodeBlock(size=4, offset=0x10, byte_interval=interval)

        function_symbol = gtirb.Symbol(
            name="function",
            payload=source,
            module=module,
        )
        if attributes is None:
            attributes = {gtirb.SymbolicExpression.Attribute.PCREL}
        interval.symbolic_expressions[2] = gtirb.SymAddrConst(
            offset=expression_offset,
            symbol=function_symbol,
            attributes=attributes,
        )

        branch = gtirb.Edge(
            source,
            target,
            gtirb.Edge.Label(
                type=gtirb.Edge.Type.Branch,
                conditional=True,
                direct=direct,
            ),
        )
        fallthrough_edge = gtirb.Edge(
            source,
            fallthrough,
            gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
        ir = gtirb.IR(modules=[module], cfg={branch, fallthrough_edge})

        for name, type_name in (
            ("functionEntries", "mapping<UUID,set<UUID>>"),
            ("functionBlocks", "mapping<UUID,set<UUID>>"),
            ("functionNames", "mapping<UUID,UUID>"),
        ):
            module.aux_data[name] = gtirb.AuxData({}, type_name)

        instruction = SimpleNamespace(address=source.address, size=source.size)
        decoder = _Decoder({source: (instruction,)})
        return ir, module, section, interval, source, target, decoder

    def _layout_case(self):
        module = gtirb.Module(
            name="control-flow-layout-test",
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            byte_order=gtirb.Module.ByteOrder.Little,
        )
        section = gtirb.Section(
            name=".text",
            flags={
                gtirb.Section.Flag.Readable,
                gtirb.Section.Flag.Executable,
                gtirb.Section.Flag.Loaded,
                gtirb.Section.Flag.Initialized,
            },
            module=module,
        )
        interval = gtirb.ByteInterval(
            address=0x1000,
            contents=(
                b"\x85\xff\x0f\x84\x08\x00\x00\x00"
                b"\xb8\x01\x00\x00\x00\xc3\x90\x90"
                b"\x31\xc0\xc3\x90\x90\x90\x90\x90"
            ),
            section=section,
        )
        source = gtirb.CodeBlock(size=8, offset=0, byte_interval=interval)
        fallthrough = gtirb.CodeBlock(size=8, offset=8, byte_interval=interval)
        target = gtirb.CodeBlock(size=8, offset=0x10, byte_interval=interval)
        function_symbol = gtirb.Symbol(
            name="function",
            payload=source,
            module=module,
        )
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(
            offset=0x10,
            symbol=function_symbol,
            attributes={gtirb.SymbolicExpression.Attribute.PCREL},
        )
        ir = gtirb.IR(
            modules=[module],
            cfg={
                gtirb.Edge(
                    source,
                    target,
                    gtirb.Edge.Label(
                        type=gtirb.Edge.Type.Branch,
                        conditional=True,
                        direct=True,
                    ),
                ),
                gtirb.Edge(
                    source,
                    fallthrough,
                    gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
                ),
                gtirb.Edge(
                    fallthrough,
                    target,
                    gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
                ),
                gtirb.Edge(
                    fallthrough,
                    gtirb.ProxyBlock(module=module),
                    gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
                ),
                gtirb.Edge(
                    target,
                    gtirb.ProxyBlock(module=module),
                    gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
                ),
            },
        )
        for name, type_name in (
            ("functionEntries", "mapping<UUID,set<UUID>>"),
            ("functionBlocks", "mapping<UUID,set<UUID>>"),
            ("functionNames", "mapping<UUID,UUID>"),
        ):
            module.aux_data[name] = gtirb.AuxData({}, type_name)
        self._add_rewriting_aux_data(module, section, interval)
        return ir, module, interval, source, fallthrough, target

    def test_reanchors_function_plus_offset_to_cfg_target(self):
        _, module, _, interval, _, target, decoder = self._case()
        normalize = NormalizeControlFlowTargetsPass(decoder)

        normalize.begin_module(module, (), None)

        expression = interval.symbolic_expressions[2]
        self.assertEqual(normalize.normalized, 1)
        self.assertEqual(expression.offset, 0)
        self.assertIs(expression.symbol.referent, target)
        self.assertFalse(expression.symbol.at_end)
        self.assertEqual(
            expression.attributes,
            {gtirb.SymbolicExpression.Attribute.PCREL},
        )

    def test_normalized_target_is_copied_to_transient_block(self):
        _, module, section, interval, _, target, decoder = self._case()
        normalize = NormalizeControlFlowTargetsPass(decoder)
        normalize.begin_module(module, (), None)

        transient, _, _, mapping = copy_section(section, ".teapot_transient")
        transient_interval = next(iter(transient.byte_intervals))
        expression = transient_interval.symbolic_expressions[2]

        self.assertEqual(expression.offset, 0)
        self.assertIs(
            expression.symbol.referent,
            mapping.code_blocks_map[target.uuid],
        )

    def test_exact_target_is_idempotent(self):
        _, module, _, interval, _, target, decoder = self._case()
        expression = interval.symbolic_expressions[2]
        expression.symbol = gtirb.Symbol(
            name="exact_target",
            payload=target,
            module=module,
        )
        expression.offset = 0
        symbol_count = len(module.symbols)
        normalize = NormalizeControlFlowTargetsPass(decoder)

        normalize.begin_module(module, (), None)

        self.assertEqual(normalize.normalized, 0)
        self.assertEqual(len(module.symbols), symbol_count)
        self.assertIs(interval.symbolic_expressions[2], expression)

    def test_reuses_existing_exact_target_symbol(self):
        _, module, _, interval, _, target, decoder = self._case()
        exact_target = gtirb.Symbol(
            name="existing_target",
            payload=target,
            module=module,
        )
        symbol_count = len(module.symbols)
        normalize = NormalizeControlFlowTargetsPass(decoder)

        normalize.begin_module(module, (), None)

        expression = interval.symbolic_expressions[2]
        self.assertEqual(normalize.normalized, 1)
        self.assertIs(expression.symbol, exact_target)
        self.assertEqual(len(module.symbols), symbol_count)

    def test_nonterminal_expression_is_unchanged(self):
        _, module, _, interval, source, _, _ = self._case()
        expression = interval.symbolic_expressions.pop(2)
        interval.symbolic_expressions[0] = expression
        decoder = _Decoder(
            {
                source: (
                    SimpleNamespace(address=source.address, size=4),
                    SimpleNamespace(address=source.address + 4, size=2),
                )
            }
        )
        normalize = NormalizeControlFlowTargetsPass(decoder)

        normalize.begin_module(module, (), None)

        self.assertEqual(normalize.normalized, 0)
        self.assertIs(interval.symbolic_expressions[0], expression)

    def test_indirect_edge_is_unchanged(self):
        _, module, _, interval, _, _, decoder = self._case(direct=False)
        expression = interval.symbolic_expressions[2]
        normalize = NormalizeControlFlowTargetsPass(decoder)

        normalize.begin_module(module, (), None)

        self.assertEqual(normalize.normalized, 0)
        self.assertIs(interval.symbolic_expressions[2], expression)

    def test_mismatched_cfg_target_is_unchanged(self):
        _, module, _, interval, _, _, decoder = self._case(
            expression_offset=0x0c,
        )
        expression = interval.symbolic_expressions[2]
        normalize = NormalizeControlFlowTargetsPass(decoder)

        normalize.begin_module(module, (), None)

        self.assertEqual(normalize.normalized, 0)
        self.assertIs(interval.symbolic_expressions[2], expression)

    def test_proxy_referent_is_unchanged(self):
        _, module, _, interval, _, _, decoder = self._case()
        expression = interval.symbolic_expressions[2]
        expression.symbol = gtirb.Symbol(
            name="external_target",
            payload=gtirb.ProxyBlock(module=module),
            module=module,
        )
        normalize = NormalizeControlFlowTargetsPass(decoder)

        normalize.begin_module(module, (), None)

        self.assertEqual(normalize.normalized, 0)
        self.assertIs(interval.symbolic_expressions[2], expression)

    def test_special_relocation_is_unchanged(self):
        _, module, _, interval, _, _, decoder = self._case(
            attributes={
                gtirb.SymbolicExpression.Attribute.PCREL,
                gtirb.SymbolicExpression.Attribute.PLT,
            },
        )
        expression = interval.symbolic_expressions[2]
        normalize = NormalizeControlFlowTargetsPass(decoder)

        normalize.begin_module(module, (), None)

        self.assertEqual(normalize.normalized, 0)
        self.assertIs(interval.symbolic_expressions[2], expression)

    def test_nop_insertion_keeps_normalized_branch_on_cfg_target(self):
        ir, module, interval, source, fallthrough, target = self._layout_case()
        original_target_address = target.address
        normalize = NormalizeControlFlowTargetsPass(
            GtirbInstructionDecoder(module.isa)
        )
        pass_manager = PassManager()
        pass_manager.add(normalize)
        pass_manager.add(_InsertNopsPass(fallthrough))

        pass_manager.run(ir)

        expression = interval.symbolic_expressions[4]
        self.assertEqual(normalize.normalized, 1)
        self.assertGreater(target.address, original_target_address)
        self.assertEqual(expression.offset, 0)
        self.assertIs(expression.symbol.referent, target)
        self.assertEqual(expression.symbol.referent.address, target.address)
        self.assertNotEqual(source.address + 0x10, target.address)


if __name__ == "__main__":
    unittest.main()
