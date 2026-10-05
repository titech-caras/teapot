"""Names in patch text denote the symbol they were written for.

gtirb-rewriting's assembler resolves each name in a patch with
next(module.symbols_named(name)): one of the symbols that share the name, from
a set ordered by object identity. Each test here gives one name to two places
and makes the instruction refer to the symbol that this lookup does not return
first, so text that prints the plain name binds the other place in every run.
"""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import uuid

import gtirb
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import Assembler, PassManager
from gtirb_rewriting.assembly import X86Syntax

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.arch.decoders import aarch64_decoder
from teapot.liveness import LiveRegisterManager
from teapot.passes.common.x64_relax_jcxz_pass import X64RelaxJcxzPass
from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass
from test_live_register_preservation import make_module

ATTRIBUTES = gtirb.SymbolicExpression.Attribute
INFO_TYPE = "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"
VERSIONS_TYPE = ("tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,mapping<string,mapping<uint16_t,string>>,"
                 "mapping<UUID,tuple<uint16_t,bool>>>")
WRITABLE = {gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Readable,
            gtirb.Section.Flag.Writable, gtirb.Section.Flag.Initialized}


def set_payload(symbol, payload):
    if isinstance(payload, int):
        symbol.value = payload
    else:
        symbol.referent = payload


def two_places(module, name, wanted_payload, other_payload):
    """Two symbols called name: the one at wanted_payload is not the one lookup returns first."""
    wanted = gtirb.Symbol(name, payload=wanted_payload, module=module)
    other = gtirb.Symbol(name, payload=other_payload, module=module)
    if next(module.symbols_named(name)) is wanted:
        set_payload(wanted, other_payload)
        set_payload(other, wanted_payload)
        wanted, other = other, wanted
    assert next(module.symbols_named(name)) is other
    return wanted, other


def data_blocks(module, address=0x2000, count=2, size=8):
    section = gtirb.Section(name=".data", module=module, flags=set(WRITABLE))
    interval = gtirb.ByteInterval(address=address, contents=bytes(count * size), section=section)
    return [gtirb.DataBlock(offset=index * size, size=size, byte_interval=interval) for index in range(count)]


def assembled_references(module, text, syntax=None):
    """The symbols that the expressions of text, assembled for module, refer to."""
    assembler = Assembler(module)
    if syntax is None:
        assembler.assemble(text)
    else:
        assembler.assemble(text, syntax)
    result = assembler.finalize()
    symbols = []
    for expression in result.text_section.symbolic_expressions.values():
        symbols += list(expression.symbols)
    return symbols


def same_place(first, second):
    return (first.referent is second.referent and first.at_end == second.at_end and
            first.value == second.value)


def where(symbol):
    """A symbol's name and address, for failure messages."""
    referent = symbol.referent
    if referent is None:
        address = symbol.value
    elif getattr(referent, "address", None) is not None:
        address = referent.address + (referent.size if symbol.at_end else 0)
    else:
        address = None
    return f"{symbol.name} at {address:#x}" if address is not None else symbol.name


class SymbolReferenceTests(unittest.TestCase):
    def x64_store(self):
        """mov dword ptr [rip + counter], edi; ret, counter being one of two statics of that name."""
        arch = X64Architecture()
        ir, module, block, abi, registers = make_module(arch, gtirb.Module.ISA.X64,
                                                        bytes.fromhex("893d00000000c3"))
        wanted_block, other_block = data_blocks(module)
        wanted, other = two_places(module, "counter", wanted_block, other_block)
        block.byte_interval.symbolic_expressions[2] = gtirb.SymAddrConst(0, wanted)
        decoder = CachedGtirbInstructionDecoder(module.isa)
        inst = next(decoder.get_instructions(block))
        return arch, ir, module, block, abi, registers, inst, wanted, other

    def test_the_assembler_takes_whichever_symbol_comes_first(self):
        # The defect's mechanism: the plain name binds the other static.
        _, _, module, _, _, _, _, wanted, other = self.x64_store()
        symbols = assembled_references(module, "lea rax, [rip + counter]", X86Syntax.INTEL)
        self.assertEqual(symbols, [other])

    def test_x64_memory_operands_name_their_own_symbol(self):
        # Every x64 capture, memory log, policy and DIFT address uses this text.
        arch, _, module, block, _, _, inst, wanted, other = self.x64_store()
        operand = arch.memory_operand(inst)
        text = arch.mem_operand_to_str(block, inst, operand)
        symbols = assembled_references(module, f"lea rax, {text}", X86Syntax.INTEL)
        self.assertEqual(len(symbols), 1)
        self.assertTrue(same_place(symbols[0], wanted),
                        f"'lea rax, {text}' captures {where(symbols[0])}; the store writes {where(wanted)}")
        from teapot.utils.symbol_references import ALIAS_PREFIX
        self.assertIn(ALIAS_PREFIX, text)
        # The same alias every time, at the same place.
        self.assertEqual(arch.mem_operand_to_str(block, inst, operand), text)
        self.assertEqual(sum(1 for s in module.symbols if s.name.startswith(ALIAS_PREFIX)), 1)

    def test_unshared_names_are_printed_unchanged(self):
        from teapot.utils.symbol_references import reference_symbol
        arch = X64Architecture()
        _, module, block, _, _ = make_module(arch, gtirb.Module.ISA.X64, bytes.fromhex("893d00000000c3"))
        only = gtirb.Symbol("counter", payload=data_blocks(module, count=1)[0], module=module)
        block.byte_interval.symbolic_expressions[2] = gtirb.SymAddrConst(4, only)
        inst = next(CachedGtirbInstructionDecoder(module.isa).get_instructions(block))
        symbols_before = len(list(module.symbols))
        self.assertEqual(arch.mem_operand_to_str(block, inst, arch.memory_operand(inst)), "[rip + counter + 4]")
        self.assertEqual(len(list(module.symbols)), symbols_before)
        # Several symbols for one place are one place: no alias either.
        gtirb.Symbol("counter", payload=only.referent, module=module)
        self.assertIs(reference_symbol(only), only)
        externals = [gtirb.Symbol("memcpy", payload=gtirb.ProxyBlock(module=module), module=module)
                     for _ in range(2)]
        self.assertIs(reference_symbol(externals[0]), externals[0])

    def test_an_external_shadowed_by_a_definition_is_refused(self):
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_name, reference_symbol
        _, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        external = gtirb.Symbol("stdout", payload=gtirb.ProxyBlock(module=module), module=module)
        defined = gtirb.Symbol("stdout", payload=data_blocks(module, count=1)[0], module=module)
        with self.assertRaisesRegex(AmbiguousReferenceError,
                                    r"cannot refer to 'stdout', an undefined symbol, by name: the name also "
                                    r"denotes a symbol in \.data at 0x2000\. .* but this one is external"):
            reference_name(external)
        self.assertTrue(same_place(reference_symbol(defined), defined))

    # Address equality is not resolution equality: what a reference reaches can depend on the symbol's linker
    # identity. Only a LOCAL symbol referred to by its address may be aliased; the rest is refused.

    def test_differently_versioned_externals_are_refused(self):
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_symbol
        _, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        first, second = (gtirb.Symbol("api", payload=gtirb.ProxyBlock(module=module), module=module)
                         for _ in range(2))
        module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
            ({}, {"libapi.so": {2: "LIBAPI_1", 3: "LIBAPI_2"}}, {first: (2, False), second: (3, False)}),
            VERSIONS_TYPE)
        for symbol, version in ((first, "LIBAPI_1"), (second, "LIBAPI_2")):
            with self.subTest(version=version):
                with self.assertRaisesRegex(AmbiguousReferenceError,
                                            f"cannot refer to 'api', an undefined symbol of version {version}"):
                    reference_symbol(symbol)
        # Imports of one version resolve alike: no alias, no refusal.
        module.aux_data["elfSymbolVersions"].data[2][second] = (2, False)
        self.assertIs(reference_symbol(first), first)
        self.assertIs(reference_symbol(second), second)

    def test_a_forwarded_symbol_is_refused(self):
        # The printer prints a forwarded symbol as its target (symbolForwarding), so an alias of its place
        # would reach another symbol.
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_symbol
        _, module, block, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3\xc3")
        stub = gtirb.CodeBlock(offset=1, size=1, byte_interval=block.byte_interval)
        target = gtirb.Symbol("puts", payload=gtirb.ProxyBlock(module=module), module=module)
        forwarded = gtirb.Symbol("helper", payload=stub, module=module)
        module.aux_data["symbolForwarding"] = gtirb.AuxData({forwarded: target}, "mapping<UUID,UUID>")
        self.assertIs(reference_symbol(forwarded), forwarded)  # its name is its own
        other = gtirb.Symbol("helper", payload=data_blocks(module, count=1)[0], module=module)
        with self.assertRaisesRegex(AmbiguousReferenceError, "forwards to puts"):
            reference_symbol(forwarded)
        self.assertTrue(same_place(reference_symbol(other), other))

    def test_symbols_bound_otherwise_than_locally_are_refused(self):
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_symbol
        cases = (((8, "OBJECT", "GLOBAL", "DEFAULT", 0), None, "is GLOBAL"),
                 ((8, "OBJECT", "WEAK", "DEFAULT", 0), None, "is WEAK"),
                 ((8, "GNU_IFUNC", "LOCAL", "DEFAULT", 0), None, "is a GNU_IFUNC symbol"),
                 ((8, "TLS", "LOCAL", "DEFAULT", 0), gtirb.Section.Flag.ThreadLocal, "is a TLS symbol"),
                 (None, gtirb.Section.Flag.ThreadLocal, "is thread-local"),
                 ((8, "OBJECT", "LOCAL", "DEFAULT", 0), None, None))
        for entry, flag, reason in cases:
            with self.subTest(entry=entry, flag=flag):
                _, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
                wanted_block, other_block = data_blocks(module)
                if flag is not None:
                    wanted_block.section.flags.add(flag)
                wanted, _ = two_places(module, "counter", wanted_block, other_block)
                module.aux_data["elfSymbolInfo"] = gtirb.AuxData({wanted: entry} if entry else {}, INFO_TYPE)
                if reason is None:
                    self.assertTrue(same_place(reference_symbol(wanted), wanted))
                else:
                    with self.assertRaisesRegex(AmbiguousReferenceError, reason):
                        reference_symbol(wanted)

    def test_got_plt_and_tls_references_are_refused(self):
        # A GOT entry, PLT entry or TLS offset belongs to the symbol's linker identity: a local alias has its own.
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_expression
        arch, module, block, abi, decoder, wanted = self.riscv64_load()
        inst = list(decoder.get_instructions(block))[1]
        operand = arch.memory_operand(inst)
        for attributes in ({ATTRIBUTES.GOT}, {ATTRIBUTES.TLSGD}):
            with self.subTest(attributes=attributes):
                expression = gtirb.SymAddrConst(0, wanted, attributes)
                with self.assertRaisesRegex(AmbiguousReferenceError,
                                            f"referred to by a {next(iter(attributes)).name} relocation"):
                    arch.mem_operand_address_snippet(abi, inst, "t0", "t1", operand, mem_symexpr=expression)
        for attributes in ({ATTRIBUTES.GOT, ATTRIBUTES.PCREL}, {ATTRIBUTES.PLT}, {ATTRIBUTES.TPOFF}):
            with self.subTest(attributes=attributes):
                with self.assertRaises(AmbiguousReferenceError):
                    reference_expression(gtirb.SymAddrConst(0, wanted, attributes))
        # The plain pc-relative reference is still aliased.
        self.assertTrue(same_place(reference_expression(
            gtirb.SymAddrConst(0, wanted, {ATTRIBUTES.PCREL, ATTRIBUTES.HI})).symbol, wanted))

    def test_same_place_symbols_bound_otherwise_are_refused(self):
        # Two symbols called api at one place that the linker binds differently: the assembler would bind
        # whichever comes first, so a reference through either name is refused, also through the GOT.
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_symbol
        exported = (0, "FUNC", "GLOBAL", "DEFAULT", 1)
        cases = {"visibility": ((0, "FUNC", "GLOBAL", "HIDDEN", 1), None, "a GLOBAL HIDDEN FUNC symbol"),
                 "type": ((0, "GNU_IFUNC", "GLOBAL", "DEFAULT", 1), None, "a GLOBAL GNU_IFUNC symbol"),
                 "version": (exported, ((2, False), (2, True)), "of version API_1 (hidden)")}
        for differ, (other_entry, versions, description) in cases.items():
            for attributes in (set(), {ATTRIBUTES.GOT}):
                with self.subTest(differ=differ, attributes=attributes):
                    _, module, block, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
                    first, second = (gtirb.Symbol("api", payload=block, module=module) for _ in range(2))
                    module.aux_data["elfSymbolInfo"] = gtirb.AuxData({first: exported, second: other_entry},
                                                                     INFO_TYPE)
                    if versions is not None:
                        module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
                            ({2: (["API_1"], 0)}, {}, {first: versions[0], second: versions[1]}), VERSIONS_TYPE)
                    for symbol in (first, second):
                        with self.assertRaisesRegex(AmbiguousReferenceError,
                                                    "cannot refer to 'api'.* but this one is GLOBAL") as refusal:
                            reference_symbol(symbol, attributes)
                        self.assertIn(description, str(refusal.exception))

    def test_same_place_symbols_bound_alike_keep_their_name(self):
        # One linker symbol under two GTIRB symbols: either name reaches it, also through the GOT.
        from teapot.utils.symbol_references import reference_symbol
        _, module, block, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        first, second = (gtirb.Symbol("api", payload=block, module=module) for _ in range(2))
        entry = (0, "FUNC", "GLOBAL", "DEFAULT", 1)
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData({first: entry, second: entry}, INFO_TYPE)
        module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
            ({2: (["API_1"], 0)}, {}, {first: (2, False), second: (2, False)}), VERSIONS_TYPE)
        symbols_before = len(list(module.symbols))
        for symbol in (first, second):
            self.assertIs(reference_symbol(symbol, {ATTRIBUTES.GOT}), symbol)
        self.assertEqual(len(list(module.symbols)), symbols_before)

    def test_same_place_local_symbols_entered_otherwise_get_an_alias(self):
        # LOCAL symbols referred to by their address: whichever entry, an alias at the place reaches it.
        from teapot.utils.symbol_references import reference_symbol
        _, module, block, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        first, second = (gtirb.Symbol("helper", payload=block, module=module) for _ in range(2))
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            {first: (0, "FUNC", "LOCAL", "DEFAULT", 1), second: (0, "NOTYPE", "LOCAL", "DEFAULT", 1)}, INFO_TYPE)
        for symbol in (first, second):
            alias = reference_symbol(symbol)
            self.assertIsNot(alias, symbol)
            self.assertTrue(same_place(alias, symbol))

    def test_an_import_and_a_common_definition_of_one_name_are_refused(self):
        # DDisasm gives COMMON definitions proxy blocks too; neither has a place for an alias.
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_symbol
        _, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        imported, common = (gtirb.Symbol("buffer", payload=gtirb.ProxyBlock(module=module), module=module)
                            for _ in range(2))
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            {imported: (0, "OBJECT", "GLOBAL", "DEFAULT", 0), common: (64, "OBJECT", "GLOBAL", "DEFAULT", 0xfff2)},
            INFO_TYPE)
        with self.assertRaisesRegex(AmbiguousReferenceError,
                                    "an undefined GLOBAL OBJECT symbol, by name: the name also denotes a COMMON "
                                    "definition, .* but this one is external"):
            reference_symbol(imported)
        with self.assertRaisesRegex(AmbiguousReferenceError,
                                    "a COMMON definition, a GLOBAL OBJECT symbol, by name: .* but this one is a "
                                    "COMMON definition"):
            reference_symbol(common)

    # An alias is reused only if it is the one made for this symbol.

    def test_an_alias_name_taken_by_another_place_is_refused(self):
        from teapot.utils.misc import generate_distinct_label_name
        from teapot.utils.symbol_references import ALIAS_PREFIX, AmbiguousReferenceError, reference_symbol
        _, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        wanted_block, other_block = data_blocks(module)
        wanted, other = two_places(module, "counter", wanted_block, other_block)
        squatter = gtirb.Symbol(generate_distinct_label_name(ALIAS_PREFIX, wanted.uuid), payload=other_block,
                                module=module)
        with self.assertRaisesRegex(AmbiguousReferenceError, "already have the name"):
            reference_symbol(wanted)
        # Also at the right place: it is not the alias Teapot made.
        squatter.referent = wanted_block
        with self.assertRaisesRegex(AmbiguousReferenceError, "already have the name"):
            reference_symbol(wanted)

    def test_a_duplicated_alias_name_is_refused(self):
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_symbol
        _, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        wanted_block, other_block = data_blocks(module)
        wanted, _ = two_places(module, "counter", wanted_block, other_block)
        alias = reference_symbol(wanted)
        self.assertIs(reference_symbol(wanted), alias)
        gtirb.Symbol(alias.name, payload=wanted_block, module=module)
        with self.assertRaisesRegex(AmbiguousReferenceError, "2 symbol"):
            reference_symbol(wanted)

    def test_an_occupied_alias_uuid_is_refused(self):
        # The alias's UUID is derived from the symbol's, for reproducible output; it is never replaced by a
        # random one.
        from teapot.utils.symbol_references import AmbiguousReferenceError, reference_symbol
        ir, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        wanted_block, other_block = data_blocks(module)
        wanted, _ = two_places(module, "counter", wanted_block, other_block)
        gtirb.Symbol("squatter", uuid=uuid.uuid5(wanted.uuid, "teapot-copy:reference:alias"), payload=0,
                     module=module)
        with self.assertRaisesRegex(AmbiguousReferenceError, "already has its alias UUID"):
            reference_symbol(wanted)

    def test_an_alias_of_a_block_end_is_at_the_block_end(self):
        from teapot.utils.symbol_references import reference_expression
        _, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
        wanted_block, other_block = data_blocks(module)
        wanted, _ = two_places(module, "table_end", wanted_block, other_block)
        wanted.at_end = True
        alias = reference_expression(gtirb.SymAddrConst(0, wanted)).symbol
        self.assertIsNot(alias, wanted)
        self.assertTrue(alias.at_end)
        symbols = assembled_references(module, f"lea rax, [rip + {alias.name}]", X86Syntax.INTEL)
        self.assertEqual(len(symbols), 1)
        self.assertTrue(same_place(symbols[0], wanted), f"{where(symbols[0])} is not {where(wanted)}")
        self.assertEqual(symbols[0].referent.address + symbols[0].referent.size, 0x2008)

    def test_aliases_are_named_and_numbered_from_the_input(self):
        # Two rewrites of the same input print and serialize the same alias.
        from teapot.utils.symbol_references import reference_symbol
        aliases = []
        for _ in range(2):
            _, module, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b"\xc3")
            first, second = data_blocks(module)
            symbol = gtirb.Symbol("counter", uuid=uuid.UUID(int=7), payload=first, module=module)
            gtirb.Symbol("counter", uuid=uuid.UUID(int=8), payload=second, module=module)
            alias = reference_symbol(symbol)
            aliases.append((alias.name, alias.uuid))
            self.assertTrue(same_place(alias, symbol))
            self.assertIs(reference_symbol(symbol), alias)
        self.assertEqual(aliases[0], aliases[1])

    def test_aarch64_operands_name_their_own_symbols(self):
        arch = AArch64Architecture()
        inst = next(aarch64_decoder().disasm(bytes.fromhex("20004139"), 0x1000))
        for form in ("lo12", "difference", "subtrahend"):
            with self.subTest(form=form):
                module = gtirb.Module(name="address", isa=gtirb.Module.ISA.ARM64,
                                      file_format=gtirb.Module.FileFormat.ELF)
                wanted, other = two_places(module, "counter", 0x4040, 0x4080)
                if form == "lo12":
                    expression = gtirb.SymAddrConst(0, wanted, {ATTRIBUTES.LO12})
                elif form == "difference":
                    base = gtirb.Symbol("base", payload=0x4000, module=module)
                    expression = gtirb.SymAddrAddr(1, 0, wanted, base)
                else:
                    # The shared name as the second symbol: a jump-table entry minus its table.
                    base = gtirb.Symbol("base", payload=0x4100, module=module)
                    expression = gtirb.SymAddrAddr(1, 0, base, wanted)
                text = arch.mem_operand_address_snippet(arch.abi, inst, "x2", "x3", inst.operands[1],
                                                        mem_symexpr=expression)
                symbols = [s for s in assembled_references(module, text) if s.name != "base"]
                self.assertEqual(len(symbols), 1)
                self.assertEqual(symbols[0].value, 0x4040,
                                 f"{' '.join(text.split())} refers to {where(symbols[0])}, not {where(wanted)}")

    def riscv64_load(self):
        """auipc a4 / lw a4 of target_value, one of two variables of that name."""
        arch = RISCV64Architecture()
        ir, module, block, abi, registers = make_module(
            arch, gtirb.Module.ISA.ValidButUnsupported, bytes.fromhex("177728000327c7aa67800000"))
        wanted_block, other_block = data_blocks(module, address=0x3000)
        wanted, other = two_places(module, "target_value", wanted_block, other_block)
        anchor = gtirb.Symbol(".L_original_high", payload=gtirb.CodeBlock(size=0, byte_interval=block.byte_interval),
                              module=module)
        block.byte_interval.symbolic_expressions.update({
            0: gtirb.SymAddrConst(0, wanted, {ATTRIBUTES.HI, ATTRIBUTES.PCREL}),
            4: gtirb.SymAddrConst(0, anchor, {ATTRIBUTES.LO, ATTRIBUTES.PCREL})})
        decoder = CachedGtirbInstructionDecoder(module.isa)
        return arch, module, block, abi, decoder, wanted

    def test_riscv64_operands_name_their_own_symbol(self):
        arch, module, block, abi, decoder, wanted = self.riscv64_load()
        inst = list(decoder.get_instructions(block))[1]
        operand = arch.memory_operand(inst)
        pcrel = arch.mem_operand_address_expression(block, inst, operand, 4)
        absolute = gtirb.SymAddrConst(0, wanted, {ATTRIBUTES.LO})
        for form, expression in (("pcrel", pcrel), ("absolute", absolute)):
            with self.subTest(form=form):
                text = arch.mem_operand_address_snippet(abi, inst, "t0", "t1", operand, mem_symexpr=expression)
                symbols = [s for s in assembled_references(module, text) if not s.name.startswith(".L__riscv64")]
                self.assertTrue(symbols)
                for symbol in symbols:
                    self.assertTrue(same_place(symbol, wanted),
                                    f"{' '.join(text.split())} refers to {where(symbol)}, not {where(wanted)}")

    def test_riscv64_gp_normalization_keeps_the_application_access(self):
        # This pass rewrites the program's own gp-relative accesses, so a wrong
        # binding changes what the program reads or writes outside speculation.
        from test_riscv64_gp_normalization import RISCV64GPNormalizationTests
        helper = RISCV64GPNormalizationTests()
        for instruction in ("ld a0,-128(gp)", "sd t0,-128(gp)", "addi a1,gp,-128"):
            with self.subTest(instruction=instruction):
                ir, module, block, normalization = helper.make_reference(instruction)
                original = next(module.symbols_named("target"))
                expression = block.byte_interval.symbolic_expressions[0]
                # A second static called target, which name lookup returns first.
                other_block = gtirb.DataBlock(size=8, byte_interval=gtirb.ByteInterval(
                    address=0x2900, contents=bytes(8), section=original.referent.section))
                other = gtirb.Symbol("target", payload=other_block, module=module)
                if next(module.symbols_named("target")) is original:
                    original.referent, other.referent = other_block, original.referent
                    expression.symbol1 = other
                    original, other = other, original
                wanted = expression.symbol1
                self.assertIsNot(next(module.symbols_named("target")), wanted)
                helper.run_pass(ir, normalization)
                references = [expr for interval in module.byte_intervals
                              for expr in interval.symbolic_expressions.values()
                              if isinstance(expr, gtirb.SymAddrConst) and ATTRIBUTES.HI in expr.attributes]
                self.assertEqual(len(references), 1)
                self.assertTrue(same_place(references[0].symbol, wanted),
                                f"{instruction}: the program's access now addresses {where(references[0].symbol)}, "
                                f"not {where(wanted)}")

    def test_x64_jcxz_relaxation_jumps_to_its_own_target(self):
        arch = X64Architecture()
        ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.X64, bytes.fromhex("e301c3c3c3"))
        # jrcxz to 0x1003; fallthrough ret at 0x1002; two static functions called helper.
        block.size = 2
        interval = block.byte_interval
        fallthrough, target, elsewhere = (gtirb.CodeBlock(offset=offset, size=1, byte_interval=interval)
                                          for offset in (2, 3, 4))
        function = next(iter(module.aux_data["functionBlocks"].data))
        module.aux_data["functionBlocks"].data[function] = {block, fallthrough, target, elsewhere}
        ir.cfg.add(gtirb.Edge(block, target, gtirb.Edge.Label(gtirb.Edge.Type.Branch, conditional=True,
                                                               direct=True)))
        ir.cfg.add(gtirb.Edge(block, fallthrough, gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
        wanted, _ = two_places(module, "helper", target, elsewhere)
        passes = PassManager()
        passes.add(X64RelaxJcxzPass(CachedGtirbInstructionDecoder(module.isa), arch))
        passes.run(ir)
        references = [expr.symbol for expr in interval.symbolic_expressions.values()
                      if isinstance(expr, gtirb.SymAddrConst) and
                      expr.symbol.referent in (target, elsewhere)]
        self.assertEqual(len(references), 1)
        self.assertTrue(same_place(references[0], wanted),
                        f"the relaxed jrcxz continues at {where(references[0])}, not at {where(wanted)}")

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc")
                         and shutil.which(os.environ.get("PPRINTER_PATH", "gtirb-pprinter")),
                         "requires native x64, compiler and printer")
    def test_x64_memory_log_restores_the_static_it_was_written_for(self):
        # A speculative store to one of two statics called counter: the memory
        # log must record that static, so the rollback restores it.
        arch, ir, module, block, abi, registers, _, wanted, other = self.x64_store()
        entry = next(module.symbols_named("test_function"))
        module.aux_data["sectionProperties"] = gtirb.AuxData(
            {block.section: (1, 6), wanted.referent.section: (1, 3)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
        symbol_info = {entry: (block.size, "FUNC", "GLOBAL", "DEFAULT", 0),
                       wanted: (4, "OBJECT", "LOCAL", "DEFAULT", 0), other: (4, "OBJECT", "LOCAL", "DEFAULT", 0)}
        for name, place in (("store_target", wanted.referent), ("other_static", other.referent)):
            symbol_info[gtirb.Symbol(name, payload=place, module=module)] = (4, "OBJECT", "GLOBAL", "DEFAULT", 0)
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            symbol_info, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
        for name in ("scratchpad", "old_rsp", "memory_history_top"):
            gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        manager = LiveRegisterManager(module, abi)
        for inst in manager.decoder.get_instructions(block):
            module.aux_data["liveRegisterSets"].data[gtirb.Offset(
                block, inst.address - block.address)] = (1 << len(registers)) - 1
        passes = PassManager()
        passes.add(X64TransientMemlogPass(manager, block.section, manager.decoder, arch))
        passes.run(ir)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ir.save_protobuf(root / "store.gtirb")
            printed = subprocess.run([os.environ.get("PPRINTER_PATH", "gtirb-pprinter"),
                                      "--ir", str(root / "store.gtirb"), "--asm", str(root / "store.S")],
                                     capture_output=True, text=True)
            self.assertEqual(printed.returncode, 0, printed.stderr)
            source = Path(__file__).with_name("fixtures") / "x64_static_memlog.c"
            compiled = subprocess.run(["cc", "-O2", "-no-pie", str(source), str(root / "store.S"),
                                       "-o", str(root / "check")], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("the log names the stored static and the rollback restores it", executed.stdout)


if __name__ == "__main__":
    unittest.main()
