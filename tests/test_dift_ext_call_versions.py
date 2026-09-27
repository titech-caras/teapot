import subprocess
import unittest
from pathlib import Path

import gtirb
from gtirb_rewriting.decoder import GtirbInstructionDecoder
from gtirb_rewriting import _auxdata

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.passes.preprocessing.dift_ext_call_pass import DiftExtCallPass


class DiftExtCallVersionTests(unittest.TestCase):
    def test_signal_runtime_wrappers_do_not_depend_on_dift(self):
        for wrap_dift in (False, True):
            for name in ("signal", "sigaction"):
                with self.subTest(wrap_dift=wrap_dift, name=name):
                    module = gtirb.Module(name="signal-call")
                    section = gtirb.Section(name=".text", module=module)
                    symbol = gtirb.Symbol(name=name, module=module)
                    versions = {symbol: (2, False)}
                    _auxdata.elf_symbol_versions.set(module, ({}, {}, versions))
                    transform = DiftExtCallPass(section, None, wrap_dift_calls=wrap_dift)
                    transform.begin_module(module, [], None)
                    transform.symbols_to_rename.add(symbol)
                    transform.end_module(module, [])
                    self.assertEqual(symbol.name, name + "__teapot_wrapper__")
                    self.assertNotIn(symbol, versions)

    def test_call_relocation_takes_precedence_over_plt_anchor(self):
        for arch, isa, contents, expression_offset in (
            (X64Architecture(), gtirb.Module.ISA.X64, "488d0500000000e800000000", 8),
            (AArch64Architecture(), gtirb.Module.ISA.ARM64, "0000001000000094", 4),
            (RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported, "13050000ef000000", 4),
        ):
            for tail_call in (False, True):
                with self.subTest(arch=arch.name, tail_call=tail_call):
                    ir = gtirb.IR()
                    module = gtirb.Module(name="external-call", isa=isa, ir=ir,
                                          byte_order=gtirb.Module.ByteOrder.Little)
                    if arch.name == "riscv64":
                        module.aux_data["archInfo"] = gtirb.AuxData(
                            {"ISA": "RISCV64"}, "mapping<string,string>")
                    section = gtirb.Section(name=".text", module=module)
                    plt = gtirb.Section(name=".plt", module=module)
                    encoded = bytes.fromhex(contents)
                    if tail_call:
                        jump = bytes.fromhex({"x64": "e900000000", "aarch64": "00000014",
                                              "riscv64": "6f000000"}[arch.name])
                        encoded = encoded[:-len(jump)] + jump
                    interval = gtirb.ByteInterval(address=0x1000, contents=encoded, section=section)
                    block = gtirb.CodeBlock(size=len(interval.contents), byte_interval=interval)
                    target = gtirb.CodeBlock(size=4)
                    gtirb.ByteInterval(address=0x2000, contents=b"\0" * 4, blocks=[target], section=plt)
                    anchor = gtirb.Symbol(name=".L_pcrel_2000", payload=target, module=module)
                    fread = gtirb.Symbol(name="fread", payload=gtirb.ProxyBlock(module=module), module=module)
                    data_reference = gtirb.Symbol(
                        name="memcpy", payload=gtirb.ProxyBlock(module=module), module=module)
                    interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, data_reference)
                    interval.symbolic_expressions[expression_offset] = gtirb.SymAddrConst(0, fread)
                    # A low relocation needs the exact AUIPC anchor unchanged.
                    target.byte_interval.symbolic_expressions[0] = gtirb.SymAddrConst(
                        0, anchor, attributes={gtirb.SymbolicExpression.Attribute.LO12})
                    ir.cfg.add(gtirb.Edge(block, target, gtirb.Edge.Label(
                        type=gtirb.EdgeType.Branch if tail_call else gtirb.EdgeType.Call)))
                    versions = {fread: (2, False), data_reference: (3, False)}
                    _auxdata.elf_symbol_versions.set(module, ({}, {}, versions))
                    transform = DiftExtCallPass(section, GtirbInstructionDecoder(isa))
                    transform.begin_module(module, [], None)
                    transform.visit_code_block(block)
                    transform.end_module(module, [])
                    self.assertEqual(fread.name, "fread__dift_wrapper__")
                    self.assertEqual(anchor.name, ".L_pcrel_2000")
                    self.assertIs(target.byte_interval.symbolic_expressions[0].symbol, anchor)
                    self.assertEqual(data_reference.name, "memcpy")
                    self.assertEqual(versions, {data_reference: (3, False)})

    def test_all_forwarded_target_aliases_are_considered(self):
        ir = gtirb.IR()
        module = gtirb.Module(name="aliases", isa=gtirb.Module.ISA.X64, ir=ir,
                              byte_order=gtirb.Module.ByteOrder.Little)
        text = gtirb.Section(name=".text", module=module)
        plt = gtirb.Section(name=".plt", module=module)
        block = gtirb.CodeBlock(size=2)
        gtirb.ByteInterval(address=0x1000, contents=b"\xff\xd0", blocks=[block], section=text)
        target = gtirb.CodeBlock(size=1)
        gtirb.ByteInterval(address=0x2000, contents=b"\xc3", blocks=[target], section=plt)
        anchor = gtirb.Symbol(name="local_anchor", payload=target, module=module)
        aliases = [gtirb.Symbol(name=name, payload=target, module=module) for name in ("plt1", "plt2")]
        fread = gtirb.Symbol(name="fread", payload=gtirb.ProxyBlock(module=module), module=module)
        _auxdata.symbol_forwarding.set(module, {alias: fread for alias in aliases})
        ir.cfg.add(gtirb.Edge(block, target, gtirb.Edge.Label(type=gtirb.EdgeType.Call, direct=False)))
        transform = DiftExtCallPass(text, GtirbInstructionDecoder(module.isa))
        transform.begin_module(module, [], None)
        transform.visit_code_block(block)
        self.assertEqual(transform.symbols_to_rename, {anchor, *aliases})
        transform.end_module(module, [])
        self.assertEqual(fread.name, "fread__dift_wrapper__")
        self.assertEqual(anchor.name, "local_anchor")

    def test_internal_calls_are_not_wrapped(self):
        ir = gtirb.IR()
        module = gtirb.Module(name="internal", isa=gtirb.Module.ISA.X64, ir=ir)
        section = gtirb.Section(name=".text", module=module)
        block, target = gtirb.CodeBlock(size=5), gtirb.CodeBlock(size=1, offset=5)
        interval = gtirb.ByteInterval(address=0x1000, contents=b"\xe8\0\0\0\0\xc3",
                                      blocks=[block, target], section=section)
        symbol = gtirb.Symbol(name="memcpy", payload=target, module=module)
        interval.symbolic_expressions[1] = gtirb.SymAddrConst(0, symbol)
        ir.cfg.add(gtirb.Edge(block, target, gtirb.Edge.Label(type=gtirb.EdgeType.Call)))
        transform = DiftExtCallPass(section, GtirbInstructionDecoder(module.isa))
        transform.begin_module(module, [], None)
        transform.visit_code_block(block)
        transform.end_module(module, [])
        self.assertEqual(symbol.name, "memcpy")

    def test_inflate_lifecycle_calls_are_wrapped(self):
        # The pass renames exactly the names this predicate accepts; the renaming itself is
        # checked by test_only_wrapped_symbols_lose_their_versions.
        lifecycle = ("inflate", "inflateInit_", "inflateInit2_", "inflateReset", "inflateReset2",
                     "inflateResetKeep", "inflateEnd", "inflateCopy", "inflateSetDictionary",
                     "inflatePrime", "inflateSync")
        self.assertEqual([name for name in lifecycle if DiftExtCallPass.should_ignore_dift_wrapper(name)], [])

    def test_assembly_fixup_keeps_symbol_versions(self):
        script = Path(__file__).resolve().parents[1] / "scripts/fix_asm.sed"
        source = ".symver dependency,dependency@DEPENDENCY_1.0\n"
        result = subprocess.run(["sed", "-f", str(script)], input=source,
                                text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, source)

    def test_only_wrapped_symbols_lose_their_versions(self):
        for wrap in (False, True):
            for forwarded in (False, True):
                with self.subTest(wrap=wrap, forwarded=forwarded):
                    module = gtirb.Module(name="versions")
                    section = gtirb.Section(name=".text", module=module)
                    memcpy = gtirb.Symbol(name="memcpy", module=module)
                    untouched = gtirb.Symbol(name="some_versioned_function", module=module)
                    versions = {memcpy: (2, False), untouched: (3, False)}
                    _auxdata.elf_symbol_versions.set(module, ({}, {}, versions))
                    targets = {memcpy, untouched}
                    if forwarded:
                        proxies = {
                            gtirb.Symbol(name=sym.name + "_plt", module=module): sym
                            for sym in targets
                        }
                        _auxdata.symbol_forwarding.set(module, proxies)
                        targets = set(proxies)
                    transform = DiftExtCallPass(section, None, wrap_dift_calls=wrap)
                    transform.begin_module(module, [], None)
                    transform.symbols_to_rename.update(targets)
                    transform.end_module(module, [])
                    self.assertEqual(versions[untouched], (3, False))
                    self.assertEqual(untouched.name, "some_versioned_function")
                    if wrap:
                        self.assertNotIn(memcpy, versions)
                        self.assertEqual(memcpy.name, "memcpy__dift_wrapper__")
                    else:
                        self.assertEqual(versions[memcpy], (2, False))
                        self.assertEqual(memcpy.name, "memcpy")


if __name__ == "__main__":
    unittest.main()
