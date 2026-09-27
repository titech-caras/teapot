import unittest
import shutil
import subprocess
import tempfile
from pathlib import Path

import gtirb
from teapot.preprocess.copy_section import copy_section


class CopiedGotFunctionTests(unittest.TestCase):
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
