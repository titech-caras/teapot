"""Patch text that names a symbol of a shared name reaches that symbol when it runs.

tests/test_symbol_references.py checks which symbol the names in patch text
bind to. These tests print, assemble, link and run the rewritten code, under
QEMU, where a wrong binding makes the program fail:

- RV64 GP normalization of a relaxed build. The linker relaxes the accesses
  to two statics called target, in two files, into gp-relative loads, stores
  and address computations. The normalization pass rewrites them into
  pc-relative sequences, which name the static in text, so these are the
  program's own accesses outside speculation.
- An AArch64 memory log of a store through adrp and :lo12: to one of two
  statics called counter. The log's address computation names the static in
  :lo12:, and the rollback replays the log.
"""
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import PassManager
from gtirb_rewriting.abi import _ABIS

from teapot.arch import AArch64Architecture, RISCV64Architecture
from teapot.liveness import LiveRegisterManager
from teapot.passes.preprocessing.normalize_riscv64_gp_references_pass import NormalizeRISCV64GPReferencesPass
from teapot.passes.transient.memlog.aarch64 import AArch64TransientMemlogPass
from test_live_register_preservation import make_module
from test_symbol_references import ATTRIBUTES, INFO_TYPE, data_blocks, two_places

FIXTURES = Path(__file__).with_name("fixtures")
PPRINTER = os.environ.get("PPRINTER_PATH", "gtirb-pprinter")
GP_STATICS_EXIT = {1: "a load read the other static", 2: "an address computation yielded the other static",
                   3: "a store to the first static wrote the other one",
                   4: "a store to the second static wrote the other one"}


def run(command, **kwargs):
    return subprocess.run([str(part) for part in command], capture_output=True, text=True, timeout=300, **kwargs)


class SymbolReferenceExecutionTests(unittest.TestCase):
    def check(self, result, what):
        self.assertEqual(result.returncode, 0, f"{what}: {result.stdout}{result.stderr}")

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("riscv64-linux-gnu-gcc", "qemu-riscv64", "ddisasm",
                                                              PPRINTER)),
                         "requires the RV64 cross compiler, qemu-riscv64, DDisasm and the printer")
    def test_riscv64_gp_normalization_of_a_relaxed_build_reaches_each_static(self):
        sources = [FIXTURES / "riscv64_gp_statics" / name for name in ("start.S", "main.c", "first.c", "second.c")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # The linker relaxes by default: each lui/%lo access becomes gp-relative.
            self.check(run(["riscv64-linux-gnu-gcc", "-O1", "-fno-pie", "-no-pie", "-nostdlib", "-static",
                            "-msmall-data-limit=8", *sources, "-o", root / "original"]), "compile")
            self.check(run(["qemu-riscv64", root / "original"]), "the original program")
            self.check(run(["ddisasm", root / "original", "--ir", root / "lift.gtirb", "-j", "1"]), "lift")
            ir = gtirb.IR.load_protobuf(str(root / "lift.gtirb"))
            module = ir.modules[0]
            statics = {symbol.referent.address: symbol for symbol in module.symbols_named("target")}
            self.assertEqual(len(statics), 2)
            # For an ordinary static whose name is shared, the current DDisasm
            # names such a reference by a label of its own. Other IR can name
            # the static: another frontend, hand-built IR (as in
            # tests/test_symbol_references.py), or an inferred .L_<address>
            # label that DDisasm does not check against the input's names.
            # Name it here: the test hardens the pass for such IR.
            references = 0
            for interval in module.byte_intervals:
                for expression in interval.symbolic_expressions.values():
                    if isinstance(expression, gtirb.SymAddrAddr) and expression.symbol2.name == "__global_pointer$":
                        expression.symbol1 = statics[expression.symbol1.referent.address]
                        references += 1
            # A load, a store and an address computation of each static.
            self.assertEqual(references, 6)
            arch = RISCV64Architecture()
            decoder = CachedGtirbInstructionDecoder(module.isa)
            normalization = NormalizeRISCV64GPReferencesPass(
                decoder, LiveRegisterManager(module, arch.register_abi(_ABIS), decoder), arch)
            passes = PassManager()
            passes.add(normalization)
            with redirect_stdout(io.StringIO()):
                passes.run(ir)
            self.assertEqual(normalization.normalized, 6)
            ir.save_protobuf(str(root / "normalized.gtirb"))
            self.check(run([PPRINTER, "--ir", root / "normalized.gtirb", "--asm", root / "normalized.S",
                            "--policy", "complete", "--shared", "no"]), "print")
            # The accesses are pc-relative now; keep them so.
            self.check(run(["riscv64-linux-gnu-gcc", "-nostdlib", "-static", "-no-pie", "-Wl,--no-relax",
                            root / "normalized.S", "-o", root / "normalized"]), "assemble and link")
            result = run(["qemu-riscv64", root / "normalized"])
            self.assertEqual(result.returncode, 0,
                             f"the normalized program exits {result.returncode}: "
                             f"{GP_STATICS_EXIT.get(result.returncode, result.stderr)}")

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("aarch64-linux-gnu-gcc", "qemu-aarch64", PPRINTER)),
                         "requires the AArch64 cross compiler, qemu-aarch64 and the printer")
    def test_aarch64_memory_log_through_lo12_restores_the_static_it_was_written_for(self):
        arch = AArch64Architecture()
        # adrp x1, counter; str w0, [x1, :lo12:counter]; ret
        ir, module, block, abi, registers = make_module(arch, gtirb.Module.ISA.ARM64,
                                                        bytes.fromhex("01000090200000b9c0035fd6"))
        wanted_block, other_block = data_blocks(module)
        # Name lookup returns the other static first.
        wanted, other = two_places(module, "counter", wanted_block, other_block)
        block.byte_interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, wanted)
        block.byte_interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, wanted, {ATTRIBUTES.LO12})
        entry = next(module.symbols_named("test_function"))
        module.aux_data["sectionProperties"] = gtirb.AuxData(
            {block.section: (1, 6), wanted.referent.section: (1, 3)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
        symbol_info = {entry: (block.size, "FUNC", "GLOBAL", "DEFAULT", 0),
                       wanted: (4, "OBJECT", "LOCAL", "DEFAULT", 0), other: (4, "OBJECT", "LOCAL", "DEFAULT", 0)}
        for name, place in (("store_target", wanted.referent), ("other_static", other.referent)):
            symbol_info[gtirb.Symbol(name, payload=place, module=module)] = (4, "OBJECT", "GLOBAL", "DEFAULT", 0)
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(symbol_info, INFO_TYPE)
        for name in ("scratchpad", "memory_history_top"):
            gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        manager = LiveRegisterManager(module, abi)
        for inst in manager.decoder.get_instructions(block):
            module.aux_data["liveRegisterSets"].data[gtirb.Offset(
                block, inst.address - block.address)] = (1 << len(registers)) - 1
        passes = PassManager()
        passes.add(AArch64TransientMemlogPass(manager, block.section, manager.decoder, arch))
        passes.run(ir)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ir.save_protobuf(str(root / "store.gtirb"))
            self.check(run([PPRINTER, "--ir", root / "store.gtirb", "--asm", root / "store.S"]), "print")
            self.check(run(["aarch64-linux-gnu-gcc", "-O2", "-static", "-no-pie", FIXTURES / "aarch64_static_memlog.c",
                            root / "store.S", "-o", root / "check"]), "assemble and link")
            # The instrumentation spills to a shadow stack AARCH64_SHADOW_STACK_SIZE (8 MiB) below sp, which the
            # runtime keeps mapped; QEMU's default guest stack is 8 MiB.
            result = run(["qemu-aarch64", "-s", "64M", root / "check"])
            self.check(result, "the memory log")
            self.assertIn("the log names the stored static and the rollback restores it", result.stdout)


if __name__ == "__main__":
    unittest.main()
