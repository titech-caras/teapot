"""The same input IR must not pick different code because Python hashes differ."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import gtirb
from teapot.liveness import LiveRegisterManager
from gtirb_rewriting import Assembler, PassManager

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.passes.transient.lazy_dift import AArch64TransientDiftLLVMPass
from teapot.passes.transient.lazy_dift import RISCV64TransientDiftLLVMPass
from teapot.passes.transient.lazy_dift import X64TransientDiftLLVMPass
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from teapot.pipeline import TeapotPipeline
from test_live_register_preservation import make_module
from runtime_contract_support import fixture_contract, fixture_contract_path, fixture_layout


VARIANTS = (
    (X64Architecture, gtirb.Module.ISA.X64,
     ".intel_syntax noprefix\nmov rax,[rdi+rcx*8]\nimul rax,rsi\nadd rax,rdx\n"
     "xchg rax,rbx\nmov [rdi+8],rax\nret",
     X64TransientDiftLLVMPass, X64TextDiftPropagationLLVMPass),
    (AArch64Architecture, gtirb.Module.ISA.ARM64,
     "add x0,x1,x2\neor x3,x4,x5\nldp x6,x7,[x8]\nstp x6,x7,[x9]\nldr x10,[x8,x9]\nret",
     AArch64TransientDiftLLVMPass, AArch64TextDiftPropagationLLVMPass),
    (RISCV64Architecture, gtirb.Module.ISA.ValidButUnsupported,
     ".option norvc\nadd a0,a1,a2\nxor a3,a4,a5\nld t0,8(a0)\nsd a3,8(a1)\nret",
     RISCV64TransientDiftLLVMPass, RISCV64TextDiftPropagationLLVMPass),
)


def rewritten_code(path, variant, mode):
    arch = VARIANTS[variant][0]()
    from gtirb_rewriting.abi import _ABIS
    abi = arch.register_abi(_ABIS)
    ir = gtirb.IR.load_protobuf(path)
    module = ir.modules[0]
    section = next(s for s in module.sections if s.name == ".text")
    manager = LiveRegisterManager(module, abi)
    if mode == 2:
        # The input stands in for the runtime symbols the single passes refer to.
        # The pipeline imports them itself and refuses a program that uses
        # their names (teapot/preprocess/runtime_names.py).
        for symbol in [symbol for symbol in module.symbols if isinstance(symbol.referent, gtirb.ProxyBlock)]:
            module.proxies.discard(symbol.referent)
            module.symbols.discard(symbol)
        TeapotPipeline(ir, runtime_contract=fixture_contract(arch.name)).run()
    else:
        passes = PassManager()
        passes.add(VARIANTS[variant][3 + mode](manager, section, manager.decoder, arch,
                                               dift_layout=fixture_layout(arch.name)))
        passes.run(ir)

    intervals = sorted(module.byte_intervals, key=lambda bi: (bi.section.name, bi.address or 0))
    interval_keys = {}
    counts = {}
    for interval in intervals:
        name = interval.section.name
        interval_keys[interval] = (name, counts.get(name, 0))
        counts[name] = counts.get(name, 0) + 1

    def symbol_key(symbol):
        referent = symbol.referent
        if isinstance(referent, gtirb.ByteBlock):
            # Assembly-local labels get fresh UUIDs. Compare their actual
            # targets, never discard register choices, bytes or relocations.
            return (*interval_keys[referent.byte_interval],
                    referent.offset + (referent.size if symbol.at_end else 0))
        return (symbol.name, symbol.value)

    result = []
    for interval in intervals:
        expressions = []
        for offset, expr in sorted(interval.symbolic_expressions.items()):
            if isinstance(expr, gtirb.SymAddrConst):
                value = (symbol_key(expr.symbol), expr.offset)
            else:
                value = (symbol_key(expr.symbol1), symbol_key(expr.symbol2), expr.scale, expr.offset)
            expressions.append((offset, sorted(a.name for a in expr.attributes), value))
        # Fresh section UUIDs can change temporary whole-module placement.
        # Preserve every byte and relocation target within its own interval.
        result.append((interval_keys[interval], bytes(interval.contents).hex(), expressions))
    return result


class RewriteReproducibilityTests(unittest.TestCase):
    def test_dift_rewrites_match_across_process_hash_seeds(self):
        for variant, (arch_type, isa, assembly, _, _) in enumerate(VARIANTS):
            arch = arch_type()
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ir, module, block, abi, registers = make_module(arch, isa, b"")
                assembler = Assembler(module)
                assembler.assemble(assembly)
                code = assembler.finalize().text_section.data
                block.byte_interval.contents = code
                block.byte_interval.size = block.size = len(code)
                for name in ("scratchpad", "dift_reg_tags", "dift_reg_queued_tags", "dift_reg_queue_pending", "old_rsp", "memory_history_top"):
                    gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
                manager = LiveRegisterManager(module, abi)
                for index, inst in enumerate(manager.decoder.get_instructions(block)):
                    # Exercise both dead-register allocation and all-live spills.
                    module.aux_data["liveRegisterSets"].data[gtirb.Offset(block, inst.address-block.address)] = \
                        (1 << len(registers)) - 1 if index % 2 else 0
                input_path = root / "input.gtirb"
                ir.save_protobuf(input_path)
                for mode in (0, 1, 2):
                    with self.subTest(arch=arch.name, mode=("transient", "text", "full")[mode]):
                        outputs = []
                        for seed in (1, 2, 42):
                            output = root / f"{mode}-{seed}.json"
                            process = subprocess.run(
                                [sys.executable, "-B", __file__, "--rewrite", str(input_path),
                                 str(variant), str(mode), str(output)],
                                env={**os.environ, "PYTHONHASHSEED": str(seed)},
                                capture_output=True, text=True, timeout=60)
                            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
                            outputs.append(json.loads(output.read_text()))
                        self.assertEqual(outputs[0], outputs[1])
                        self.assertEqual(outputs[0], outputs[2])

    @unittest.skipUnless(all(shutil.which(tool) for tool in ("gcc", "ddisasm", "gtirb-pprinter")),
                         "gcc, ddisasm and gtirb-pprinter are required")
    def test_lifted_rewrite_prints_the_same_assembly_across_heap_layouts(self):
        # Sets of GTIRB nodes hash by identity and iterate in heap-address
        # order, which ASLR moves between processes even under one hash seed.
        # Allocating nodes before the rewrite moves them deterministically.
        # The printed assembly must not change: section order and alignment
        # (layout), coverage indices and trampoline order (block visits),
        # copies' label names (their UUIDs), alias label order (symbols) and
        # the labels of relaxed jrcxz branches. The runtime is the one built
        # for a fuzzer, so that the rewrite numbers coverage guards.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "probe.c").write_text(LIFTED_PROBE)
            for command in (["gcc", "-O1", "-fno-pie", "-no-pie", "-nostdlib", "-fno-stack-protector",
                             "-Wl,-e,main", "probe.c", "-o", "probe"],
                            ["ddisasm", "probe", "--ir", "lift.gtirb", "-j", "1"]):
                result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=300)
                self.assertEqual(result.returncode, 0, f"{command}\n{result.stdout}\n{result.stderr}")
            printed = []
            for index, (nodes, seed) in enumerate(((0, 0), (997, 0), (3001, 42))):
                commands = (
                    [sys.executable, "-B", "-c", HEAP_SHIFTED_REWRITE, str(nodes), "lift.gtirb",
                     f"out{index}.gtirb", "--runtime-contract", str(fixture_contract_path("x64-coverage")),
                     "--compact-output"],
                    ["gtirb-pprinter", "--ir", f"out{index}.gtirb", "--asm", f"out{index}.S",
                     "--policy", "complete", "--shared", "no"])
                for command in commands:
                    result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=300,
                                            env={**os.environ, "PYTHONHASHSEED": str(seed)})
                    self.assertEqual(result.returncode, 0, f"{command}\n{result.stdout}\n{result.stderr}")
                printed.append((root / f"out{index}.S").read_text())
            self.assertIn("step_alias", printed[0])
            self.assertIn(".teapot_trampolines", printed[0])
            self.assertIn(".L__x64_jcxz_taken", printed[0])
            self.assertIn("guard_list_top", printed[0])
            self.assertEqual(printed[0], printed[1])
            self.assertEqual(printed[0], printed[2])


LIFTED_PROBE = r"""
int counter;

__attribute__((noinline)) int step(int value) {
    if (value & 1)
        counter += value;
    else
        counter -= value;
    for (int i = 0; i < value; i++)
        if (i % 3 == 0)
            counter ^= i;
    return counter;
}

int step_alias(int) __attribute__((alias("step")));

/* Teapot's last round relaxes this rel8-only branch. */
__attribute__((noinline)) long count_zero(long count) {
    long result = 1;
    __asm__ volatile("mov %1, %%rcx\n\tjrcxz 1f\n\tinc %0\n1:" : "+r"(result) : "r"(count) : "rcx");
    return result;
}

int main(void) {
    return step(7) + step_alias(4) + (int)count_zero(3);
}
"""

HEAP_SHIFTED_REWRITE = """
import sys
import gtirb
nodes = [(gtirb.Section(name=""), gtirb.ByteInterval(), gtirb.CodeBlock(), gtirb.Symbol(name=""))
         for _ in range(int(sys.argv[1]))]
sys.argv = ["teapot", *sys.argv[2:]]
from teapot.cmdline import main
main()
"""


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--rewrite":
        Path(sys.argv[5]).write_text(json.dumps(rewritten_code(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))))
    else:
        unittest.main()
