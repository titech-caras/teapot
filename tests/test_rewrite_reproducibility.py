"""The same input IR must not pick different code because Python hashes differ."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import gtirb
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Assembler, PassManager

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.passes.common.dift.aarch64 import AArch64DiftPropagationPass
from teapot.passes.common.dift.riscv64 import RISCV64DiftPropagationPass
from teapot.passes.common.dift.x64 import X64DiftPropagationPass
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from teapot.pipeline import TeapotPipeline
from test_live_register_preservation import make_module


VARIANTS = (
    (X64Architecture, gtirb.Module.ISA.X64,
     ".intel_syntax noprefix\nmov rax,[rdi+rcx*8]\nimul rax,rsi\nadd rax,rdx\n"
     "xchg rax,rbx\nmov [rdi+8],rax\nret",
     X64DiftPropagationPass, X64TextDiftPropagationLLVMPass),
    (AArch64Architecture, gtirb.Module.ISA.ARM64,
     "add x0,x1,x2\neor x3,x4,x5\nldp x6,x7,[x8]\nstp x6,x7,[x9]\nldr x10,[x8,x9]\nret",
     AArch64DiftPropagationPass, AArch64TextDiftPropagationLLVMPass),
    (RISCV64Architecture, gtirb.Module.ISA.ValidButUnsupported,
     ".option norvc\nadd a0,a1,a2\nxor a3,a4,a5\nld t0,8(a0)\nsd a3,8(a1)\nret",
     RISCV64DiftPropagationPass, RISCV64TextDiftPropagationLLVMPass),
)


def rewritten_code(path, variant, mode):
    arch = VARIANTS[variant][0]()
    arch.install_decoder_compat()
    arch.install_rewriting_compat()
    from gtirb_rewriting.abi import _ABIS
    abi = arch.register_abi(_ABIS)
    ir = gtirb.IR.load_protobuf(path)
    module = ir.modules[0]
    section = next(s for s in module.sections if s.name == ".text")
    manager = LiveRegisterManager(module, abi)
    if mode == 2:
        TeapotPipeline(ir).run()
    else:
        passes = PassManager()
        passes.add(VARIANTS[variant][3 + mode](manager, section, manager.analyzer.decoder, arch))
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
                for name in ("scratchpad", "dift_reg_tags", "dift_reg_queued_tags", "old_rsp"):
                    gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
                manager = LiveRegisterManager(module, abi)
                for index, inst in enumerate(manager.analyzer.decoder.get_instructions(block)):
                    # Exercise both dead-register allocation and all-live spills.
                    module.aux_data["liveRegisterSets"].data[gtirb.Offset(block, inst.address-block.address)] = \
                        (1 << len(registers)) - 1 if index % 2 else 0
                input_path = root / "input.gtirb"
                ir.save_protobuf(input_path)
                for mode in (0, 1, 2):
                    with self.subTest(arch=arch.name, mode=("common", "llvm", "full")[mode]):
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


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--rewrite":
        Path(sys.argv[5]).write_text(json.dumps(rewritten_code(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))))
    else:
        unittest.main()
