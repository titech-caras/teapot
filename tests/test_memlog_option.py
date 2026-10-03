"""The public memlog switch covers application and instrumentation stores."""
from contextlib import redirect_stdout
import io
import unittest

import gtirb
from gtirb_rewriting import Assembler

from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from test_live_register_preservation import make_module, symbol_references
from runtime_contract_support import fixture_contract


class MemlogOptionTests(unittest.TestCase):
    def test_pipeline_flag_covers_dift_and_saved_return_tags(self):
        for arch, isa, code in (
                (X64Architecture(), gtirb.Module.ISA.X64, 'mov qword ptr [rdi],rax\nret'),
                (AArch64Architecture(), gtirb.Module.ISA.ARM64,
                 'stp x29,x30,[sp,#-16]!\nstr x0,[x1]\nldp x29,x30,[sp],#16\nret'),
                (RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported,
                 'addi sp,sp,-16\nsd ra,8(sp)\nsd a0,0(a1)\nld ra,8(sp)\naddi sp,sp,16\nret')):
            for enabled in (False, True):
                with self.subTest(arch=arch.name, memlog=enabled):
                    ir, module, block, _, _ = make_module(arch, isa, b'\0' * 4)
                    assembler = Assembler(module)
                    assembler.assemble(('.intel_syntax noprefix\n' if arch.name == 'x64' else '') + code)
                    data = assembler.finalize().text_section.data
                    block.byte_interval.contents = data
                    block.byte_interval.size = block.size = len(data)
                    ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                                         gtirb.Edge.Label(gtirb.Edge.Type.Return)))
                    pipeline = TeapotPipeline(ir, options=InstrumentationOptions(
                        enable_memlog=enabled, enable_gadgets=False), runtime_contract=fixture_contract(arch.name))
                    with redirect_stdout(io.StringIO()):
                        pipeline.run()
                    refs = symbol_references(pipeline.transient_section)
                    self.assertEqual('memory_history_top' in refs, enabled)


if __name__ == '__main__':
    unittest.main()
