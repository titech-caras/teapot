"""Address capture must survive temporary isolation of PC-relative anchors."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import gtirb
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import PassManager
from gtirb_rewriting.prepare import prepare_for_rewriting

from teapot.arch import RISCV64Architecture
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
from test_live_register_preservation import make_module
from runtime_contract_support import fixture_layout


class RiscvMemoryAddressCaptureTests(unittest.TestCase):
    def fixture(self, *, at_end=False):
        self.arch = RISCV64Architecture()
        ir, module, block, abi, registers = make_module(
            self.arch, gtirb.Module.ISA.ValidButUnsupported,
            bytes.fromhex('177728000327c7aa67800000'))
        section = gtirb.Section(name='.data', module=module, flags={
            gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Readable,
            gtirb.Section.Flag.Writable, gtirb.Section.Flag.Initialized})
        target = gtirb.Symbol('target_value', payload=gtirb.DataBlock(size=4,
            byte_interval=gtirb.ByteInterval(address=0x3000, contents=bytes(4), section=section)), module=module)
        for name in ('scratchpad', 'dift_reg_tags'):
            gtirb.Symbol(name, payload=gtirb.ProxyBlock(module=module), module=module)
        anchor_block = gtirb.CodeBlock(size=0, byte_interval=block.byte_interval)
        anchor = gtirb.Symbol('.L_original_high', payload=anchor_block, at_end=at_end, module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        high = gtirb.SymAddrConst(0, target, {attrs.HI, attrs.PCREL})
        low = gtirb.SymAddrConst(0, anchor, {attrs.LO, attrs.PCREL})
        block.byte_interval.symbolic_expressions.update({0: high, 4: low})
        decoder = CachedGtirbInstructionDecoder(module.isa)
        module.aux_data['liveRegisterSets'].data = {
            gtirb.Offset(block, inst.address - block.address): (1 << len(registers)) - 1
            for inst in decoder.get_instructions(block)}
        return ir, module, block, abi, decoder, high, low

    def test_snapshot_survives_zero_size_anchor_isolation_and_symbol_rename(self):
        _, module, block, abi, decoder, high, low = self.fixture()
        inst = list(decoder.get_instructions(block))[1]
        operand = self.arch.memory_operand(inst)
        captured = self.arch.mem_operand_address_expression(block, inst, operand, 4)
        self.assertIs(captured.symbol, high.symbol)
        self.assertIsNot(captured, high)
        with prepare_for_rewriting(module, bytes.fromhex('13000000')):
            # Equal-offset block ordering can leave the empty anchor in the
            # producer interval on some runs. Model its permitted isolated
            # state explicitly, rather than relying on random UUID ordering.
            isolated = gtirb.ByteInterval(contents=b'', section=block.section)
            low.symbol.referent.byte_interval = isolated
            low.symbol.referent.offset = 0
            self.assertIsNone(self.arch._paired_pcrel_hi_expression(low))
            high.symbol.name = 'renamed_target'
            asm = self.arch.mem_operand_address_snippet(
                abi, inst, 't0', 't1', operand, mem_symexpr=captured)
            self.assertIn('%pcrel_hi(renamed_target)', asm)
            self.assertNotIn('mv t0, a4', asm)
            with self.assertRaisesRegex(ValueError, 'no valid HI anchor'):
                self.arch.mem_operand_address_snippet(abi, inst, 't0', 't1', operand, mem_symexpr=low)

    def test_end_anchor_and_addend_are_resolved_exactly(self):
        _, module, block, abi, decoder, high, low = self.fixture(at_end=True)
        # A nonempty preceding block may name the AUIPC at its end.
        interval = block.byte_interval
        interval.contents = bytes.fromhex('13000000') + interval.contents
        interval.size += 4
        block.offset = 4
        low.symbol.referent.size = 4
        interval.symbolic_expressions = {4: high, 8: low}
        high.offset = 12
        self.assertIs(self.arch._paired_pcrel_hi_expression(low), high)
        inst = list(decoder.get_instructions(block))[1]
        operand = self.arch.memory_operand(inst)
        captured = self.arch.mem_operand_address_expression(block, inst, operand, 4)
        asm = self.arch.mem_operand_address_snippet(abi, inst, 't0', 't1', operand, mem_symexpr=captured)
        self.assertIn('%pcrel_hi(target_value+12)', asm)
        low.offset = 4
        with self.assertRaisesRegex(ValueError, 'no valid HI anchor'):
            self.arch.mem_operand_address_expression(block, inst, operand, 4)

    def capture_from_real_llvm_pass(self):
        ir, module, block, abi, decoder, _, _ = self.fixture()
        manager = LiveRegisterManager(module, abi, decoder, analysis_scope='block')
        captured = []

        class Probe(RISCV64TextDiftPropagationLLVMPass):
            def _build_store_values_patch(self, inst, operands, *args, **kwargs):
                result = super()._build_store_values_patch(inst, operands, *args, **kwargs)
                if not operands:
                    return result

                def emit(context):
                    assembly = result(context)
                    captured.append(assembly)
                    return assembly

                emit.constraints = result.constraints
                return emit

        passes = PassManager()
        passes.add(Probe(manager, block.section, decoder, self.arch, dift_layout=fixture_layout('riscv64')))
        passes.run(ir)
        self.assertEqual(len(captured), 1)
        self.assertIn('%pcrel_hi(target_value)', captured[0])
        self.assertNotIn('mv t0, a4', captured[0])
        return captured[0]

    def test_real_llvm_capture_does_not_read_the_overwritten_base(self):
        self.capture_from_real_llvm_pass()

    @unittest.skipUnless(shutil.which('riscv64-linux-gnu-gcc') and shutil.which('qemu-riscv64'),
                         'RISC-V compiler and emulator required')
    def test_emitted_capture_executes_after_a_self_overwriting_load(self):
        capture = self.capture_from_real_llvm_pass()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assembly, binary = root / 'capture.S', root / 'capture'
            assembly.write_text('''
.option norelax
.option norvc
.text
.globl _start
_start:
.L_load:
    auipc a4, %pcrel_hi(target_value)
    lw a4, %pcrel_lo(.L_load)(a4)
''' + capture + '''
    la a0, target_value
    la a1, scratchpad
    ld a1, 0(a1)
    bne a0, a1, bad
    li a0, 0
    j done
bad:
    li a0, 77
done:
    li a7, 93
    ecall
.data
.balign 8
target_value: .word 0
.bss
.balign 16
scratchpad: .skip 1048576
''')
            subprocess.run(['riscv64-linux-gnu-gcc', '-nostdlib', '-static', '-no-pie',
                            '-march=rv64imafd', '-mabi=lp64d', '-Wl,--no-relax',
                            str(assembly), '-o', str(binary)], check=True, capture_output=True)
            result = subprocess.run(['qemu-riscv64', str(binary)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
