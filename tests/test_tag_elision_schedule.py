"""An enforcing replay keeps every eager-selected prefix and flush boundary."""
from unittest.mock import patch
import unittest

import gtirb
from gtirb_rewriting import Assembler, PassManager
from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.liveness import LiveRegisterManager
from teapot.passes.transient.lazy_dift import transient_replay_pass
from teapot.passes.transient.gadget_policy.mem_operand.x64 import X64TransientMemOperandPoliciesPass
from teapot.passes.transient.gadget_policy.mem_operand.aarch64 import AArch64TransientMemOperandPoliciesPass
from teapot.passes.transient.gadget_policy.mem_operand.riscv64 import RISCV64TransientMemOperandPoliciesPass
from test_live_register_preservation import make_module
from runtime_contract_support import fixture_layout


CASES = (
    (X64Architecture, gtirb.Module.ISA.X64, X64TransientMemOperandPoliciesPass,
     '.intel_syntax noprefix\n',
     'mov [rdi],rax\nmov r10,rsi\nmov r11,rdx\nmov rbx,[r8]\n'
     'mov [r9+3],rbx\nmov rcx,[rbx]\ncmp r10,r11\nmov rdi,[rax]\nret'),
    (AArch64Architecture, gtirb.Module.ISA.ARM64, AArch64TransientMemOperandPoliciesPass,
     '', 'str x0,[x1]\nmov x10,x2\nmov x11,x3\nldr x4,[x5]\n'
     'str x4,[x6,#8]\nldr x7,[x4]\ncmp x10,x11\nldr x1,[x0]\nret'),
    (RISCV64Architecture, gtirb.Module.ISA.ValidButUnsupported, RISCV64TransientMemOperandPoliciesPass,
     '.attribute arch,"rv64imafd"\n.option norvc\n',
     'sd a0,0(a1)\nmv t3,a2\nmv t4,a3\nld a4,0(a5)\n'
     'sd a4,8(a6)\nld a7,0(a4)\nsltu t5,t3,t4\nld a1,0(a0)\nret'),
)


def pending_state(replay):
    return (id(replay.effects), tuple(replay.effects), id(replay.llvm_ir), tuple(replay.llvm_ir),
            replay.tempval_cnt, replay.scratchpad_offset, frozenset(replay.pending_registers),
            replay.pending_memory, replay.pending_queue_apply, replay._elision_pricing)


def register_names(registers):
    values = registers.registers if hasattr(registers, 'registers') else registers
    return {register.name for register in values}


class ElisionSchedulingTests(unittest.TestCase):
    def run_case(self, case, pressure, enforcing, *, immediate=False, pairs=False):
        kind, isa, policy_kind, directive, body = case
        arch = kind()
        if pairs and arch.name == 'aarch64':
            body = body.replace('str x0,[x1]', 'stp x0,x2,[x1]')
            body = body.replace('ldr x4,[x5]', 'ldp x4,x8,[x5]')
        ir, module, block, abi, registers = make_module(arch, isa, b'')
        assembler = Assembler(module)
        assembler.assemble(directive + body)
        contents = assembler.finalize().text_section.data
        block.byte_interval.contents = contents
        block.byte_interval.size = block.size = len(contents)
        for name in dict.fromkeys((*arch.checkpoint_lib_symbols(),
                     'scratchpad', 'dift_reg_tags', 'dift_reg_queued_tags', 'dift_reg_queue_pending',
                     'old_rsp', 'memory_history_top', 'memory_history', 'teapot_shadow_registry',
                     'teapot_shadow_registry_count', 'teapot_shadow_mapping_ready',
                     'report_gadget_KASPER_CACHE', 'report_gadget_KASPER_MDS')):
            gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        manager = LiveRegisterManager(module, abi)
        full = (1 << len(registers))-1
        for index, inst in enumerate(manager.decoder.get_instructions(block)):
            masks = {'all-live': full, 'all-dead': 0,
                     'isolated-dead': 0 if index == 1 else full,
                     'changing-pressure': full >> (index % len(registers))}
            module.aux_data['liveRegisterSets'].data[gtirb.Offset(block, inst.address-block.address)] = masks[pressure]
        memory = policy_kind(manager, block.section, manager.decoder, arch, dift_layout=fixture_layout(arch.name))
        replay = transient_replay_pass(arch, manager, block.section, manager.decoder,
            memory_policy=memory, dift_layout=fixture_layout(arch.name),
            shadow_mapping_enforcement=enforcing, immediate=immediate)
        selected, emitted, rebuilt = [], [], []
        original_select = replay._select_replay
        original_emit = replay._emit_replay
        original_rebuild = replay._rebuild_replay_body

        def select(block, function, index, required):
            before = pending_state(replay)
            # Pricing may compile LLVM, but must not create new GTIRB nodes,
            # consume effects, change capture/SSA counters, or build actual IR.
            with patch('uuid.uuid4', side_effect=AssertionError('pricing allocated a UUID')):
                choice = original_select(block, function, index, required)
            self.assertEqual(before, pending_state(replay))
            self.assertNotIn('@teapot_shadow_registry', '\n'.join(replay.llvm_ir))
            selected.append((index, required, *choice[:3],
                             tuple(effect.instruction for effect in replay.effects[:choice[2]]),
                             tuple(line for effect in replay.effects[:choice[2]] for line in effect.ir)))
            return choice

        def rebuild(effects):
            before = pending_state(replay)
            # Emit only from the recorded captures. A second address lookup or
            # capture patch can mutate relocation/UUID state and is forbidden.
            with patch('uuid.uuid4', side_effect=AssertionError('rebuild allocated a UUID')), \
                    patch.object(type(replay), '_build_store_values_patch',
                                 side_effect=AssertionError('rebuild emitted a capture')), \
                    patch.object(arch, 'mem_operand_address_expression',
                                 side_effect=AssertionError('rebuild resolved a relocation')):
                result = original_rebuild(effects)
            self.assertEqual(before, pending_state(replay))
            rebuilt.append(result)
            return result

        def emit(block, function, index, offset, assembly, usage, plan):
            # The real body, not the cheaper pricing body, determines saves.
            self.assertEqual(register_names(usage), register_names(replay._get_register_usage(assembly)))
            emitted.append((index, offset, register_names(usage), assembly))
            return original_emit(block, function, index, offset, assembly, usage, plan)

        passes = PassManager()
        passes.add(replay)
        with patch.object(replay, '_select_replay', side_effect=select), \
                patch.object(replay, '_rebuild_replay_body', side_effect=rebuild), \
                patch.object(replay, '_emit_replay', side_effect=emit):
            passes.run(ir)
        self.assertEqual(len(selected), len(emitted))
        self.assertEqual(len(rebuilt), len(selected) if enforcing else 0)
        if enforcing:
            self.assertTrue(any('@teapot_shadow_registry' in body for body in rebuilt))
        return selected, emitted

    def test_same_boundaries_prefixes_flushes_and_actual_allocation(self):
        for case in CASES:
            for pressure in ('all-live', 'all-dead', 'isolated-dead', 'changing-pressure'):
                with self.subTest(arch=case[0]().name, pressure=pressure):
                    eager, _ = self.run_case(case, pressure, False)
                    enforcing, _ = self.run_case(case, pressure, True)
                    self.assertEqual(eager, enforcing)

    def test_immediate_and_pair_capture_rebuilds_keep_boundaries(self):
        for case in CASES:
            with self.subTest(arch=case[0]().name):
                eager, _ = self.run_case(case, 'all-live', False, immediate=True, pairs=True)
                enforcing, _ = self.run_case(case, 'all-live', True, immediate=True, pairs=True)
                self.assertEqual(eager, enforcing)


if __name__ == '__main__':
    unittest.main()
