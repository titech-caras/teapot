"""Execute the production capture/replay wrappers in focused DIFT fixtures."""
from types import SimpleNamespace

import gtirb


def replay_asm(replay, inst, regs_read, regs_write, *, block=None,
               live_registers=None, **effects):
    if block is None:
        block = gtirb.CodeBlock(size=inst.size)
        gtirb.ByteInterval(address=inst.address, contents=bytes(inst.bytes), blocks=[block])
    replay._reset()
    replay.rewriting_ctx = SimpleNamespace(_abi=replay.arch.abi)
    plan = replay._plan_scratch_registers(2, live_registers)
    capture = replay._build_dift_patch(block, inst, 0, regs_read, regs_write,
                                     scratch_plan=plan, **effects)
    parsed = replay._parse_and_optimize_llvm(replay._format_llvm_ir(
        '\n'.join(replay.llvm_ir), target_triple=replay.target_triple))
    asm = replay._extract_function_asm(replay.target_machine.emit_assembly(parsed))
    flush = replay._build_optimized_dift_values_patch(
        asm, replay._get_register_usage(asm), scratch_plan=plan)
    if replay.arch.name == 'x64':
        from test_x64_rep_dift import wrapped_patch
        return wrapped_patch(replay.arch, capture) + wrapped_patch(replay.arch, flush)
    context = SimpleNamespace(stack_adjustment=0)
    # GNU as accepts architecture attributes only before the first opcode.
    # The full rewriter handles the patch's attribute; standalone fixtures
    # declare it at the start of their assembly unit instead.
    return (capture(context) + flush(context)).replace('.attribute arch, "rv64imafd"\n', '')
