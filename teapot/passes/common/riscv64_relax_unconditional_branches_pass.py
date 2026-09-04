import gtirb
from gtirb_rewriting import Pass, Patch


class RISCV64RelaxUnconditionalBranchesPass(Pass):
    """Replace distant direct jumps with spill-preserving long jumps."""

    # JAL reaches just under +/-1 MiB. Relax at 768 KiB, then let the
    # architecture driver relayout and rescan until later growth reaches a
    # fixed point.
    JAL_RELAX_THRESHOLD = 3 * (1 << 18)

    def __init__(self, transient_section, text_transient_mapping,
                 landing_pad_targets, decoder, arch):
        self.transient_section = transient_section
        self.text_transient_mapping = text_transient_mapping
        self.landing_pad_targets = landing_pad_targets
        self.decoder = decoder
        self.arch = arch
        self.relaxed = 0
        self.direct_landing_pads = 0

    def begin_module(self, module, functions, rewriting_ctx):
        self.relaxed = 0
        self.direct_landing_pads = 0
        original_by_transient = {
            transient.uuid: original_uuid
            for original_uuid, transient in self.text_transient_mapping.code_blocks_map.items()
        }
        symbol_names = {symbol.name for symbol in module.symbols}

        for block in list(self.transient_section.code_blocks):
            if block.size == 0 or block.address is None or block.byte_interval is None:
                continue
            instructions = list(self.decoder.get_instructions(block))
            if not instructions:
                continue
            instruction = instructions[-1]
            if instruction.mnemonic not in {"j", "c.j"}:
                continue

            byte_interval_offset = block.offset + instruction.address - block.address
            expression = block.byte_interval.symbolic_expressions.get(byte_interval_offset)
            if not isinstance(expression, gtirb.SymAddrConst):
                continue
            target = expression.symbol.referent
            if (not isinstance(target, gtirb.CodeBlock) or target.address is None or
                    target.section is None or target.section.name != self.transient_section.name):
                continue
            distance = target.address + expression.offset - instruction.address
            if abs(distance) < self.JAL_RELAX_THRESHOLD:
                continue
            if expression.offset != 0:
                raise ValueError(
                    f"cannot relax RV64 jump with nonzero target offset at {instruction.address:#x}")

            original_uuid = original_by_transient.get(target.uuid)
            landing_uuid = original_uuid if original_uuid is not None else target.uuid
            landing_name = self.arch.landing_pad_entry_label(landing_uuid)
            landing_name_is_new = landing_name not in symbol_names
            if landing_name_is_new:
                gtirb.Symbol(name=landing_name, payload=target, module=module)
                symbol_names.add(landing_name)
            if original_uuid is not None:
                self.landing_pad_targets.add(original_uuid)
            elif landing_name_is_new:
                # Instrumentation can introduce targets that have no original
                # .text block in the copy mapping. Give those blocks the same
                # conditional restore entry directly; ordinary incoming paths
                # see a clear flag and pass through transparently.
                rewriting_ctx.insert_at(
                    target,
                    0,
                    Patch.from_function(
                        self.arch.restore_landing_entry_patch(target.uuid)),
                )
                self.direct_landing_pads += 1

            @self.arch.constraints()
            def long_jump(ctx, target_name=landing_name):
                return self.arch.jump_symbol_with_first_spill_restore(target_name, "t0")

            rewriting_ctx.replace_at(
                block,
                instruction.address - block.address,
                instruction.size,
                Patch.from_function(long_jump),
            )
            self.relaxed += 1

    def end_module(self, module, functions):
        print(
            f"[teapot] RISCV64RelaxUnconditionalBranchesPass relaxed {self.relaxed} instructions "
            f"direct_landing_pads {self.direct_landing_pads}",
            flush=True,
        )
