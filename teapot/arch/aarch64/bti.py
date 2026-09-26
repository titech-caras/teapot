"""Opt-in, page-isolated BTI experiment; the ordinary architecture is unchanged.

The runtime validates every possible aligned normal-text landing before it
enables this path. Range checks remain, RET uses both marker words, and all
other instrumentation is retained. See experiments/hardware_targets/BTI.md.
"""
import gtirb

from teapot.arch.aarch64.architecture import AArch64Architecture


class AArch64BTIArchitecture(AArch64Architecture):
    MAGIC_WORDS = (0xd50324df, AArch64Architecture.MAGIC_WORDS[1])  # bti jc + magic
    uses_bti_landing_checks = True

    def checkpoint_lib_symbols(self):
        return super().checkpoint_lib_symbols() + ["libcheckpoint_enable_aarch64_bti"]

    def init_library_patch(self):
        return self.constraints()(lambda ctx: """
            stp x0, x1, [sp, #-32]!
            stp x2, x30, [sp, #16]
            bl libcheckpoint_enable_aarch64_bti
            ldp x2, x30, [sp, #16]
            ldp x0, x1, [sp], #32
        """)

    def indirect_branch_hardware_check_patch(self, operand_str, transient_start_symbol,
                                             transient_end_symbol, text_start_symbol,
                                             text_end_symbol, reads_registers=None):
        @self.constraints(scratch_registers=2, clobbers_flags=True,
                          reads_registers=reads_registers or set())
        def patch(ctx):
            target, temp = ctx.scratch_registers[:2]
            return f"""
                mov {target}, {operand_str}
                {self.load_address(temp, transient_start_symbol.name)}
                cmp {target}, {temp}
                b.lo 4f
                {self.load_address(temp, transient_end_symbol.name)}
                cmp {target}, {temp}
                b.lo 3f
            4:
                {self.load_address(temp, text_start_symbol.name)}
                cmp {target}, {temp}
                b.lo 2f
                {self.load_address(temp, text_end_symbol.name)}
                cmp {target}, {temp}
                b.hs 2f
                tst {target}, #3
                b.eq 3f
            5:
                // Preserve the old byte-address predicate on unaligned normal
                // targets; only aligned instruction targets use BTI. Scratch
                // registers exclude operand_str, so it survives this fallback.
                ldr {self.w_reg(temp)}, [{target}]
                {self.mov_w_imm32(self.w_reg(target), self.MAGIC_WORDS[0])}
                cmp {self.w_reg(temp)}, {self.w_reg(target)}
                b.ne 2f
                ldr {self.w_reg(temp)}, [{operand_str}, #4]
                {self.mov_w_imm32(self.w_reg(target), self.MAGIC_WORDS[1])}
                cmp {self.w_reg(temp)}, {self.w_reg(target)}
                b.ne 2f
                b 3f
            2:
                b restore_checkpoint_MALFORMED_INDIRECT_BR
            3:
                nop
            """
        return patch

    @staticmethod
    def finalize_bti_layout(pipeline):
        from gtirb_rewriting import PassManager
        from teapot.passes.common.aarch64_outline_native_landings_pass import AArch64OutlineNativeLandingsPass

        module = pipeline.module
        section_name = ".teapot_bti_normal"
        if any(section.name == section_name for section in module.sections):
            raise ValueError("input already contains the reserved BTI section")
        outline = AArch64OutlineNativeLandingsPass(pipeline.text_section, pipeline.arch.MAGIC_WORDS)
        manager = PassManager()
        manager.add(outline)
        pipeline._run_pass_manager(manager, 'outline-native-landings')
        if outline.outlined:
            # New cross-section direct branches also need range convergence.
            pipeline.arch.relax_conditional_branches(module)
            pipeline._refresh_register_analysis()
        symbols = (
            ("text_start", pipeline.text_section_start_symbol),
            ("text_end", pipeline.text_section_end_symbol),
            ("transient_start", pipeline.transient_section_start_symbol),
            ("transient_end", pipeline.transient_section_end_symbol),
        )
        info = module.aux_data.setdefault("elfSymbolInfo", gtirb.AuxData(
            {}, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"))
        for suffix, source in symbols:
            name = "__teapot_bti_" + suffix
            if next(module.symbols_named(name), None) is not None:
                raise ValueError("input collides with reserved BTI symbol " + name)
            alias = gtirb.Symbol(name=name, payload=source.referent,
                                at_end=source.at_end, module=module)
            info.data[alias] = (0, "NOTYPE", "GLOBAL", "HIDDEN", 0)
        # Rename only after the normal pipeline: no pass is silently omitted.
        pipeline.text_section.name = section_name
        module.aux_data["teapotTargetIdentification"] = gtirb.AuxData("aarch64-bti-v1", "string")
