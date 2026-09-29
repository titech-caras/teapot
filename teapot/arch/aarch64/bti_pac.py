"""Opt-in BTI plus signed returns: --target-identification aarch64-bti-pac.

AArch64 only. The BTI target policy is unchanged: range checks, the return
predicate and the deferred transient-target decision stay as they are. The mode
adds normal-path return signing and activates PAC after BTI, so an
authentication failure inside simulation rolls back through the runtime's
malformed-target path and outside simulation is forwarded unchanged.
"""
import gtirb

from teapot.arch.aarch64.bti import AArch64BTIArchitecture


class AArch64BTIPACArchitecture(AArch64BTIArchitecture):
    """BTI with signed return addresses; no target-policy change."""

    def checkpoint_lib_symbols(self):
        return super().checkpoint_lib_symbols() + ["libcheckpoint_enable_aarch64_bti_pac"]

    def init_library_patch(self):
        return self.constraints()(lambda ctx: """
            stp x0, x1, [sp, #-32]!
            stp x2, x30, [sp, #16]
            bl libcheckpoint_enable_aarch64_bti_pac
            ldp x2, x30, [sp, #16]
            ldp x0, x1, [sp], #32
        """)

    def normalize_passes(self, decoder, reg_manager):
        from teapot.passes.preprocessing.sign_return_addresses_pass import (
            AArch64SignReturnAddressesPass,
        )

        return super().normalize_passes(decoder, reg_manager) + [
            AArch64SignReturnAddressesPass(self, decoder)]

    @staticmethod
    def finalize_bti_layout(pipeline):
        AArch64BTIArchitecture.finalize_bti_layout(pipeline)
        module = pipeline.module
        module.aux_data["teapotTargetIdentification"] = gtirb.AuxData(
            "aarch64-bti-pac-v1", "string")
        # A weak alias the runtime resolves weakly; its address makes the
        # runtime's preinit activate PAC before any constructor can run a
        # signed function. Multiple component objects may define it weakly.
        name = "teapot_aarch64_bti_pac_rewrite_marker"
        if next(module.symbols_named(name), None) is not None:
            raise ValueError("input collides with reserved PAC marker symbol")
        blocks = sorted(pipeline.text_section.code_blocks,
                        key=lambda block: (block.address is None, block.address or 0, block.offset))
        if not blocks:
            raise ValueError("PAC mode requires at least one text block")
        marker = gtirb.Symbol(name=name, payload=blocks[0], at_end=False, module=module)
        info = module.aux_data.setdefault(
            "elfSymbolInfo",
            gtirb.AuxData({}, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"))
        info.data[marker] = (0, "NOTYPE", "WEAK", "DEFAULT", 0)
