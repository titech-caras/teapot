from teapot.arch.aarch64.assembly import AArch64AssemblyMixin
from teapot.arch.aarch64.abi import _ARM64_ELF
from teapot.arch.aarch64.asan import AArch64AsanPatchesMixin
from teapot.arch.aarch64.checkpoint import AArch64CheckpointPatchesMixin
from teapot.arch.aarch64.control_flow import AArch64ControlFlowPatchesMixin
from teapot.arch.aarch64.dift import AArch64DiftPatchesMixin
from teapot.arch.aarch64.gadget import AArch64GadgetPatchesMixin
from teapot.arch.aarch64.memlog import AArch64MemlogPatchesMixin
from teapot.arch.aarch64.operands import AArch64OperandMixin
from teapot.arch.aarch64.registers import AArch64RegisterMixin
from teapot.arch.aarch64.runtime import AArch64RuntimeMixin
from teapot.arch.aarch64.spill import AArch64ShadowStackMixin
from teapot.arch.architecture import Architecture


class AArch64Architecture(
        AArch64RuntimeMixin,
        AArch64AssemblyMixin,
        AArch64RegisterMixin,
        AArch64AsanPatchesMixin,
        AArch64MemlogPatchesMixin,
        AArch64OperandMixin,
        AArch64DiftPatchesMixin,
        AArch64GadgetPatchesMixin,
        AArch64CheckpointPatchesMixin,
        AArch64ControlFlowPatchesMixin,
        AArch64ShadowStackMixin,
        Architecture):
    MAGIC_WORDS = (0xd280229f, 0xd280a29f)
    CHECKPOINT_TARGET_SCRATCH_REG_ADDR = 24
    INVERSE_CONDITIONS = {
        "eq": "ne",
        "ne": "eq",
        "cs": "cc",
        "hs": "lo",
        "cc": "cs",
        "lo": "hs",
        "mi": "pl",
        "pl": "mi",
        "vs": "vc",
        "vc": "vs",
        "hi": "ls",
        "ls": "hi",
        "ge": "lt",
        "lt": "ge",
        "gt": "le",
        "le": "gt",
    }

    def __init__(self):
        marker_bytes = b"".join(word.to_bytes(4, "little") for word in self.MAGIC_WORDS)
        super().__init__("aarch64", True, marker_bytes, _ARM64_ELF())

    def normalize_passes(self, decoder):
        from teapot.passes.preprocessing.normalize_aarch64_relocations_pass import (
            NormalizeAArch64RelocationsPass,
        )
        from teapot.passes.preprocessing.normalize_aarch64_startup_pass import (
            NormalizeAArch64StartupPass,
        )

        passes = [NormalizeAArch64RelocationsPass(decoder)]
        if self.needs_startup_normalization():
            passes.append(NormalizeAArch64StartupPass(decoder))
        return passes

    def relax_conditional_branches(self, module) -> None:
        from gtirb_capstone.instructions import GtirbInstructionDecoder
        from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder

        from teapot.passes.common.aarch64_relax_conditional_branches_pass import (
            AArch64RelaxConditionalBranchesPass,
        )

        if not self.needs_conditional_branch_relax():
            return
        print("[teapot] begin aarch64-relax", flush=True)
        AArch64RelaxConditionalBranchesPass(GtirbInstructionDecoder(module.isa)).begin_module(
            module, [], None)
        CachedGtirbInstructionDecoder.cache.clear()
        print("[teapot] end aarch64-relax", flush=True)

    def create_text_dift_pass(self, reg_manager, section, decoder, dift_layout):
        from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
        return AArch64TextDiftPropagationLLVMPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout)

    def create_transient_dift_pass(self, reg_manager, section, decoder, dift_layout):
        from teapot.passes.common.dift.aarch64 import AArch64DiftPropagationPass
        return AArch64DiftPropagationPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout, insert_memlog=True)

    def create_transient_memlog_pass(self, reg_manager, section, decoder):
        from teapot.passes.transient.memlog.aarch64 import AArch64TransientMemlogPass
        return AArch64TransientMemlogPass(reg_manager, section, decoder, self)

    def create_transient_mem_operand_policy_pass(self, reg_manager, section, decoder, *,
                                                 dift_layout, enable_asan_check: bool):
        from teapot.passes.transient.gadget_policy.mem_operand.aarch64 import (
            AArch64TransientMemOperandPoliciesPass,
        )
        return AArch64TransientMemOperandPoliciesPass(
            reg_manager, section, decoder, self,
            dift_layout=dift_layout, enable_asan_check=enable_asan_check)

    def create_transient_port_contention_policy_pass(self, reg_manager, section, decoder, *,
                                                     dift_layout):
        from teapot.passes.transient.gadget_policy.port_contention.aarch64 import (
            AArch64TransientPortContentionPolicyPass,
        )
        return AArch64TransientPortContentionPolicyPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout)
