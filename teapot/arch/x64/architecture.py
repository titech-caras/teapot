from gtirb_rewriting import patch_constraints
from gtirb_rewriting import PassManager
from gtirb_rewriting.assembly import X86Syntax

from teapot.arch.architecture import Architecture
from teapot.arch.x64.abi import _X86_64_ELF
from teapot.arch.x64.asan import X64AsanPatchesMixin
from teapot.arch.x64.checkpoint import X64CheckpointPatchesMixin
from teapot.arch.x64.control_flow import X64ControlFlowPatchesMixin
from teapot.arch.x64.dift import X64DiftPatchesMixin
from teapot.arch.x64.gadget import X64GadgetPatchesMixin
from teapot.arch.x64.memlog import X64MemlogPatchesMixin
from teapot.arch.x64.operands import X64OperandMixin
from teapot.arch.x64.registers import X64RegisterMixin
from teapot.arch.x64.runtime import X64RuntimeMixin


class X64Architecture(
        X64RuntimeMixin,
        X64RegisterMixin,
        X64AsanPatchesMixin,
        X64MemlogPatchesMixin,
        X64OperandMixin,
        X64DiftPatchesMixin,
        X64GadgetPatchesMixin,
        X64CheckpointPatchesMixin,
        X64ControlFlowPatchesMixin,
        Architecture):
    MAGIC_WORDS = (0x90db8748, 0x90d28748)

    def __init__(self):
        marker_bytes = b"".join(word.to_bytes(4, "little") for word in self.MAGIC_WORDS)
        super().__init__("x64", True, marker_bytes, _X86_64_ELF())

    def constraints(self, **kwargs):
        return patch_constraints(x86_syntax=X86Syntax.INTEL, **kwargs)

    def return_address_is_stack_resident(self) -> bool:
        return True

    def relax_conditional_branches(self, module) -> None:
        from gtirb_capstone.instructions import GtirbInstructionDecoder
        from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder

        from teapot.passes.common.x64_relax_jcxz_pass import X64RelaxJcxzPass

        if not self.needs_conditional_branch_relax():
            return
        print("[teapot] begin x64-relax", flush=True)
        pass_manager = PassManager()
        pass_manager.add(X64RelaxJcxzPass(
            GtirbInstructionDecoder(module.isa), self))
        pass_manager.run(module.ir)
        CachedGtirbInstructionDecoder.cache.clear()
        print("[teapot] end x64-relax", flush=True)

    def create_text_dift_pass(self, reg_manager, section, decoder, dift_layout):
        from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
        return X64TextDiftPropagationLLVMPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout)

    def create_transient_dift_pass(self, reg_manager, section, decoder, dift_layout):
        from teapot.passes.common.dift.x64 import X64DiftPropagationPass
        return X64DiftPropagationPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout, insert_memlog=True)

    def create_transient_memlog_pass(self, reg_manager, section, decoder):
        from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass
        return X64TransientMemlogPass(reg_manager, section, decoder, self)

    def create_transient_mem_operand_policy_pass(self, reg_manager, section, decoder, *,
                                                 dift_layout, enable_asan_check: bool,
                                                 asan_tag_storage: str = "shadow"):
        from teapot.passes.transient.gadget_policy.mem_operand.x64 import (
            X64TransientMemOperandPoliciesPass,
        )
        return X64TransientMemOperandPoliciesPass(
            reg_manager, section, decoder, self,
            dift_layout=dift_layout, enable_asan_check=enable_asan_check)

    def create_transient_port_contention_policy_pass(self, reg_manager, section, decoder, *,
                                                     dift_layout):
        from teapot.passes.transient.gadget_policy.port_contention.x64 import (
            X64TransientPortContentionPolicyPass,
        )
        return X64TransientPortContentionPolicyPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout)
