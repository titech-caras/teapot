from teapot.arch.architecture import Architecture
from teapot.arch.riscv64.abi import _RISCV64_ELF
from teapot.arch.riscv64.assembly import RISCV64AssemblyMixin
from teapot.arch.riscv64.asan import RISCV64AsanPatchesMixin
from teapot.arch.riscv64.checkpoint import RISCV64CheckpointPatchesMixin
from teapot.arch.riscv64.control_flow import RISCV64ControlFlowPatchesMixin
from teapot.arch.riscv64.dift import RISCV64DiftPatchesMixin
from teapot.arch.riscv64.gadget import RISCV64GadgetPatchesMixin
from teapot.arch.riscv64.landing_pads import RISCV64LandingPadPatchesMixin
from teapot.arch.riscv64.memlog import RISCV64MemlogPatchesMixin
from teapot.arch.riscv64.operands import RISCV64OperandMixin
from teapot.arch.riscv64.registers import RISCV64RegisterMixin
from teapot.arch.riscv64.runtime import RISCV64RuntimeMixin
from teapot.arch.riscv64.spill import RISCV64FirstSpillMixin


class RISCV64Architecture(
        RISCV64RuntimeMixin,
        RISCV64AssemblyMixin,
        RISCV64RegisterMixin,
        RISCV64AsanPatchesMixin,
        RISCV64MemlogPatchesMixin,
        RISCV64OperandMixin,
        RISCV64DiftPatchesMixin,
        RISCV64GadgetPatchesMixin,
        RISCV64LandingPadPatchesMixin,
        RISCV64CheckpointPatchesMixin,
        RISCV64ControlFlowPatchesMixin,
        RISCV64FirstSpillMixin,
        Architecture):
    MAGIC_WORDS = (0x11400013, 0x51400013)
    CHECKPOINT_TARGET_SCRATCH_REG_ADDR = 24

    def __init__(self):
        marker_bytes = b"".join(word.to_bytes(4, "little") for word in self.MAGIC_WORDS)
        super().__init__("riscv64", True, marker_bytes, _RISCV64_ELF())

    def preprocess_passes(self, *, text_section, transient_section,
                          text_transient_mapping, landing_pad_targets,
                          decoder):
        from teapot.passes.preprocessing.riscv64_landing_pads_pass import RISCV64LandingPadsPass
        return [
            RISCV64LandingPadsPass(
                text_section,
                transient_section,
                text_transient_mapping,
                self,
                landing_pad_targets,
                insert_code=False,
                decoder=decoder)
        ]

    def late_text_checkpoint_passes(self, *, text_section, transient_section,
                                    text_transient_mapping, landing_pad_targets,
                                    decoder):
        from teapot.passes.preprocessing.riscv64_landing_pads_pass import RISCV64LandingPadsPass
        return [
            RISCV64LandingPadsPass(
                text_section,
                transient_section,
                text_transient_mapping,
                self,
                landing_pad_targets,
                decoder=decoder)
        ]

    def create_text_dift_pass(self, reg_manager, section, decoder, dift_layout):
        from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass
        return RISCV64TextDiftPropagationLLVMPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout)

    def create_transient_dift_pass(self, reg_manager, section, decoder, dift_layout):
        from teapot.passes.common.dift.riscv64 import RISCV64DiftPropagationPass
        return RISCV64DiftPropagationPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout, insert_memlog=True)

    def create_transient_memlog_pass(self, reg_manager, section, decoder):
        from teapot.passes.transient.memlog.riscv64 import RISCV64TransientMemlogPass
        return RISCV64TransientMemlogPass(reg_manager, section, decoder, self)

    def create_transient_mem_operand_policy_pass(self, reg_manager, section, decoder, *,
                                                 dift_layout, enable_asan_check: bool,
                                                 asan_tag_storage: str = "shadow"):
        from teapot.passes.transient.gadget_policy.mem_operand.riscv64 import (
            RISCV64TransientMemOperandPoliciesPass,
        )
        return RISCV64TransientMemOperandPoliciesPass(
            reg_manager, section, decoder, self,
            dift_layout=dift_layout, enable_asan_check=enable_asan_check)

    def create_transient_port_contention_policy_pass(self, reg_manager, section, decoder, *,
                                                     dift_layout):
        from teapot.passes.transient.gadget_policy.port_contention.riscv64 import (
            RISCV64TransientPortContentionPolicyPass,
        )
        return RISCV64TransientPortContentionPolicyPass(
            reg_manager, section, decoder, self, dift_layout=dift_layout)
