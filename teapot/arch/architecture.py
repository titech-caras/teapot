from abc import ABC
from dataclasses import dataclass
from typing import Any

import gtirb
from gtirb_rewriting import patch_constraints

from teapot.arch.interfaces import (
    ArchitectureAsanMixin,
    ArchitectureCheckpointMixin,
    ArchitectureControlFlowMixin,
    ArchitectureDiftMixin,
    ArchitectureGadgetMixin,
    ArchitectureMemlogMixin,
    ArchitectureOperandMixin,
    ArchitectureRegisterMixin,
    ArchitectureRuntimeMixin,
)


@dataclass(frozen=True)
class Architecture(
        ArchitectureRuntimeMixin,
        ArchitectureRegisterMixin,
        ArchitectureCheckpointMixin,
        ArchitectureControlFlowMixin,
        ArchitectureDiftMixin,
        ArchitectureOperandMixin,
        ArchitectureGadgetMixin,
        ArchitectureMemlogMixin,
        ArchitectureAsanMixin,
        ABC):
    name: str
    uses_live_registers: bool
    nop_bytes: bytes
    abi: Any

    def constraints(self, **kwargs):
        return patch_constraints(**kwargs)

    def normalize_passes(self, decoder):
        return []

    def preprocess_passes(self, *, text_section, transient_section,
                          text_transient_mapping, landing_pad_targets,
                          decoder):
        return []

    def late_text_checkpoint_passes(self, *, text_section, transient_section,
                                    text_transient_mapping, landing_pad_targets,
                                    decoder):
        return []

    def relax_late_branches(self, *, module, text_section, transient_section,
                            text_transient_mapping, landing_pad_targets,
                            run_pass_manager):
        """Finish architecture-specific branch relaxation after late layout."""
        return ()

    def relax_conditional_branches(self, module: gtirb.Module) -> None:
        return None

    def create_text_dift_pass(self, reg_manager, section, decoder, dift_layout):
        raise NotImplementedError(f"{self.name} does not define text DIFT pass")

    def create_transient_dift_pass(self, reg_manager, section, decoder, dift_layout):
        raise NotImplementedError(f"{self.name} does not define transient DIFT pass")

    def create_transient_memlog_pass(self, reg_manager, section, decoder):
        raise NotImplementedError(f"{self.name} does not define transient memlog pass")

    def create_transient_mem_operand_policy_pass(self, reg_manager, section, decoder, *,
                                                 dift_layout, enable_asan_check: bool,
                                                 asan_tag_storage: str = "shadow"):
        raise NotImplementedError(f"{self.name} does not define transient memory-operand policy pass")

    def create_transient_port_contention_policy_pass(self, reg_manager, section, decoder, *,
                                                     dift_layout):
        raise NotImplementedError(f"{self.name} does not define transient port-contention policy pass")
