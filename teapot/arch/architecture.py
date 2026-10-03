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
    nop_bytes: bytes
    abi: Any
    # The aarch64-bti-pac mode's Architecture checks speculative targets by
    # BTI landings (teapot/arch/aarch64/bti.py).
    uses_bti_landing_checks = False

    def __post_init__(self):
        # Local label numbers, per instance: the pipeline builds one
        # Architecture per rewrite, so one module's labels do not depend on
        # what the process rewrote before it.
        object.__setattr__(self, "_label_numbers", {})

    def next_label_number(self, kind: str) -> int:
        number = self._label_numbers.get(kind, 0)
        self._label_numbers[kind] = number + 1
        return number

    def return_address_is_stack_resident(self) -> bool:
        """Whether a call stores its return address in application memory."""
        return False

    def constraints(self, **kwargs):
        return patch_constraints(**kwargs)

    def normalize_passes(self, decoder, reg_manager):
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

    def unsupported_instructions(self, section: gtirb.Section, decoder) -> list:
        """Input instructions this ISA's rewrite cannot handle, as "mnemonic at address" strings."""
        return []

    def relax_conditional_branches(self, module: gtirb.Module, *, direct_pads) -> None:
        """Relax out-of-range branches; ``direct_pads`` maps each direct-entry label to its pad."""
        return None

    def create_text_dift_pass(self, reg_manager, section, decoder, dift_layout):
        raise NotImplementedError(f"{self.name} does not define text DIFT pass")

    def transient_instruction_passes(self, reg_manager, section, decoder, dift_layout, options):
        return []

    def create_transient_dift_pass(self, reg_manager, section, decoder, dift_layout, *, insert_memlog=True):
        from teapot.passes.transient.lazy_dift import transient_replay_pass
        return transient_replay_pass(
            self, reg_manager, section, decoder, dift_layout=dift_layout,
            insert_memlog=insert_memlog)

    def create_transient_memlog_pass(self, reg_manager, section, decoder):
        raise NotImplementedError(f"{self.name} does not define transient memlog pass")

    def create_transient_mem_operand_policy_pass(self, reg_manager, section, decoder, *,
                                                 dift_layout, enable_asan_check: bool,
                                                 asan_tag_storage: str = "shadow"):
        raise NotImplementedError(f"{self.name} does not define transient memory-operand policy pass")

    def create_transient_port_contention_policy_pass(self, reg_manager, section, decoder, *,
                                                     dift_layout):
        raise NotImplementedError(f"{self.name} does not define transient port-contention policy pass")
