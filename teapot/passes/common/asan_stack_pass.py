from collections import Counter
import warnings

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import Patch, RewritingContext

from teapot.arch.architecture import Architecture
from teapot.configs.runtime import ASAN_TAG_STORAGE_SHADOW
from teapot.configs.blacklist import function_symbol_names, is_blacklisted_function
from teapot.datacls.dift_layout import get_dift_layout
from teapot.passes.mixins import RegInstAwarePassMixin, VisitorPassMixin
from teapot.utils.misc import distinguish_edges
from teapot.passes.common.return_slot_analysis import ReturnSlotAnalysis, UnsupportedReturnSlot


class AsanStackPass(VisitorPassMixin, RegInstAwarePassMixin):
    section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager,
                 section: gtirb.Section, decoder: GtirbInstructionDecoder, arch: Architecture,
                 insert_memlog: bool, *, dift_layout=None, tag_storage: str = ASAN_TAG_STORAGE_SHADOW):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.section = section
        self.arch = arch
        self.insert_memlog = insert_memlog
        self.dift_layout = dift_layout or get_dift_layout(arch.name)
        self.tag_storage = tag_storage
        self.coverage = Counter()
        self.unsupported_reasons = Counter()

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        self.visit_functions(functions, self.section)

    def visit_function(self, function: Function):
        if any(name == "main" for name in function_symbol_names(function)) or is_blacklisted_function(function):
            return

        if not self.arch.return_address_is_stack_resident():
            if self.tag_storage != ASAN_TAG_STORAGE_SHADOW:
                self.coverage["MTE omitted"] += 1
                return
            try:
                # Checkpoint/trampoline transfers enter a copied instruction
                # with its original frame state, not a fresh ABI entry frame.
                checkpoint_sources = {section for section in self.module.sections
                                      if self.insert_memlog and section.name in {".text", ".teapot_trampolines"}}
                sites = ReturnSlotAnalysis(self.arch, self.decoder).analyze(
                    function, checkpoint_sources=checkpoint_sources)
            except UnsupportedReturnSlot as error:
                self.coverage["unsupported"] += 1
                self.unsupported_reasons[str(error)] += 1
                warnings.warn(f"Saved-return poisoning omitted for {function.get_name()}: {error}",
                              RuntimeWarning)
                return
            if not sites:
                self.coverage["no saved slot"] += 1
                return
            self.reg_manager.analyze(function)
            for site in sites:
                self.reg_manager.add_live_registers(function, site.block, site.instruction_index, {site.base})
                patch = self.arch.asan_stack_patch(
                    self.reg_manager.abi, poison=site.poison,
                    insert_memlog=self.insert_memlog,
                    shadow_offset=self.dift_layout.asan_shadow_offset,
                    tag_storage=self.tag_storage, slot=(site.base, site.displacement))
                patch = self.allocate_registers(function, site.block, site.instruction_index)(patch)
                instructions = tuple(self.decoder.get_instructions(site.block))
                offset = sum(inst.size for inst in instructions[:site.instruction_index])
                self.insert_at(site.block, offset, Patch.from_function(patch))
            self.coverage["instrumented"] += 1
            return

        self.reg_manager.analyze(function)
        for block in function.get_entry_blocks():
            patch = self.arch.asan_stack_patch(
                self.reg_manager.abi, poison=True,
                insert_memlog=self.insert_memlog,
                shadow_offset=self.dift_layout.asan_shadow_offset,
                tag_storage=self.tag_storage)
            patch = self.allocate_registers(function, block, 0)(patch)
            self.insert_at(block, 0, Patch.from_function(patch))

        for block in function.get_exit_blocks():
            non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                continue

            instructions = list(self.decoder.get_instructions(block))
            patch = self.arch.asan_stack_patch(
                self.reg_manager.abi, poison=False,
                insert_memlog=self.insert_memlog,
                shadow_offset=self.dift_layout.asan_shadow_offset,
                tag_storage=self.tag_storage)
            patch = self.allocate_registers(function, block, len(instructions) - 1)(patch)
            self.insert_at(block, sum(inst.size for inst in instructions[:-1]), Patch.from_function(patch))

    def end_module(self, module, functions):
        if not self.arch.return_address_is_stack_resident():
            counts = ", ".join(f"{key}={value}" for key, value in sorted(self.coverage.items()))
            print(f"[teapot] saved-return poisoning {self.section.name}: {counts}", flush=True)
            if self.unsupported_reasons:
                reasons = "; ".join(f"{reason}={count}"
                                    for reason, count in sorted(self.unsupported_reasons.items()))
                print(f"[teapot] saved-return omissions {self.section.name}: {reasons}", flush=True)
        super().end_module(module, functions)
