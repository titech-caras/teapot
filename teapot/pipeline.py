import gc
from dataclasses import dataclass, replace
from typing import Optional

import gtirb
from gtirb_rewriting.decoder import GtirbInstructionDecoder
from gtirb_live_register_analysis import (
    LIVE_REGISTER_NAMES_AUXDATA,
    LIVE_REGISTER_SETS_AUXDATA,
    LiveRegisterManager,
)
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import PassManager
from gtirb_rewriting.abi import _ABIS

from teapot.arch import get_arch
from teapot.configs.runtime import ASAN_TAG_STORAGE_MTE, ASAN_TAG_STORAGE_SHADOW
from teapot.datacls.dift_layout import get_dift_layout
from teapot.passes.common.asan_stack_pass import AsanStackPass
from teapot.passes.common.insert_checkpoints_pass import InsertCheckpointsPass
from teapot.passes.preprocessing.create_trampolines_pass import CreateTrampolinesPass
from teapot.passes.preprocessing.dift_ext_call_pass import DiftExtCallPass
from teapot.passes.preprocessing.import_symbols_pass import ImportSymbolsPass
from teapot.passes.preprocessing.normalize_data_block_alignment_pass import (
    NormalizeDataBlockAlignmentPass,
)
from teapot.passes.text.text_indirect_branch_transform_pass import TextIndirectBranchTransformPass
from teapot.passes.text.text_initialize_library_pass import TextInitializeLibraryPass
from teapot.passes.text.text_skipped_transform_restore_pass import TextSkippedTransformRestorePass
from teapot.passes.transient.indirect_branch_check_pass import TransientIndirectBranchCheckDestPass
from teapot.passes.transient.transient_coverage import TransientCoveragePass
from teapot.passes.transient.transient_insert_restore_points_pass import TransientInsertRestorePointsPass
from teapot.preprocess.copy_section import (
    SHF_ALLOC,
    SHF_WRITE,
    SHT_PROGBITS,
    copy_elf_section_properties,
    copy_section,
    create_section_bounds,
    set_elf_section_properties,
)
from teapot.preprocess.create_guards import create_guards

ARCH_INFO_AUX_TYPE = "mapping<string,string>"
AARCH64_MTE_ARCH_FEATURE = "mte"

_TLS_SYMBOL_ATTRIBUTES = {
    gtirb.SymbolicExpression.Attribute.TLS,
    gtirb.SymbolicExpression.Attribute.TLSGD,
    gtirb.SymbolicExpression.Attribute.TLSLD,
    gtirb.SymbolicExpression.Attribute.TLSLDM,
    gtirb.SymbolicExpression.Attribute.TLSCALL,
    gtirb.SymbolicExpression.Attribute.TLSDESC,
    gtirb.SymbolicExpression.Attribute.TPREL,
    gtirb.SymbolicExpression.Attribute.TPOFF,
    gtirb.SymbolicExpression.Attribute.DTPREL,
    gtirb.SymbolicExpression.Attribute.DTPOFF,
    gtirb.SymbolicExpression.Attribute.DTPMOD,
    gtirb.SymbolicExpression.Attribute.NTPOFF,
    gtirb.SymbolicExpression.Attribute.GOTNTPOFF,
    gtirb.SymbolicExpression.Attribute.INDNTPOFF,
    gtirb.SymbolicExpression.Attribute.TLSLDO,
}


def _integral_tls_symbol_values(module: gtirb.Module):
    """Capture integral TLS symbols that layout must not turn into labels."""
    symbols = {}
    for byte_interval in module.byte_intervals:
        for expression in byte_interval.symbolic_expressions.values():
            if not expression.attributes.intersection(_TLS_SYMBOL_ATTRIBUTES):
                continue
            for symbol in expression.symbols:
                if symbol.value is not None:
                    symbols[symbol] = symbol.value
    return tuple(symbols.items())


def _restore_integral_symbol_values(symbol_values):
    # gtirb-layout assigns integral symbols to blocks when their numeric value
    # happens to fall in a laid-out interval.  That is invalid for TLS offsets:
    # their value is relative to the thread pointer, not a module address.
    for symbol, value in symbol_values:
        symbol.value = value


def _add_arch_feature(module: gtirb.Module, feature: str):
    aux_data = module.aux_data.get("archInfo")
    if aux_data is None:
        aux_data = gtirb.AuxData({}, ARCH_INFO_AUX_TYPE)
        module.aux_data["archInfo"] = aux_data

    features = set(aux_data.data.get("features", "").replace(",", " ").split())
    features.add(feature)
    aux_data.data["features"] = " ".join(sorted(features))


@dataclass(frozen=True)
class InstrumentationOptions:
    enable_dift: bool = True
    eager_transient_dift: bool = False
    enable_asan: bool = True
    enable_gadgets: bool = True
    enable_memlog: bool = True
    enable_checkpoints: bool = True
    enable_nested_speculation: bool = False
    enable_indirect_transform: bool = True
    enable_indirect_check: bool = True
    enable_conditional_branch_relax: bool = True
    enable_mem_operand_gadgets: bool = True
    enable_port_gadgets: bool = True
    enable_gadget_asan_check: bool = True
    aarch64_tag_storage: str = ASAN_TAG_STORAGE_SHADOW
    target_identification: str = "software"
    debug_source: Optional[str] = None
    conservative_flags: bool = False
    force_checkpoint_df: bool = False
    x64_vector_state: str = 'auto'
    debug_vector_liveness: bool = False


class TeapotPipeline:
    linked_component = None
    component_guard_base = None
    checkpoint_df_blocks = frozenset()
    checkpoint_vector_cases = None
    vector_state = None

    def __init__(self, ir: gtirb.IR, dift_layout_name=None,
                 options: InstrumentationOptions = InstrumentationOptions(), *,
                 linked_component=None):
        self.ir = ir
        self.dift_layout_name = dift_layout_name
        self.options = options
        self.linked_component = linked_component
        self.reg_manager = None

    def run(self):
        if self.options.debug_source is not None and len(self.ir.modules) != 1:
            raise ValueError("source-line preservation requires one ELF module")
        self.module = self.ir.modules[0]
        self.arch = get_arch(self.module)
        if self.options.target_identification != "software":
            if self.options.target_identification != "aarch64-bti" or self.arch.name != "aarch64":
                raise ValueError("the experimental BTI backend requires AArch64")
            if not all((self.options.enable_indirect_transform, self.options.enable_indirect_check,
                        self.options.enable_checkpoints)):
                raise ValueError("BTI requires target transformation, checking and checkpoints")
            from teapot.arch.aarch64.bti import AArch64BTIArchitecture
            self.arch = AArch64BTIArchitecture()
        if self.linked_component is not None:
            if len(self.ir.modules) != 1 or self.arch.name not in ("x64", "aarch64", "riscv64"):
                raise ValueError("separate component rewriting requires one supported ELF64 module")
            # AArch64 MTE tag storage changes only how ASan tags are stored;
            # every pass stays enabled and nesting stays off.
            if replace(self.options, aarch64_tag_storage=ASAN_TAG_STORAGE_SHADOW) != InstrumentationOptions():
                raise ValueError("component prototype requires all default instrumentation, nesting off")
        if self.options.aarch64_tag_storage == ASAN_TAG_STORAGE_MTE and self.arch.name != "aarch64":
            raise ValueError("--aarch64-tag-storage=mte is only valid for AArch64 modules")
        if self.options.aarch64_tag_storage == ASAN_TAG_STORAGE_MTE:
            _add_arch_feature(self.module, AARCH64_MTE_ARCH_FEATURE)
        self.dift_layout = get_dift_layout(self.arch.name, self.dift_layout_name)
        self.text_section = [section for section in self.module.sections if section.name == ".text"][0]
        self.decoder = CachedGtirbInstructionDecoder(self.module.isa)
        self.abi = self.arch.register_abi(_ABIS)
        self.checkpoint_df_blocks, self.vector_state = set(), None
        if self.arch.name == 'x64':
            from teapot.arch.x64.checkpoint_state import df_checkpoint_blocks, vector_state
            self.checkpoint_df_blocks = df_checkpoint_blocks(self.module, self.decoder, self.abi)
            self.vector_state = vector_state(self.options.x64_vector_state)
            print(f'[teapot] x64 vector state: {self.vector_state}; '
                  f'DF-sensitive blocks: {len(self.checkpoint_df_blocks)}', flush=True)
        self.reg_manager = LiveRegisterManager(
            self.module, self.abi, self.decoder, analysis_scope="block",
            conservative_flags=self.options.conservative_flags)
        if self.arch.name == 'x64':
            from teapot.arch.x64.checkpoint_state import vector_checkpoint_cases
            self.checkpoint_vector_cases = vector_checkpoint_cases(
                self.module, self.reg_manager, self.options.x64_vector_state,
                debug_cross_check=self.options.debug_vector_liveness)
        print(f"[teapot] live-register analysis: {self.reg_manager.analysis_source}", flush=True)
        if self.reg_manager.analysis_source == "python":
            # Invalid tables must not enter the rewriter's offset hooks.
            self.module.aux_data.pop(LIVE_REGISTER_NAMES_AUXDATA, None)
            self.module.aux_data.pop(LIVE_REGISTER_SETS_AUXDATA, None)
            self.module.aux_data.pop('liveRegisterSetsHigh', None)
        if self.linked_component is not None:
            if self.reg_manager.analysis_source != "ddisasm":
                raise ValueError("component prototype requires validated DDisasm liveness metadata")
            # A standalone ELF is analyzed at ABI boundaries. Preserve its
            # masks, including genuinely live arguments/results; do not
            # replace them with the liveness of a particular linked caller
            # or force every register live. Missing masks remain all-live
            # in LiveRegisterManager, as for ordinary instrumentation.
            print("[teapot] component liveness: standalone DDisasm ABI masks; "
                  "missing masks remain all-live", flush=True)

        source_lines = None
        if self.options.debug_source is not None:
            # No imports, metadata or extra rewrite rounds on the default path.
            from teapot.debug_lines import SourceLines
            source_lines = SourceLines(self.module, self.options.debug_source,
                                       self.arch.name, self.decoder)

        self._run_normalize_passes()
        self._create_instrumentation_sections()
        self.checkpoint_df_blocks |= {
            self.text_transient_mapping.code_blocks_map[uuid].uuid
            for uuid in tuple(self.checkpoint_df_blocks)
            if uuid in self.text_transient_mapping.code_blocks_map}
        if self.checkpoint_vector_cases is not None:
            self.checkpoint_vector_cases.update({
                self.text_transient_mapping.code_blocks_map[uuid].uuid: case
                for uuid, case in tuple(self.checkpoint_vector_cases.items())
                if uuid in self.text_transient_mapping.code_blocks_map})
        self._run_preprocess_passes()
        self._run_dift_ext_call_passes()

        if self.arch.run_text_passes_before_transient():
            self._run_text_passes()

        self._run_transient_passes()

        if not self.arch.run_text_passes_before_transient():
            self._run_text_passes()

        if self.options.enable_conditional_branch_relax and self.arch.needs_conditional_branch_relax():
            integral_tls_symbols = _integral_tls_symbol_values(self.module)
            try:
                self.arch.relax_conditional_branches(self.module)
            finally:
                _restore_integral_symbol_values(integral_tls_symbols)
                self._refresh_register_analysis()

        if self.arch.needs_late_text_checkpoints():
            self._run_late_text_checkpoint_passes()
        if self.options.target_identification == "aarch64-bti":
            self.arch.finalize_bti_layout(self)
        if source_lines is not None:
            source_lines.finish(GtirbInstructionDecoder(self.module.isa))

    def _run_pass_manager(self, pass_manager: PassManager, label: str):
        print(f"[teapot] begin {label}", flush=True)
        integral_tls_symbols = _integral_tls_symbol_values(self.module)
        try:
            pass_manager.run(self.ir)
        finally:
            _restore_integral_symbol_values(integral_tls_symbols)
            self._refresh_register_analysis()
        gc.collect()
        print(f"[teapot] end {label}", flush=True)

    def _refresh_register_analysis(self):
        if self.reg_manager is None:
            CachedGtirbInstructionDecoder.cache.clear()
            return
        previous_source = self.reg_manager.analysis_source
        # These rounds preserve application register dependencies: inserted
        # patches save their clobbers and replacements retain original effects.
        # A transformation changing those effects must invalidate, not opt in.
        self.reg_manager.refresh(preserve_liveness=True)
        source = self.reg_manager.analysis_source
        if source != previous_source:
            print(f"[teapot] live-register analysis: {previous_source} -> {source}", flush=True)
        if source == "python":
            self.module.aux_data.pop(LIVE_REGISTER_NAMES_AUXDATA, None)
            self.module.aux_data.pop(LIVE_REGISTER_SETS_AUXDATA, None)
            self.module.aux_data.pop('liveRegisterSetsHigh', None)

    def _run_normalize_passes(self):
        pass_manager = PassManager()
        pass_manager.add(NormalizeDataBlockAlignmentPass())
        for arch_pass in self.arch.normalize_passes(self.decoder, self.reg_manager):
            pass_manager.add(arch_pass)
        self._run_pass_manager(pass_manager, "normalize")

    def _create_instrumentation_sections(self):
        self.transient_section, self.transient_section_start_symbol, self.transient_section_end_symbol, \
            self.text_transient_mapping = copy_section(self.text_section, ".teapot_transient", self.decoder)
        self.text_section_start_symbol, self.text_section_end_symbol = create_section_bounds(
            self.text_section, "text")
        self.component_guard_base = None
        if self.linked_component is not None:
            (self.text_section_start_symbol, self.text_section_end_symbol,
             self.transient_section_start_symbol, self.transient_section_end_symbol) = \
                self.linked_component.bounds(self.module)
            self.component_guard_base = self.linked_component.external_symbol(
                self.module, self.linked_component.guard_base_name)

        self._refresh_register_analysis()

        self.trampoline_section = gtirb.Section(
            name=".teapot_trampolines", flags=self.transient_section.flags, module=self.module)
        copy_elf_section_properties(self.transient_section, self.trampoline_section)
        gtirb.ByteInterval(section=self.trampoline_section)

        writable_section_flags = {
            gtirb.Section.Flag.Readable,
            gtirb.Section.Flag.Writable,
            gtirb.Section.Flag.Loaded,
            gtirb.Section.Flag.Initialized,
        }
        self.guard_section = gtirb.Section(
            name=".teapot_guards", flags=writable_section_flags, module=self.module)
        set_elf_section_properties(self.guard_section, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE)
        gtirb.ByteInterval(section=self.guard_section)

        self.branch_counter_section = gtirb.Section(
            name=".teapot_branch_counters", flags=writable_section_flags, module=self.module)
        set_elf_section_properties(self.branch_counter_section, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE)
        gtirb.ByteInterval(section=self.branch_counter_section)

        self.landing_pad_targets = set()
        self.checkpoint_spare_registers = {}

    def _run_preprocess_passes(self):
        pass_manager = PassManager()
        pass_manager.add(ImportSymbolsPass(self.arch.checkpoint_lib_symbols()))
        trampolines = CreateTrampolinesPass(
            self.text_section,
            self.trampoline_section,
            self.branch_counter_section,
            self.text_transient_mapping,
            self.decoder,
            self.arch,
            self.reg_manager,
            self.landing_pad_targets,
            self.checkpoint_spare_registers)
        pass_manager.add(trampolines)
        for arch_pass in self.arch.preprocess_passes(
                text_section=self.text_section,
                transient_section=self.transient_section,
                text_transient_mapping=self.text_transient_mapping,
                landing_pad_targets=self.landing_pad_targets,
                decoder=self.decoder):
            pass_manager.add(arch_pass)
        self._run_pass_manager(pass_manager, "preprocess")
        # Only generated trampolines may be checkpoint destinations. In
        # particular, conditionals leaving the copied region were omitted.
        self.checkpoint_block_uuids = set(trampolines.processed_blocks)
        if self.checkpoint_vector_cases is not None:
            from collections import Counter
            counts = Counter(self.checkpoint_vector_cases.get(u, 2)
                             for u in self.checkpoint_block_uuids)
            print(f'[teapot] x64 checkpoint sites: integer={counts[0]} '
                  f'xmm0-7={counts[1]} full={counts[2]}', flush=True)
            if self.options.x64_vector_state == 'auto':
                reasons = getattr(self.reg_manager, 'checkpoint_vector_reasons', {})
                full_reasons = Counter(reasons.get(u, 'new-or-missing-mask')
                                       for u in self.checkpoint_block_uuids
                                       if self.checkpoint_vector_cases.get(u, 2) == 2)
                print(f'[teapot] full vector-save reasons: {dict(full_reasons)}', flush=True)

    def _run_dift_ext_call_passes(self):
        pass_manager = PassManager()
        pass_manager.add(DiftExtCallPass(
            self.text_section, self.decoder,
            wrap_dift_calls=self.options.enable_dift))
        self._run_pass_manager(pass_manager, "dift-ext-calls")

    def _run_text_passes(self):
        pass_manager = PassManager()
        target_transform = None
        if self.options.enable_indirect_transform:
            target_transform = TextIndirectBranchTransformPass(
                self.text_section,
                self.text_transient_mapping,
                self.decoder,
                self.arch,
                self.reg_manager,
                self.landing_pad_targets,
                required_target_symbols=(self.linked_component.exported_function_symbols
                                         if self.linked_component else ()))
        if target_transform is not None:
            # Every legal normal target address must start with the full
            # marker, not just a separately rewritten component's exports.
            # Register this before all other entry effects in the SAME round:
            # an active indirect call redirects before normal stack poisoning
            # or runtime initialization, without instrumenting the bouncer.
            pass_manager.add(target_transform)
        pass_manager.add(TextInitializeLibraryPass(self.text_section, self.decoder, self.arch,
                                                   self.vector_state))
        if self.options.enable_asan:
            pass_manager.add(AsanStackPass(
                self.reg_manager, self.text_section, self.decoder, self.arch, False,
                dift_layout=self.dift_layout, tag_storage=self.options.aarch64_tag_storage))
        if self.options.enable_indirect_transform:
            if self.options.enable_checkpoints:
                pass_manager.add(TextSkippedTransformRestorePass(
                    self.text_section, self.arch))
        if self.options.enable_dift:
            pass_manager.add(self.arch.create_text_dift_pass(
                self.reg_manager, self.text_section, self.decoder, self.dift_layout))
        # Register checkpoints while offsets still identify application branches: once RISC-V
        # target guards split blocks, an original UUID can belong to a guard's checkpoint_cnt
        # branch inside its first-spill lifetime.
        if self.options.enable_checkpoints:
            pass_manager.add(InsertCheckpointsPass(
                self.reg_manager, self.text_section, self.decoder, self.arch,
                self.checkpoint_block_uuids, self.checkpoint_spare_registers,
                self.checkpoint_df_blocks, self.options.force_checkpoint_df,
                self.checkpoint_vector_cases))
        self._run_pass_manager(pass_manager, "text")

    def _run_transient_passes(self):
        pass_manager = PassManager()
        memory_policy = port_policy = None
        if self.options.enable_asan:
            pass_manager.add(AsanStackPass(
                self.reg_manager, self.transient_section, self.decoder, self.arch, self.options.enable_memlog,
                dift_layout=self.dift_layout, tag_storage=self.options.aarch64_tag_storage, transient=True))
        if self.options.enable_gadgets:
            pass_manager.add(TransientCoveragePass(
                self.reg_manager, self.transient_section, self.decoder, self.guard_section, self.arch,
                index_base_symbol=self.component_guard_base))
            if self.options.enable_mem_operand_gadgets:
                memory_policy = self.arch.create_transient_mem_operand_policy_pass(
                    self.reg_manager,
                    self.transient_section,
                    self.decoder,
                    dift_layout=self.dift_layout,
                    enable_asan_check=self.options.enable_gadget_asan_check,
                    asan_tag_storage=self.options.aarch64_tag_storage)
            if self.options.enable_port_gadgets:
                port_policy = self.arch.create_transient_port_contention_policy_pass(
                    self.reg_manager,
                    self.transient_section,
                    self.decoder,
                    dift_layout=self.dift_layout)
        else:
            create_guards(self.guard_section, 0)
        lazy = self.options.enable_dift and not self.options.eager_transient_dift
        if lazy:
            from teapot.passes.transient.lazy_dift import transient_replay_pass
            pass_manager.add(transient_replay_pass(
                self.arch, self.reg_manager, self.transient_section, self.decoder,
                dift_layout=self.dift_layout, insert_memlog=self.options.enable_memlog,
                memory_policy=memory_policy, port_policy=port_policy))
        else:
            for policy in (memory_policy, port_policy):
                if policy is not None:
                    pass_manager.add(policy)
        if self.options.enable_dift and not lazy:
            pass_manager.add(self.arch.create_transient_dift_pass(
                self.reg_manager, self.transient_section, self.decoder, self.dift_layout,
                insert_memlog=self.options.enable_memlog))
        if self.options.enable_memlog:
            pass_manager.add(self.arch.create_transient_memlog_pass(
                self.reg_manager, self.transient_section, self.decoder))
        if self.options.enable_checkpoints:
            pass_manager.add(TransientInsertRestorePointsPass(
                self.reg_manager, self.text_section, self.transient_section, self.decoder, self.arch,
                linked_function_symbols=(self.linked_component.linked_function_symbols
                                         if self.linked_component else ())))
        if self.options.enable_indirect_check:
            pass_manager.add(TransientIndirectBranchCheckDestPass(
                self.reg_manager,
                self.transient_section,
                self.decoder,
                self.transient_section_start_symbol,
                self.transient_section_end_symbol,
                self.text_section_start_symbol,
                self.text_section_end_symbol,
                self.arch))
        if self.options.enable_checkpoints and self.options.enable_nested_speculation:
            pass_manager.add(InsertCheckpointsPass(
                self.reg_manager,
                self.transient_section,
                self.decoder,
                self.arch,
                {self.text_transient_mapping.code_blocks_map[uuid].uuid
                 for uuid in self.checkpoint_block_uuids},
                self.checkpoint_spare_registers,
                self.checkpoint_df_blocks, self.options.force_checkpoint_df,
                self.checkpoint_vector_cases))
        # Replacements must follow insertions at the same original offset.
        for arch_pass in self.arch.transient_instruction_passes(
                self.reg_manager, self.transient_section, self.decoder, self.dift_layout, self.options):
            pass_manager.add(arch_pass)
        self._run_pass_manager(pass_manager, "transient")

    def _run_late_text_checkpoint_passes(self):
        pass_manager = PassManager()
        # These passes run no live-register analysis, so caching the expanded text
        # disassembly would only raise the peak during rewrite application.
        checkpoint_decoder = GtirbInstructionDecoder(self.module.isa)
        for arch_pass in self.arch.late_text_checkpoint_passes(
                text_section=self.text_section,
                transient_section=self.transient_section,
                text_transient_mapping=self.text_transient_mapping,
                landing_pad_targets=self.landing_pad_targets,
                decoder=checkpoint_decoder):
            pass_manager.add(arch_pass)
        self._run_pass_manager(pass_manager, "text-checkpoints")
        self.arch.relax_late_branches(
            module=self.module,
            text_section=self.text_section,
            transient_section=self.transient_section,
            text_transient_mapping=self.text_transient_mapping,
            landing_pad_targets=self.landing_pad_targets,
            run_pass_manager=self._run_pass_manager,
        )
