import gc
from dataclasses import dataclass

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
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
from teapot.passes.preprocessing.normalize_control_flow_targets_pass import (
    NormalizeControlFlowTargetsPass,
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
from teapot.utils.misc import distinguish_edges
from teapot.utils.reg_analysis import LiveRegisterManagerWrapper

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


def _run_pass_manager(pass_manager: PassManager, ir: gtirb.IR, label: str):
    print(f"[teapot] begin {label}", flush=True)
    integral_tls_symbols = _integral_tls_symbol_values(ir.modules[0])
    try:
        pass_manager.run(ir)
    finally:
        _restore_integral_symbol_values(integral_tls_symbols)
    CachedGtirbInstructionDecoder.cache.clear()
    gc.collect()
    print(f"[teapot] end {label}", flush=True)


def _conditional_branch_block_uuids(section: gtirb.Section):
    block_uuids = set()
    for block in section.code_blocks:
        non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
        if (non_fallthrough_edges and
                non_fallthrough_edges[0].label.type == gtirb.cfg.Edge.Type.Branch and
                non_fallthrough_edges[0].label.conditional):
            block_uuids.add(block.uuid)
    return block_uuids


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


class TeapotPipeline:
    def __init__(self, ir: gtirb.IR, dift_layout_name=None,
                 options: InstrumentationOptions = InstrumentationOptions()):
        self.ir = ir
        self.dift_layout_name = dift_layout_name
        self.options = options

    def run(self):
        self.module = self.ir.modules[0]
        self.arch = get_arch(self.module)
        if self.options.aarch64_tag_storage == ASAN_TAG_STORAGE_MTE and self.arch.name != "aarch64":
            raise ValueError("--aarch64-tag-storage=mte is only valid for AArch64 modules")
        if self.options.aarch64_tag_storage == ASAN_TAG_STORAGE_MTE:
            _add_arch_feature(self.module, AARCH64_MTE_ARCH_FEATURE)
        self.arch.install_decoder_compat()
        self.dift_layout = get_dift_layout(self.arch.name, self.dift_layout_name)
        self.arch.install_rewriting_compat()
        self.text_section = [section for section in self.module.sections if section.name == ".text"][0]
        self.decoder = CachedGtirbInstructionDecoder(self.module.isa)
        self.abi = self.arch.register_abi(_ABIS)

        self._run_normalize_passes()
        self._create_instrumentation_sections()
        self._run_preprocess_passes()
        self._run_dift_ext_call_passes()
        self.checkpoint_block_uuids = _conditional_branch_block_uuids(self.text_section)

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

        if self.arch.needs_late_text_checkpoints():
            self._run_late_text_checkpoint_passes()

    def _run_normalize_passes(self):
        pass_manager = PassManager()
        pass_manager.add(NormalizeDataBlockAlignmentPass())
        pass_manager.add(NormalizeControlFlowTargetsPass(self.decoder))
        for arch_pass in self.arch.normalize_passes(self.decoder):
            pass_manager.add(arch_pass)
        _run_pass_manager(pass_manager, self.ir, "normalize")

    def _create_instrumentation_sections(self):
        self.transient_section, self.transient_section_start_symbol, self.transient_section_end_symbol, \
            self.text_transient_mapping = copy_section(self.text_section, ".teapot_transient")
        self.text_section_start_symbol, self.text_section_end_symbol = create_section_bounds(
            self.text_section, "text")

        self.reg_manager = LiveRegisterManagerWrapper(
            self.module, self.abi, self.decoder, text_transient_mapping=self.text_transient_mapping) \
            if self.arch.uses_live_registers else None

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
        pass_manager.add(CreateTrampolinesPass(
            self.text_section,
            self.trampoline_section,
            self.branch_counter_section,
            self.text_transient_mapping,
            self.decoder,
            self.arch,
            self.reg_manager,
            self.landing_pad_targets,
            self.checkpoint_spare_registers))
        for arch_pass in self.arch.preprocess_passes(
                text_section=self.text_section,
                transient_section=self.transient_section,
                text_transient_mapping=self.text_transient_mapping,
                landing_pad_targets=self.landing_pad_targets,
                decoder=self.decoder):
            pass_manager.add(arch_pass)
        _run_pass_manager(pass_manager, self.ir, "preprocess")

    def _run_dift_ext_call_passes(self):
        pass_manager = PassManager()
        if self.options.enable_dift and self.arch.supports_dift_ext_calls():
            pass_manager.add(DiftExtCallPass(self.text_section, wrap_dift_calls=True))
        _run_pass_manager(pass_manager, self.ir, "dift-ext-calls")

    def _run_text_passes(self):
        pass_manager = PassManager()
        pass_manager.add(TextInitializeLibraryPass(self.text_section, self.decoder, self.arch))
        if self.options.enable_asan:
            pass_manager.add(AsanStackPass(
                self.reg_manager, self.text_section, self.decoder, self.arch, False,
                dift_layout=self.dift_layout, tag_storage=self.options.aarch64_tag_storage))
        if self.options.enable_indirect_transform:
            if self.options.enable_checkpoints:
                pass_manager.add(TextSkippedTransformRestorePass(
                    self.text_section, self.arch))
            pass_manager.add(TextIndirectBranchTransformPass(
                self.text_section,
                self.text_transient_mapping,
                self.decoder,
                self.arch,
                self.reg_manager,
                self.landing_pad_targets))
        if self.options.enable_dift:
            pass_manager.add(self.arch.create_text_dift_pass(
                self.reg_manager, self.text_section, self.decoder, self.dift_layout))
        if self.options.enable_checkpoints and self.arch.text_checkpoints_in_main_text_pass():
            pass_manager.add(InsertCheckpointsPass(
                self.reg_manager, self.text_section, self.decoder, self.arch,
                self.checkpoint_block_uuids, self.checkpoint_spare_registers))
        _run_pass_manager(pass_manager, self.ir, "text")
        if self.reg_manager is not None:
            self.reg_manager.result_cache.clear()

    def _run_transient_passes(self):
        pass_manager = PassManager()
        if self.options.enable_asan:
            pass_manager.add(AsanStackPass(
                self.reg_manager, self.transient_section, self.decoder, self.arch, True,
                dift_layout=self.dift_layout, tag_storage=self.options.aarch64_tag_storage))
        if self.options.enable_gadgets:
            pass_manager.add(TransientCoveragePass(
                self.reg_manager, self.transient_section, self.decoder, self.guard_section, self.arch))
            if self.options.enable_mem_operand_gadgets:
                pass_manager.add(self.arch.create_transient_mem_operand_policy_pass(
                    self.reg_manager,
                    self.transient_section,
                    self.decoder,
                    dift_layout=self.dift_layout,
                    enable_asan_check=self.options.enable_gadget_asan_check,
                    asan_tag_storage=self.options.aarch64_tag_storage))
            if self.options.enable_port_gadgets:
                pass_manager.add(self.arch.create_transient_port_contention_policy_pass(
                    self.reg_manager,
                    self.transient_section,
                    self.decoder,
                    dift_layout=self.dift_layout))
        else:
            create_guards(self.guard_section, 0)
        if self.options.enable_dift:
            pass_manager.add(self.arch.create_transient_dift_pass(
                self.reg_manager, self.transient_section, self.decoder, self.dift_layout))
        if self.options.enable_memlog:
            pass_manager.add(self.arch.create_transient_memlog_pass(
                self.reg_manager, self.transient_section, self.decoder))
        if self.options.enable_checkpoints:
            pass_manager.add(TransientInsertRestorePointsPass(
                self.reg_manager, self.text_section, self.transient_section, self.decoder, self.arch))
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
                _conditional_branch_block_uuids(self.transient_section),
                self.checkpoint_spare_registers))
        _run_pass_manager(pass_manager, self.ir, "transient")

    def _run_late_text_checkpoint_passes(self):
        pass_manager = PassManager()
        # This pass visits each eligible block once and does not run live-register
        # analysis, so caching the expanded text disassembly only raises the peak
        # during rewrite application.
        checkpoint_decoder = GtirbInstructionDecoder(self.module.isa)
        if self.options.enable_checkpoints:
            pass_manager.add(InsertCheckpointsPass(
                None, self.text_section, checkpoint_decoder, self.arch,
                self.checkpoint_block_uuids, self.checkpoint_spare_registers))
        for arch_pass in self.arch.late_text_checkpoint_passes(
                text_section=self.text_section,
                transient_section=self.transient_section,
                text_transient_mapping=self.text_transient_mapping,
                landing_pad_targets=self.landing_pad_targets,
                decoder=checkpoint_decoder):
            pass_manager.add(arch_pass)
        _run_pass_manager(pass_manager, self.ir, "text-checkpoints")
        self.arch.relax_late_branches(
            module=self.module,
            text_section=self.text_section,
            transient_section=self.transient_section,
            text_transient_mapping=self.text_transient_mapping,
            landing_pad_targets=self.landing_pad_targets,
            run_pass_manager=lambda manager, label: _run_pass_manager(
                manager, self.ir, label),
        )
