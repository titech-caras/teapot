import gtirb
from gtirb_rewriting import Patch, RewritingContext

from teapot.datacls.copied_section_mapping import CopiedSectionMapping
from teapot.passes.mixins import ArchSpecificPassMixin, VisitorPassMixin


class RISCV64LandingPadsPass(ArchSpecificPassMixin, VisitorPassMixin):
    EXPECTED_ARCH = "riscv64"

    def __init__(self, text_section: gtirb.Section, transient_section: gtirb.Section,
                 text_transient_mapping: CopiedSectionMapping,
                 arch, landing_pad_targets=None, insert_code: bool = True,
                 decoder=None):
        self.check_expected_arch(arch)
        self.text_section = text_section
        self.transient_section = transient_section
        self.text_transient_mapping = text_transient_mapping
        self.arch = arch
        self.landing_pad_targets = landing_pad_targets if landing_pad_targets is not None else set()
        self.insert_code = insert_code
        self.decoder = decoder
        self.padded_blocks = set()
        self.symbol_names = set()

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.padded_blocks = set()
        self.symbol_names = {symbol.name for symbol in module.symbols}
        for target_uuid in list(self.landing_pad_targets):
            self._ensure_landing_pad(target_uuid)

    def _ensure_landing_pad(self, original_block_uuid):
        if original_block_uuid in self.padded_blocks:
            return

        transient_block = self.text_transient_mapping.code_blocks_map.get(original_block_uuid)
        if transient_block is None:
            return

        landing_name = self.arch.landing_pad_entry_label(original_block_uuid)
        if landing_name not in self.symbol_names:
            gtirb.Symbol(
                name=landing_name,
                payload=transient_block,
                module=self.module)
            self.symbol_names.add(landing_name)

        if not self.insert_code:
            self.padded_blocks.add(original_block_uuid)
            return

        self.insert_at(
            transient_block, 0, Patch.from_function(
                self.arch.restore_landing_entry_patch(original_block_uuid)))
        self.padded_blocks.add(original_block_uuid)
