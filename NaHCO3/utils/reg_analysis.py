import gtirb
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_functions import Function

from NaHCO3.datacls.copied_section_mapping import CopiedSectionMapping


class LiveRegisterManagerWrapper(LiveRegisterManager):
    def __init__(self, *args, text_transient_mapping: CopiedSectionMapping):
        super().__init__(*args)
        self.text_transient_mapping = text_transient_mapping

    def analyze(self, function: Function):
        if function.uuid in self.result_cache:
            return

        super().analyze(function)

        if function.uuid in self.text_transient_mapping.function_uuids_map:
            copied_uuid = self.text_transient_mapping.function_uuids_map[function.uuid]

            self.result_cache[copied_uuid] = {}
            for block_uuid, regs in self.result_cache[function.uuid].items():
                try:
                    copied_block_uuid = self.text_transient_mapping.code_blocks_map[block_uuid].uuid
                    self.result_cache[copied_uuid][copied_block_uuid] = regs
                except KeyError:
                    pass
