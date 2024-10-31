from gtirb_rewriting import Pass
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder


class RegInstAwarePassMixin(Pass):
    reg_manager: LiveRegisterManager
    decoder: GtirbInstructionDecoder

    def __init__(self, reg_manager: LiveRegisterManager, decoder: GtirbInstructionDecoder):
        self.reg_manager = reg_manager
        self.decoder = decoder
