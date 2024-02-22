from gtirb_live_register_analysis import LiveRegisterManager


class FakeManager(LiveRegisterManager):
    def analyze(self, function):
        return

    def live_registers(self, function, block, inst_idx):
        return set(self.abi.all_registers())
