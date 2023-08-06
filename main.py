import gtirb
from gtirb_rewriting import PassManager

from NaHCO3.preprocess.copy_section import copy_section
from NaHCO3.passes import CreateTrampolinesPass, TextCallTransformPass, TextInsertCheckpointsPass, TransientRetpolinesPass

ir = gtirb.IR.load_protobuf("test/test.gtirb")
module = ir.modules[0]
text_section = [s for s in module.sections if s.name == ".text"][0]

transient_section, transient_section_end_symbol, text_transient_mapping = (
    copy_section(text_section, ".NaHCO3_transient"))

trampoline_section = gtirb.Section(name=".NaHCO3_trampolines", flags=transient_section.flags, module=module)
trampoline_byte_interval = gtirb.ByteInterval(section=trampoline_section)

pass_manager = PassManager()
pass_manager.add(CreateTrampolinesPass(text_section, trampoline_section, text_transient_mapping))
pass_manager.run(ir)

pass_manager = PassManager()
pass_manager.add(TextCallTransformPass(text_section, text_transient_mapping))
pass_manager.add(TextInsertCheckpointsPass(text_section))
pass_manager.add(TransientRetpolinesPass(text_section, transient_section_end_symbol, text_transient_mapping))
pass_manager.run(ir)

ir.save_protobuf("test/test_modified.gtirb")
