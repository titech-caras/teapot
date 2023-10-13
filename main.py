import gtirb
from gtirb_rewriting import PassManager
from gtirb_rewriting.abi import _ABIS
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
import pprint
import sys

from NaHCO3.abi.x86_64 import _X86_64_ELF

from NaHCO3.preprocess.copy_section import copy_section
from NaHCO3.passes import *

gtirb_name = sys.argv[-1]

ir = gtirb.IR.load_protobuf(f"test/{gtirb_name}.gtirb")
module = ir.modules[0]
text_section = [s for s in module.sections if s.name == ".text"][0]

my_x64_elf_abi = _X86_64_ELF()
reg_manager = LiveRegisterManager(module, my_x64_elf_abi)
_ABIS[(gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF)] = my_x64_elf_abi

transient_section, transient_section_start_symbol, transient_section_end_symbol, text_transient_mapping = (
    copy_section(text_section, ".NaHCO3_transient"))

trampoline_section = gtirb.Section(name=".NaHCO3_trampolines", flags=transient_section.flags, module=module)
trampoline_byte_interval = gtirb.ByteInterval(section=trampoline_section)

decoder = CachedGtirbInstructionDecoder(module.isa)

pass_manager = PassManager()
pass_manager.add(CreateTrampolinesPass(text_section, trampoline_section, text_transient_mapping, decoder))
pass_manager.add(ImportSymbolsPass())
pass_manager.run(ir)

pass_manager = PassManager()
pass_manager.add(TextCallTransformPass(text_section, text_transient_mapping, decoder))
pass_manager.add(TextInsertCheckpointsPass(reg_manager, text_section, decoder))

pass_manager.add(TransientInsertMemoryLogsPass(reg_manager, transient_section, decoder))
pass_manager.add(TransientInsertRestorePointsPass(reg_manager, transient_section, decoder))
pass_manager.add(TransientRetpolinesPass(transient_section,
                                         transient_section_start_symbol, transient_section_end_symbol))
pass_manager.add(TransientAsanPass(reg_manager, transient_section, decoder))
pass_manager.run(ir)

ir.save_protobuf(f"test/{gtirb_name}_modified.gtirb")
