import gtirb
from gtirb_rewriting import PassManager
from gtirb_rewriting.abi import _ABIS
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
import pprint
import sys

from NaHCO3.abi.x86_64 import _X86_64_ELF

from NaHCO3.preprocess.copy_section import copy_section
from NaHCO3.utils.reg_analysis import LiveRegisterManagerWrapper
from NaHCO3.passes import *

in_name = sys.argv[-2]
out_name = sys.argv[-1]

ir = gtirb.IR.load_protobuf(f"{in_name}.gtirb")
module = ir.modules[0]
text_section = [s for s in module.sections if s.name == ".text"][0]

decoder = CachedGtirbInstructionDecoder(module.isa)

my_x64_elf_abi = _X86_64_ELF()
_ABIS[(gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF)] = my_x64_elf_abi

transient_section, transient_section_start_symbol, transient_section_end_symbol, text_transient_mapping = (
    copy_section(text_section, ".NaHCO3_transient"))

from fake_reg_manager import FakeManager
freg_manager = FakeManager(module, my_x64_elf_abi, decoder)
reg_manager = LiveRegisterManagerWrapper(module, my_x64_elf_abi, decoder, text_transient_mapping=text_transient_mapping)
trampoline_section = gtirb.Section(name=".NaHCO3_trampolines", flags=transient_section.flags, module=module)
trampoline_byte_interval = gtirb.ByteInterval(section=trampoline_section)

guard_section = gtirb.Section(name=".NaHCO3_guards", flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable},
                              module=module)
guard_byte_interval = gtirb.ByteInterval(section=guard_section)

pass_manager = PassManager()
pass_manager.add(ImportSymbolsPass())
pass_manager.add(CreateTrampolinesPass(text_section, trampoline_section, text_transient_mapping, decoder))
#pass_manager.add(DiftExtCallPass(text_section))
pass_manager.run(ir)

pass_manager = PassManager()
pass_manager.add(TextInitializeLibraryPass(text_section))

pass_manager.add(AsanStackPass(reg_manager, text_section, decoder, False))
pass_manager.add(TextIndirectBranchTransformPass(text_section, text_transient_mapping, decoder))
pass_manager.add(DiftPropagationLLVMPass(reg_manager, text_section, decoder, False))
pass_manager.add(TextInsertCheckpointsPass(reg_manager, text_section, decoder))

pass_manager.add(AsanStackPass(reg_manager, transient_section, decoder, True))
pass_manager.add(TransientCoveragePass(reg_manager, transient_section, decoder, guard_section))
pass_manager.add(TransientGadgetPolicyPass(reg_manager, transient_section, decoder))
pass_manager.add(DiftPropagationPass(reg_manager, transient_section, decoder, True))
pass_manager.add(TransientMemlogPass(reg_manager, transient_section, decoder))
pass_manager.add(TransientInsertRestorePointsPass(reg_manager, text_section, transient_section, decoder))
pass_manager.add(TransientIndirectBranchCheckDestPass(reg_manager, transient_section, decoder,
                                                      transient_section_start_symbol, transient_section_end_symbol))
pass_manager.run(ir)

ir.save_protobuf(f"{out_name}.gtirb")
