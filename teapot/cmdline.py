import gtirb
from gtirb_rewriting import PassManager
from gtirb_rewriting.abi import _ABIS
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
import pprint
import sys

from teapot.abi.x86_64 import _X86_64_ELF

from teapot.preprocess.copy_section import copy_section
from teapot.utils.reg_analysis import LiveRegisterManagerWrapper
from teapot.passes import *
from teapot.config import *


def run_teapot(ir: gtirb.IR):
    module = ir.modules[0]
    text_section = [s for s in module.sections if s.name == ".text"][0]

    # pass_manager = PassManager()
    # pass_manager.add(DebugSymbolsPass(in_name))
    # pass_manager.run(ir)

    decoder = CachedGtirbInstructionDecoder(module.isa)

    my_x64_elf_abi = _X86_64_ELF()
    _ABIS[(gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF)] = my_x64_elf_abi

    transient_section, transient_section_start_symbol, transient_section_end_symbol, text_transient_mapping = (
        copy_section(text_section, ".teapot_transient"))

    reg_manager = LiveRegisterManagerWrapper(module, my_x64_elf_abi, decoder,
                                             text_transient_mapping=text_transient_mapping)
    trampoline_section = gtirb.Section(name=".teapot_trampolines", flags=transient_section.flags, module=module)
    trampoline_byte_interval = gtirb.ByteInterval(section=trampoline_section)

    guard_section = gtirb.Section(name=".teapot_guards",
                                  flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable},
                                  module=module)
    guard_byte_interval = gtirb.ByteInterval(section=guard_section)

    branch_counter_section = gtirb.Section(name=".teapot_branch_counters",
                                           flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable},
                                           module=module)
    branch_counter_byte_interval = gtirb.ByteInterval(section=branch_counter_section)

    pass_manager = PassManager()
    pass_manager.add(ImportSymbolsPass())
    pass_manager.add(
        CreateTrampolinesPass(text_section, trampoline_section, branch_counter_section, text_transient_mapping,
                              decoder))
    pass_manager.add(DiftExtCallPass(text_section))
    pass_manager.run(ir)

    pass_manager = PassManager()
    pass_manager.add(TextInitializeLibraryPass(text_section))

    pass_manager.add(AsanStackPass(reg_manager, text_section, decoder, False))
    pass_manager.add(TextIndirectBranchTransformPass(text_section, text_transient_mapping, decoder))
    pass_manager.add(TextDiftPropagationLLVMPass(reg_manager, text_section, decoder, False))
    pass_manager.add(InsertCheckpointsPass(reg_manager, text_section, decoder))

    pass_manager.add(AsanStackPass(reg_manager, transient_section, decoder, True))
    pass_manager.add(TransientCoveragePass(reg_manager, transient_section, decoder, guard_section))
    pass_manager.add(TransientMemOperandPoliciesPass(reg_manager, transient_section, decoder))
    pass_manager.add(TransientPortContentionPolicyPass(reg_manager, transient_section, decoder))
    pass_manager.add(DiftPropagationPass(reg_manager, transient_section, decoder, True))
    pass_manager.add(TransientMemlogPass(reg_manager, transient_section, decoder))
    pass_manager.add(TransientInsertRestorePointsPass(reg_manager, text_section, transient_section, decoder))
    pass_manager.add(TransientIndirectBranchCheckDestPass(reg_manager, transient_section, decoder,
                                                          transient_section_start_symbol, transient_section_end_symbol))
    pass_manager.add(InsertCheckpointsPass(reg_manager, transient_section, decoder))
    pass_manager.run(ir)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} input.gtirb output.gtirb")
        return

    in_name = sys.argv[1]
    out_name = sys.argv[2]

    ir = gtirb.IR.load_protobuf(in_name)
    run_teapot(ir)
    ir.save_protobuf(out_name)


if __name__ == '__main__':
    main()
