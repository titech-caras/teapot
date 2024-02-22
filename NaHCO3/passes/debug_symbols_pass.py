from typing import Sequence

import posixpath
import gtirb
import gtirb_functions
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_functions import Function
from gtirb_rewriting import Pass, RewritingContext, Patch, patch_constraints

from elftools.elf.elffile import ELFFile

'''
ONLY FOR DEBUGGING PURPOSES!
Don't use for actual fuzzing.
'''


class DebugSymbolsPass(Pass):
    elf: ELFFile

    def __init__(self, elf_name: str):
        self.elf = ELFFile(open(elf_name, 'rb'))

    def begin_module(
            self,
            module: gtirb.Module,
            functions: Sequence[gtirb_functions.Function],
            rewriting_ctx: RewritingContext,
    ) -> None:
        if not self.elf.has_dwarf_info():
            return

        new_filename_mapping = {}

        dwarf = self.elf.get_dwarf_info()
        for CU in dwarf.iter_CUs():
            line_program = dwarf.line_program_for_CU(CU)

            for entry in line_program.get_entries():
                if entry.state is None:
                    continue
                block = list(module.code_blocks_on(entry.state.address))[0]
                offset = entry.state.address - block.address

                filename = self.lpe_filename(line_program, entry.state.file)
                if filename not in new_filename_mapping:
                    idx = len(new_filename_mapping)
                    new_filename_mapping[filename] = idx
                else:
                    idx = new_filename_mapping[filename]

                entry.state.file = idx
                rewriting_ctx.insert_at(block, offset, Patch.from_function(self.gen_dbg_label(entry)))

        print("-----BEGIN FILE DECLARATIONS-----")
        sorted_filenames = [k for k, v in sorted(new_filename_mapping.items(), key=lambda item: item[1])]
        for idx, filename in enumerate(sorted_filenames):
            print(f".file {idx} \"{filename}\"")

        print("-----END FILE DECLARATIONS-----")

    def lpe_filename(self, line_program, file_index):
        # Retrieving the filename associated with a line program entry
        # involves two levels of indirection: we take the file index from
        # the LPE to grab the file_entry from the line program header,
        # then take the directory index from the file_entry to grab the
        # directory name from the line program header. Finally, we
        # join the (base) filename from the file_entry to the directory
        # name to get the absolute filename.
        lp_header = line_program.header
        file_entries = lp_header["file_entry"]

        # File and directory indices are 1-indexed.
        file_entry = file_entries[file_index - 1]
        dir_index = file_entry["dir_index"]

        # A dir_index of 0 indicates that no absolute directory was recorded during
        # compilation; return just the basename.
        if dir_index == 0:
            return file_entry.name.decode()

        directory = lp_header["include_directory"][dir_index - 1]
        return posixpath.join(directory, file_entry.name).decode()

    def gen_dbg_label(self, entry):
        @patch_constraints(x86_syntax=X86Syntax.INTEL)
        def patch(ctx):
            return f"""
                .L_loc_{entry.state.file}_{entry.state.line}_{entry.state.column}__test: 
                    nop
            """

        return patch
