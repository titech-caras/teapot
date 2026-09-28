"""Keep native PAC/BTI/trap instructions outside the guarded target range."""
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Pass, Patch, patch_constraints


class AArch64OutlineNativeLandingsPass(Pass):
    SECTION = '.teapot_bti_native'

    def __init__(self, normal_section, marker_words):
        self.normal_section = normal_section
        self.marker_words = marker_words
        self.outlined = 0

    @staticmethod
    def hardware_landing(word):
        return word in (0xd503245f, 0xd503249f, 0xd50324df, 0xd503233f, 0xd503237f) or \
            word & 0xffe0001f in (0xd4200000, 0xd4400000)

    @classmethod
    def _patch(cls, word):
        # Use the baseline HINT spelling for PAC/BTI. LLVM MC then retains a
        # CodeBlock/CFG (a raw .inst directive is represented as data there).
        if word & 0xfffff01f == 0xd503201f:
            native = 'hint #' + str((word >> 5) & 127)
        else:
            native = ('brk' if word & 0xffe0001f == 0xd4200000 else 'hlt') + \
                     ' #' + str((word >> 5) & 65535)
        @patch_constraints()
        def patch(ctx):
            # Direct B changes neither LR, SP, NZCV nor another register. In
            # particular, PACIASP/PACIBSP retain their original LR/SP inputs;
            # no PAC instruction is replaced with a NOP or weaker substitute.
            return f'''
                b .Lnative_landing
            .Lnative_continue:
                .pushsection {cls.SECTION}, "ax", %progbits
            .Lnative_landing:
                {native}
                b .Lnative_continue
                .popsection
            '''
        return Patch.from_function(patch)

    def begin_module(self, module, functions, rewriting_ctx):
        if any(s.name == self.SECTION for s in module.sections):
            raise ValueError('input collides with reserved native-landing section')
        decoder = GtirbInstructionDecoder(module.isa)
        for block in self.normal_section.code_blocks:
            # Section-end anchors have no instructions (and Capstone 6 rejects
            # an empty input buffer). Component bounds leave such anchors too.
            if not block.size:
                continue
            for instruction in decoder.get_instructions(block):
                if instruction.size != 4:
                    continue
                word = int.from_bytes(instruction.bytes, 'little')
                if not self.hardware_landing(word):
                    continue
                offset = instruction.address - block.address
                bi_offset = block.offset + offset
                # The inserted, complete marker is the only admitted hardware
                # landing in normal text. Native BTI alone is not a marker.
                contents = block.byte_interval.contents
                following = int.from_bytes(contents[bi_offset + 4:bi_offset + 8], 'little')
                if (word, following) == self.marker_words:
                    continue
                if any(bi_offset <= p < bi_offset + 4 for p in block.byte_interval.symbolic_expressions):
                    raise ValueError('native landing unexpectedly carries a relocation')
                rewriting_ctx.replace_at(block, offset, 4, self._patch(word))
                self.outlined += 1

    def end_module(self, module, functions):
        print('[teapot] outlined {} native AArch64 landing instructions'.format(self.outlined), flush=True)
