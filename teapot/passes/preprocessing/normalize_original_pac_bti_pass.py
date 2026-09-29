"""Normalize the original program's PAC/BTI encodings in the BTI modes.

Design step 4: instead of stripping or outlining native PAC/BTI, transform it in
place, before the speculative copy is made, so both copies see the same code.

- The BTI-compatible signing/authentication hints become their non-hint twins:
  same key, same SP modifier, same semantics, still four bytes, but no longer
  hardware landings, so the fail-closed activation scan stays exact.
- Native ``bti`` words become NOPs. Indirect targets in normal text get the
  Teapot marker from the target transform that already runs there, so no stray
  landing is left behind; a ``bti`` at a block that is only reached directly has
  no marker and must not remain a landing.
- The negate-RA-state CFI toggle (``.cfi_escape 0x2d``) that describes a
  replaced hint is restored after the rewrite. The framework drops lifted
  directives attached to a replaced instruction, so ``end_module`` adds the
  toggle after every converted PAC word of a CFI procedure unless one is
  already attached at that address.

``retaa``/``retab``, complete native pac-ret functions, BRK/HLT and the whole
software mode are left unchanged.
"""
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Pass, Patch, RewritingContext, patch_constraints

# bti j, bti c, bti jc
BTI_WORDS = frozenset((0xd503245f, 0xd503249f, 0xd50324df))
# Hint spelling -> non-hint twin (both with the x30, sp operands).
PAC_HINT_NORMALIZATION = {
    0xd503233f: "pacia x30, sp",   # paciasp
    0xd503237f: "pacib x30, sp",   # pacibsp
    0xd50323bf: "autia x30, sp",   # autiasp
    0xd50323ff: "autib x30, sp",   # autibsp
}
# The assembled non-hint twins above.
PAC_NORMALIZED_WORDS = frozenset((0xdac103fe, 0xdac107fe, 0xdac113fe, 0xdac117fe))
NEGATE_RA_STATE = (".cfi_escape", [0x2d])


class NormalizeOriginalPacBtiPass(Pass):
    """Replace native hint landings with non-hint PAC and plain NOPs."""

    def __init__(self, decoder):
        self.decoder = decoder
        self.converted_pac = 0
        self.removed_bti = 0
        self.converted_functions = set()
        self.restored_toggles = 0

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        function_by_block = {}
        for function in functions:
            for block in function.get_all_blocks():
                function_by_block[block.uuid] = function.uuid
        text = next(section for section in module.sections if section.name == ".text")
        for block in text.code_blocks:
            if not block.size:
                continue
            for instruction in self.decoder.get_instructions(block):
                if instruction.size != 4:
                    continue
                word = int.from_bytes(instruction.bytes, "little")
                offset = instruction.address - block.address
                if word in PAC_HINT_NORMALIZATION:
                    text_out = (".arch_extension pauth\n"
                                + PAC_HINT_NORMALIZATION[word] + "\n")
                    self._replace(rewriting_ctx, block, offset, text_out)
                    self.converted_pac += 1
                    uuid = function_by_block.get(block.uuid)
                    if uuid is not None:
                        self.converted_functions.add(uuid)
                elif word in BTI_WORDS:
                    self._replace(rewriting_ctx, block, offset, "nop\n")
                    self.removed_bti += 1
        print(f"[teapot] normalized original PAC/BTI: {self.converted_pac} hint PAC, "
              f"{self.removed_bti} native bti", flush=True)

    def end_module(self, module: gtirb.Module, functions):
        """Restore the negate-RA-state toggles discarded with the replaced hints."""
        aux = module.aux_data.get("cfiDirectives")
        if aux is None or not self.converted_functions:
            return
        procedures = set()
        toggle_addresses = set()
        for offset, directives in aux.data.items():
            block = offset.element_id
            if not isinstance(block, gtirb.CodeBlock) or block.byte_interval is None:
                continue
            if any(name == ".cfi_startproc" for name, _, _ in directives):
                procedures.add(block.uuid)
            if any(name == NEGATE_RA_STATE[0] and list(args) == NEGATE_RA_STATE[1]
                   for name, args, _ in directives):
                toggle_addresses.add(block.address + offset.displacement)
        decoder = GtirbInstructionDecoder(module.isa)
        for function in functions:
            if function.uuid not in self.converted_functions:
                continue
            if not any(block.uuid in procedures for block in function.get_all_blocks()):
                continue
            for block in function.get_all_blocks():
                for instruction in decoder.get_instructions(block):
                    word = int.from_bytes(instruction.bytes, "little")
                    if word not in PAC_NORMALIZED_WORDS or instruction.address is None:
                        continue
                    end = instruction.address + instruction.size
                    if end in toggle_addresses:
                        continue
                    key = gtirb.Offset(block, end - block.address)
                    aux.data[key] = list(aux.data.get(key, [])) + [
                        (".cfi_escape", [0x2d], module.uuid)]
                    toggle_addresses.add(end)
                    self.restored_toggles += 1
        print(f"[teapot] restored {self.restored_toggles} negate-RA CFI toggles "
              f"for normalized PAC hints", flush=True)

    @staticmethod
    def _replace(rewriting_ctx, block, offset, text):
        @patch_constraints()
        def patch(_ctx):
            return text

        rewriting_ctx.replace_at(block, offset, 4, Patch.from_function(patch))
