import gtirb
from gtirb_rewriting import Pass, Patch

from teapot.utils.misc import (
    distinguish_edges,
    generate_distinct_label_name,
    get_or_insert_symbol,
)


class X64RelaxJcxzPass(Pass):
    """Expand x86 count-zero branches, whose encoding is always rel8."""

    SHORT_COUNT_BRANCHES = {"jcxz", "jecxz", "jrcxz"}

    def __init__(self, decoder, arch):
        self.decoder = decoder
        self.arch = arch
        self.relaxed = 0

    def begin_module(self, module, functions, rewriting_ctx):
        self.relaxed = 0
        for section in module.sections:
            # Teapot creates executable code outside .text and
            # .teapot_transient (notably .teapot_trampolines).  Selecting by
            # the ELF/GTIRB property keeps rel8-only branches valid in every
            # executable section without encoding a section-name inventory.
            if gtirb.Section.Flag.Executable not in section.flags:
                continue
            for block in list(section.code_blocks):
                if block.size == 0 or block.address is None:
                    continue
                instructions = list(self.decoder.get_instructions(block))
                if not instructions:
                    continue
                instruction = instructions[-1]
                if instruction.mnemonic not in self.SHORT_COUNT_BRANCHES:
                    continue

                branch_edges, _ = distinguish_edges(block.outgoing_edges)
                branch_edges = [
                    edge for edge in branch_edges
                    if edge.label.type == gtirb.cfg.Edge.Type.Branch
                    and edge.label.conditional
                ]
                if len(branch_edges) != 1:
                    raise ValueError(
                        f"expected one conditional edge for {instruction.mnemonic} "
                        f"at {instruction.address:#x}, found {len(branch_edges)}")

                target = branch_edges[0].target
                if not isinstance(target, gtirb.CodeBlock):
                    raise ValueError(
                        f"cannot relax {instruction.mnemonic} at "
                        f"{instruction.address:#x}: target is not code")
                target_symbol = get_or_insert_symbol(
                    generate_distinct_label_name(
                        ".L__x64_jcxz_target", target.uuid),
                    target,
                    module,
                )
                taken_label = generate_distinct_label_name(
                    ".L__x64_jcxz_taken", block.uuid)
                done_label = generate_distinct_label_name(
                    ".L__x64_jcxz_done", block.uuid)

                @self.arch.constraints()
                def relaxed_branch(
                    ctx,
                    mnemonic=instruction.mnemonic,
                    target_name=target_symbol.name,
                    taken=taken_label,
                    done=done_label,
                ):
                    return f"""
                        {mnemonic} {taken}
                        jmp {done}
                    {taken}:
                        jmp {target_name}
                    {done}:
                        nop
                    """

                rewriting_ctx.replace_at(
                    block,
                    instruction.address - block.address,
                    instruction.size,
                    Patch.from_function(relaxed_branch),
                )
                self.relaxed += 1

    def end_module(self, module, functions):
        print(
            f"[teapot] X64RelaxJcxzPass relaxed {self.relaxed} instructions",
            flush=True,
        )
