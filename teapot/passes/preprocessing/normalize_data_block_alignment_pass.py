import gtirb
from gtirb_rewriting import Pass, RewritingContext


class NormalizeDataBlockAlignmentPass(Pass):
    """Keep alignment padding outside contiguous data-block runs.

    Rewriting temporarily splits byte intervals at aligned block boundaries.
    If an aligned data block is the tail of an otherwise contiguous data run,
    relayout can consequently materialize padding *inside* that run after an
    earlier code insertion.  Programs are allowed to address the run through
    its first block and continue across later block boundaries, so inserting
    bytes there changes the data rather than merely relocating it.

    For each requested interior alignment, find the earliest preceding,
    symbolized block boundary in the run that already had the same alignment.
    A symbol marks an independently addressable anchor rather than an
    arbitrary split chosen by lifting.  Recording that true alignment fact
    moves any required padding before the compatible sub-run and preserves
    every offset from that anchor through the original aligned block.  Runs
    with gaps, overlaps, address-less blocks, or no earlier compatible anchor
    are deliberately left unchanged.
    """

    def __init__(self):
        self.propagated = 0

    def begin_module(
        self,
        module: gtirb.Module,
        functions,
        rewriting_ctx: RewritingContext,
    ) -> None:
        self.propagated = 0
        alignment_aux = module.aux_data.get("alignment")
        if alignment_aux is None:
            return

        alignment = alignment_aux.data
        for interval in module.byte_intervals:
            for run in self._contiguous_data_runs(interval):
                if len(run) < 2:
                    continue

                requirements = {}
                for index, block in enumerate(run):
                    boundary = alignment.get(block)
                    if not self._is_power_of_two(boundary):
                        continue

                    anchor = next(
                        (
                            candidate
                            for candidate in run[:index]
                            if candidate.address is not None
                            and candidate.address % boundary == 0
                            and any(candidate.references)
                        ),
                        None,
                    )
                    if anchor is not None:
                        requirements[anchor] = max(
                            requirements.get(anchor, 1), boundary
                        )

                for anchor, required in requirements.items():
                    current = alignment.get(anchor, 1)
                    if required <= current:
                        continue
                    alignment[anchor] = required
                    self.propagated += 1

    def end_module(self, module, functions) -> None:
        print(
            "[teapot] NormalizeDataBlockAlignmentPass propagated "
            f"{self.propagated} alignments",
            flush=True,
        )

    @staticmethod
    def _is_power_of_two(value) -> bool:
        return isinstance(value, int) and value > 1 and value & (value - 1) == 0

    @staticmethod
    def _contiguous_data_runs(interval):
        blocks = sorted(
            (
                block
                for block in interval.blocks
                if isinstance(block, gtirb.DataBlock) and block.size > 0
            ),
            key=lambda block: (block.offset, block.size, block.uuid.hex),
        )
        run = []
        end = None
        ambiguous = False

        for block in blocks:
            block_end = block.offset + block.size
            if end is None:
                run = [block]
                end = block_end
                continue

            if block.offset < end:
                # Do not infer a movable run boundary through overlapping
                # byte interpretations.  Stay conservative until a real gap.
                run = []
                end = max(end, block_end)
                ambiguous = True
                continue

            if block.offset == end:
                if ambiguous:
                    end = block_end
                    continue
                run.append(block)
                end = block_end
                continue

            if run:
                yield run
            run = [block]
            end = block_end
            ambiguous = False

        if run:
            yield run
