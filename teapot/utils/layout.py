"""A module layout that does not depend on Python's hash order.

gtirb-rewriting lays a module out (gtirb_rewriting.prepare._layout_module, which
calls gtirb_layout.layout_module) when a round starts or ends with sections that
overlap or have no address. That layout walks module.sections and each
section's byte_intervals: sets of nodes hashed by identity, whose order changes
from process to process with the heap's addresses (ASLR), even under
PYTHONHASHSEED=0. The order decides every address. The printer writes sections
in address order and infers the alignment of a section's first block, and of an
exported code block, without an alignment entry from its address; the rewriter
applies a round's patches in address order and numbers their local labels so.

DeterministicLayoutPass, the last pass of every Teapot round, gives the same
layout every time. Its begin_module runs after the other passes have registered
their patches, so a due layout happens there and the rewriter finds none to do;
its end_module runs after the round and lays the module out again if the
rewriter did. Only the section order is chosen here: the input's sections in
address order, then the sections Teapot adds, by name. Each interval is placed
as the rewriter's layout places it, sequentially from 0:
- an interval with alignment entries (its own or its blocks') keeps the
  strongest compatible one at its offset, as _layout_module does
  (gtirb_rewriting.intervalutils._alignment_requirement);
- any other interval keeps the alignment gtirb-layout infers for its first
  block that has one (the largest power of two up to 16 dividing that block's
  address), at that block's offset: the block at offset 8 of an interval at
  0x1008 stays 16-aligned.
The inference uses the address the interval had before the rewriter laid it
out: the one this module gave it last, or the input's. As in gtirb-layout, it
follows the block's current offset; nothing is frozen into the alignment table,
where an instruction block's entry could become incompatible once inserted code
moves it. Teapot's own sections have no input address to infer from, so the
pipeline gives each an explicit 16-byte entry (set_interval_alignment).

The private dependency parts used here are checked against the inspected
versions (teapot/utils/dependencies.py).
"""
import functools
from types import SimpleNamespace
import weakref

import gtirb
from gtirb_rewriting import Pass

from teapot.utils.dependencies import require_inspected

TEAPOT_SECTION_ALIGNMENT = 16
ALIGNMENT_AUX_TYPE = "mapping<UUID,uint64_t>"


@functools.lru_cache(maxsize=None)
def _dependency():
    require_inspected("gtirb", "gtirb-layout", "gtirb-rewriting")
    from gtirb_layout import is_module_layout_required
    from gtirb_layout.layout import _block_sort_key, _default_alignment, _get_predecessor_byte_interval
    from gtirb_rewriting.intervalutils import _alignment_requirement
    from gtirb_rewriting.prepare import _assign_integral_symbols
    return SimpleNamespace(
        is_module_layout_required=is_module_layout_required, block_sort_key=_block_sort_key,
        default_alignment=_default_alignment, predecessor=_get_predecessor_byte_interval,
        alignment_requirement=_alignment_requirement, assign_integral_symbols=_assign_integral_symbols)


def set_interval_alignment(interval: gtirb.ByteInterval, alignment: int):
    """Give the interval an explicit start alignment: an entry in the module's alignment table."""
    table = interval.module.aux_data.setdefault(
        "alignment", gtirb.AuxData(type_name=ALIGNMENT_AUX_TYPE, data={}))
    table.data[interval] = alignment


class _ModuleOrder:
    """The section order of one module, and the addresses its last layout left."""

    def __init__(self, module: gtirb.Module):
        self.ranks = {}
        # The input's sections in address order; nothing is laid out here.
        self._add_sections(module, lambda section: (
            section.address is None, section.address or 0, section.name, section.uuid.int))
        self.addresses = _interval_addresses(module)

    def _add_sections(self, module, key):
        for section in sorted((section for section in module.sections if section.uuid not in self.ranks), key=key):
            self.ranks[section.uuid] = len(self.ranks)

    def add_new_sections(self, module):
        self._add_sections(module, lambda section: (section.name, section.uuid.int))


# Keyed weakly by module; the values hold UUIDs only, never nodes.
_ORDERS = weakref.WeakKeyDictionary()


def _interval_addresses(module):
    return {interval.uuid: interval.address for interval in module.byte_intervals}


def remember_input_order(module: gtirb.Module):
    """Record the section order and addresses of the module as it is now, before any rewrite."""
    _dependency()
    if module not in _ORDERS:
        _ORDERS[module] = _ModuleOrder(module)


def _ordered_intervals(section, addresses, dependency):
    # One interval per section is the rule. Otherwise keep the order of the
    # last deterministic layout, and gtirb-layout's rule that a fallthrough
    # source interval comes right before its target.
    intervals = sorted(section.byte_intervals, key=lambda interval: (
        addresses.get(interval.uuid) is None, addresses.get(interval.uuid) or 0, interval.uuid.int))
    ordered, seen = [], set()
    for interval in intervals:
        chain = []
        while interval is not None and interval not in seen:
            seen.add(interval)
            chain.append(interval)
            interval = dependency.predecessor(interval)
        ordered.extend(reversed(chain))
    return ordered


def _start_requirement(interval, alignment, reference, dependency):
    """The (modulus, residue) the interval's start address must have."""
    if alignment and (interval in alignment or any(block in alignment for block in interval.blocks)):
        return dependency.alignment_requirement(interval, alignment)
    if reference is None:
        return 1, 0
    # gtirb-layout's inference: the first block, in its block order, whose
    # address before the layout is aligned to 2, 4, 8 or 16 keeps that alignment.
    inferred = [block for block in interval.blocks
                if dependency.default_alignment(reference + block.offset) is not None]
    if not inferred:
        return 1, 0
    anchor = min(inferred, key=dependency.block_sort_key)
    boundary = dependency.default_alignment(reference + anchor.offset)
    return boundary, -anchor.offset % boundary


def _layout(module, order, dependency):
    # As gtirb-rewriting does before laying out: integral symbols that point
    # into an interval move with it.
    dependency.assign_integral_symbols(module)
    table = module.aux_data.get("alignment")
    alignment = table.data if table is not None else {}
    address = 0
    for section in sorted(module.sections, key=lambda section: order.ranks[section.uuid]):
        for interval in _ordered_intervals(section, order.addresses, dependency):
            reference = order.addresses.get(interval.uuid, interval.address)
            modulus, residue = _start_requirement(interval, alignment, reference, dependency)
            address += (residue - address) % modulus
            interval.address = address
            address += interval.size


def settle_layout(module: gtirb.Module):
    """Lay the module out in the fixed order if a layout is due or the rewriter made one."""
    dependency = _dependency()
    remember_input_order(module)
    order = _ORDERS[module]
    order.add_new_sections(module)
    if order.addresses != _interval_addresses(module) or dependency.is_module_layout_required(module):
        _layout(module, order, dependency)
        order.addresses = _interval_addresses(module)


class DeterministicLayoutPass(Pass):
    """Add last to a round's PassManager; see the module docstring."""

    def begin_module(self, module, functions, rewriting_ctx) -> None:
        settle_layout(module)

    def end_module(self, module, functions) -> None:
        settle_layout(module)
