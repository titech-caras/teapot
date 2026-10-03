"""Private dependency internals Teapot relies on, and the versions they were inspected at.

requirements.txt allows gtirb>=2.0.0, and the gtirb-rewriting fork accepts
gtirb-layout~=1.0. Two Teapot modules use private parts of those packages, so
they refuse every version but the inspected one. To accept another version,
inspect these parts in it and update INSPECTED_VERSIONS:

- teapot/utils/layout.py reproduces gtirb_rewriting.prepare._layout_module and
  gtirb_layout.layout.layout_module, in a fixed section order. It calls
  gtirb_rewriting.prepare._assign_integral_symbols,
  gtirb_rewriting.intervalutils._alignment_requirement and
  gtirb_layout.layout._block_sort_key, _default_alignment and
  _get_predecessor_byte_interval. It relies on PassManager.run calling every
  pass's begin_module before it applies the round and end_module after it, on
  prepare_for_rewriting laying the module out only when
  gtirb_layout.is_module_layout_required says so, and on split and rejoined
  byte intervals keeping their address.
- teapot/utils/serialization.py (save_protobuf_ordered) writes
  gtirb.IR._to_protobuf() under the header gtirb.IR.save_protobuf_file writes.
"""
import importlib.metadata

INSPECTED_VERSIONS = {
    "gtirb": "2.3.2",
    "gtirb-layout": "1.0.0",
    # lin-toto/gtirb-rewriting e47b9e40b, as requirements.txt and the Dockerfile pin it.
    "gtirb-rewriting": "0.4.2.dev11+ge47b9e40b",
}

_verified = set()


def require_inspected(*names: str) -> None:
    """Fail unless each named package is installed at its inspected version."""
    for name in names:
        if name in _verified:
            continue
        expected = INSPECTED_VERSIONS[name]
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            installed = None
        if installed != expected:
            found = f"{name} {installed} is installed" if installed else f"{name} is not installed"
            raise RuntimeError(
                f"Teapot relies on private parts of {name} {expected}, but {found}. Inspect "
                f"them in that version and update INSPECTED_VERSIONS (teapot/utils/dependencies.py).")
        _verified.add(name)
