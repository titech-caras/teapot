"""Refuse a program that uses the names of the runtime it will be linked with.

The rewritten program refers to the runtime by name: Teapot's code to the
architecture's checkpoint_lib_symbols and the contract anchor, which
ImportSymbolsPass imports, and the program's own calls of some external
functions to the runtime's wrappers, which DiftExtCallPass redirects them to
(TeapotPipeline.runtime_names). The rewriter binds each such name to the
module's symbol of that name. A program that defines one, such as a static
variable called scratchpad, would have the instrumentation use its object
instead of the runtime's. Such a program is refused before anything is
rewritten, not renamed around. Every symbol of such a name counts, whatever its
binding, type or section, and a value (absolute) symbol too.

A program that only refers to such a name (an undefined, imported symbol) is
refused too: after the final link its references would reach the runtime's
object, whichever library it expected the name from. No supported program
imports the runtime, which is a static archive linked into the rewritten
program. The archive-derived manifest (teapot/runtime_exports.json) also reserves
defined globals that emitted instrumentation never imports, including hidden
helpers and names of other supported runtime modes and ISAs. It is loaded by
the shared whole-program/component preflight, with no missing-file fallback.
The Sanitizer Coverage hooks are the exception (COVERAGE_HOOK_SYMBOLS):
a program compiled with -fsanitize-coverage calls them, and the fuzzer runtime
linked at the end provides them, as the coverage runtime expects. Teapot's code
then calls them through the program's import, which gtirb-rewriting reuses, so
only a plain import like Teapot's own is accepted: undefined, GLOBAL, DEFAULT,
a function (or NOTYPE), without a version or forwarding, and several imports of
a hook only with the same ELF symbol entry. A COMMON symbol is a definition,
although DDisasm gives it a proxy block like an import. A program that defines
the hooks, carrying its own fuzzer runtime, is refused.

The names of the symbols Teapot generates are reserved too (``generated``;
is_generated_name in teapot/configs/runtime.py): its labels and copies, section
and guard bounds, the aliases by which patch text refers to a symbol of a
shared name, the contract record and anchors, the AArch64 BTI bounds and PAC
marker, and the wrappers. Teapot finds and refers to its symbols by these
names, so it could take a program's symbol of such a name for its own. The
component driver refuses its inputs by the same rule.
"""
from typing import Callable, Iterable, List, Optional, Tuple

import gtirb


# The ELF section indices of undefined and COMMON symbols, which DDisasm both gives proxy blocks.
SHN_UNDEF, SHN_COMMON = 0, 0xfff2
# The types of a plain import of an interface: Teapot's own is a FUNC (gtirb-rewriting's
# get_or_insert_extern_symbol); an undefined reference compiled from C may be NOTYPE.
INTERFACE_IMPORT_TYPES = ("FUNC", "NOTYPE")


class RuntimeNameError(ValueError):
    """The program uses a name of the Teapot runtime."""


def _entry(module: gtirb.Module, symbol: gtirb.Symbol):
    info = module.aux_data.get("elfSymbolInfo")
    return info.data.get(symbol) if info is not None else None


def _undefined(module: gtirb.Module, symbol: gtirb.Symbol) -> bool:
    """Whether the symbol is an import: a proxy block, or no place or value, and by its ELF entry, if it has one,
    in no section. A COMMON symbol is a definition."""
    if not (isinstance(symbol.referent, gtirb.ProxyBlock) or (symbol.referent is None and symbol.value is None)):
        return False
    entry = _entry(module, symbol)
    return entry is None or entry[4] == SHN_UNDEF


def _forwarded_to(module: gtirb.Module, symbol: gtirb.Symbol):
    forwarding = module.aux_data.get("symbolForwarding")
    return forwarding.data.get(symbol) if forwarding is not None else None


def _version(module: gtirb.Module, symbol: gtirb.Symbol):
    """The symbol's ELF version name (or number), or None if it has no version."""
    versions = module.aux_data.get("elfSymbolVersions")
    if versions is None or symbol not in versions.data[2]:
        return None
    definitions, needed, entries = versions.data
    number = entries[symbol][0]
    for library in needed.values():
        if number in library:
            return library[number]
    if number in definitions and definitions[number][0]:
        return definitions[number][0][0]
    return number


def _noncanonical(module: gtirb.Module, symbol: gtirb.Symbol) -> str:
    """Why an import of an interface is not a plain one like Teapot's own, or ''."""
    entry = _entry(module, symbol)
    if entry is None:
        return "it has no ELF symbol entry"
    _, kind, binding, visibility, _ = entry
    if binding != "GLOBAL":
        return f"it is {binding}"
    if visibility != "DEFAULT":
        return f"it is {visibility}"
    if kind not in INTERFACE_IMPORT_TYPES:
        return f"it is a {kind} symbol"
    if _version(module, symbol) is not None:
        return f"it has the version {_version(module, symbol)}"
    forwarded = _forwarded_to(module, symbol)
    if forwarded is not None:
        return f"it forwards to {forwarded.name}"
    return ""


def _describe(module: gtirb.Module, symbol: gtirb.Symbol, runtime: bool = True) -> str:
    version = _version(module, symbol)
    versioned = f" of version {version}" if version is not None else ""
    if _undefined(module, symbol):
        return (f"{symbol.name}: an undefined reference{versioned}" +
                (", which the final link would resolve to the runtime's own symbol" if runtime else ""))
    entry = _entry(module, symbol)
    kind = (f"{entry[2]}{'' if entry[3] == 'DEFAULT' else ' ' + entry[3]} {entry[1]} symbol{versioned}"
            if entry is not None else f"symbol{versioned}")
    referent = symbol.referent
    if isinstance(referent, gtirb.ProxyBlock):
        if entry[4] == SHN_COMMON:
            return f"{symbol.name}: a COMMON definition, a {kind} of size {entry[0]}"
        return f"{symbol.name}: a {kind} without a place in the module, in section {entry[4]:#x}"
    if referent is None:
        return f"{symbol.name}: an absolute {kind} with value {symbol.value:#x}"
    interval = getattr(referent, "byte_interval", None)
    section = interval.section.name if interval is not None and interval.section is not None else "?"
    address = referent.address
    if address is None:
        offset = referent.offset + (referent.size if symbol.at_end else 0)
        return f"{symbol.name}: a {kind} in {section}, at offset {offset:#x} of a byte interval without an address"
    return f"{symbol.name}: a {kind} in {section} at {address + (referent.size if symbol.at_end else 0):#x}"


def runtime_name_uses(module: gtirb.Module, names: Iterable[str],
                      interfaces: Iterable[str] = ()) -> List[Tuple[gtirb.Symbol, str]]:
    """The module's symbols that use the runtime ``names``, with where they are.

    Every symbol of those names counts, defined or undefined, except plain imports of one of ``interfaces``: each
    like Teapot's own (_noncanonical), and all imports of the name with the same ELF symbol entry.
    """
    interfaces = frozenset(interfaces)
    uses = []
    for name in dict.fromkeys(names):
        symbols = sorted(module.symbols_named(name), key=lambda symbol: symbol.uuid.bytes)
        if name not in interfaces:
            uses += [(symbol, _describe(module, symbol)) for symbol in symbols]
            continue
        imports = [symbol for symbol in symbols if _undefined(module, symbol)]
        plain = [symbol for symbol in imports if not _noncanonical(module, symbol)]
        entries = {tuple(_entry(module, symbol)) for symbol in plain}
        for symbol in symbols:
            if symbol not in imports:
                uses.append((symbol, _describe(module, symbol)))
            elif _noncanonical(module, symbol):
                uses.append((symbol, f"{_describe(module, symbol, runtime=False)}, which is not a plain import "
                                     f"like Teapot's own: {_noncanonical(module, symbol)}"))
            elif len(entries) > 1:
                uses.append((symbol, f"{_describe(module, symbol, runtime=False)} with the ELF symbol entry "
                                     f"{tuple(_entry(module, symbol))}, one of {len(plain)} imports of the name "
                                     "with different entries"))
    return uses


def generated_name_uses(module: gtirb.Module, generated: Callable[[str], bool]) -> List[Tuple[gtirb.Symbol, str]]:
    """The module's symbols with names that ``generated`` reserves for the symbols Teapot generates."""
    return [(symbol, _describe(module, symbol, runtime=False))
            for symbol in sorted(module.symbols, key=lambda symbol: symbol.uuid.bytes) if generated(symbol.name)]


def refuse_runtime_names(module: gtirb.Module, names: Iterable[str], interfaces: Iterable[str] = (),
                         generated: Optional[Callable[[str], bool]] = None) -> None:
    """Raise RuntimeNameError if the module uses one of the runtime ``names``, or a name ``generated`` reserves."""
    uses = runtime_name_uses(module, names, interfaces)
    listed = {symbol for symbol, _ in uses}
    reserved = [(symbol, description) for symbol, description in
                (generated_name_uses(module, generated) if generated is not None else ())
                if symbol not in listed]
    if not uses and not reserved:
        return
    parts = []
    if uses:
        parts.append("names of the Teapot runtime, so Teapot's references to the runtime would reach the "
                     "program's symbols or the program's references the runtime's:\n  " +
                     "\n  ".join(description for _, description in uses))
    if reserved:
        parts.append("names reserved for the symbols Teapot generates (teapot/configs/runtime.py), which Teapot "
                     "could take for its own:\n  " + "\n  ".join(description for _, description in reserved))
    raise RuntimeNameError(f"module {module.name!r} uses " + "\nand ".join(parts) +
                           "\nRename them in the program and rebuild it.")
