"""Names by which patch assembly refers to an existing symbol.

Teapot writes the code it inserts as assembly text, and gtirb-rewriting's
assembler resolves each name in it with ``next(module.symbols_named(name))``.
When several symbols share a name, that is whichever comes first in a set
ordered by object identity, not necessarily the symbol the text was written
for. Input modules have such names: every translation unit's ``.LC0``, its
static variables and its static functions. A memory-log address, a policy or
DIFT address capture, or a rewritten application access could then address
another object.

Text that names an existing symbol therefore uses :func:`reference_name` or
:func:`reference_expression`. A symbol keeps its name while all symbols of that
name resolve alike: the same place, or the same external, with the same ELF
symbol entry (binding, type, visibility, section, size), the same complete
version and the same forwarding target. Otherwise a LOCAL symbol referred to by
its address gets an alias at exactly its place, named from its UUID, which no
other symbol has. Any other reference to a shared name is refused
(AmbiguousReferenceError): to an external, to a GLOBAL, WEAK, versioned,
forwarded, thread-local or GNU_IFUNC symbol, or through a GOT, PLT or TLS
relocation. The symbol's linker identity, not only its address, decides what
such a reference reaches, and a local alias would have another. A module
without shared names gets the same text and no new symbols.
"""
import uuid
from typing import Iterable

import gtirb

from teapot.utils.misc import generate_distinct_label_name

ALIAS_PREFIX = ".L__teapot_symbol"

_ATTRIBUTE = gtirb.SymbolicExpression.Attribute
# Relocations whose result depends on the symbol's linker identity (its GOT or
# PLT entry, its dynamic binding, its thread-local storage), not only on its
# address.
_IDENTITY_ATTRIBUTES = frozenset({
    _ATTRIBUTE.GOT, _ATTRIBUTE.GOTPC, _ATTRIBUTE.GOTOFF, _ATTRIBUTE.GOTREL, _ATTRIBUTE.GOTNTPOFF,
    _ATTRIBUTE.PLT, _ATTRIBUTE.PLTOFF,
    _ATTRIBUTE.TLS, _ATTRIBUTE.TLSGD, _ATTRIBUTE.TLSLD, _ATTRIBUTE.TLSLDM, _ATTRIBUTE.TLSLDO, _ATTRIBUTE.TLSCALL,
    _ATTRIBUTE.TLSDESC, _ATTRIBUTE.TPREL, _ATTRIBUTE.TPOFF, _ATTRIBUTE.NTPOFF, _ATTRIBUTE.INDNTPOFF,
    _ATTRIBUTE.DTPREL, _ATTRIBUTE.DTPOFF, _ATTRIBUTE.DTPMOD,
})
# Symbol types whose address is what a plain reference means.
_ORDINARY_TYPES = frozenset({"NOTYPE", "OBJECT", "FUNC"})
# ELF section indices of undefined and COMMON symbols; DDisasm gives both a proxy block.
_SHN_UNDEF, _SHN_COMMON = 0, 0xfff2


class AmbiguousReferenceError(ValueError):
    """Patch text cannot name the symbol: its name also denotes a symbol that resolves differently."""


def _aux(module: gtirb.Module, name: str):
    table = module.aux_data.get(name)
    return table.data if table is not None else None


def _elf_info(symbol: gtirb.Symbol):
    info = _aux(symbol.module, "elfSymbolInfo")
    return info.get(symbol) if info is not None else None


def _version(symbol: gtirb.Symbol):
    """The symbol's ELF version name (or number), or None."""
    versions = _aux(symbol.module, "elfSymbolVersions")
    if versions is None or symbol not in versions[2]:
        return None
    definitions, needed, entries = versions
    number = entries[symbol][0]
    for library in needed.values():
        if number in library:
            return library[number]
    if number in definitions and definitions[number][0]:
        return definitions[number][0][0]
    return number


def _version_identity(symbol: gtirb.Symbol):
    """The symbol's complete ELF version, or None: the version's index and whether it is hidden (not the default),
    the libraries it is needed from with the version's name in each, and the names and flags of the version the
    module defines under that index."""
    versions = _aux(symbol.module, "elfSymbolVersions")
    if versions is None or symbol not in versions[2]:
        return None
    definitions, needed, entries = versions
    index, hidden = entries[symbol]
    libraries = tuple(sorted((library, names[index]) for library, names in needed.items() if index in names))
    definition = definitions.get(index)
    return (index, bool(hidden), libraries,
            (tuple(definition[0]), definition[1]) if definition is not None else None)


def _forwarded_to(symbol: gtirb.Symbol):
    forwarding = _aux(symbol.module, "symbolForwarding")
    return forwarding.get(symbol) if forwarding is not None else None


def _common(symbol: gtirb.Symbol) -> bool:
    entry = _elf_info(symbol)
    return isinstance(symbol.referent, gtirb.ProxyBlock) and entry is not None and entry[4] == _SHN_COMMON


def _resolution(symbol: gtirb.Symbol):
    """What a reference to ``symbol`` reaches and how the linker binds it: its place (or external name), its complete
    ELF symbol entry, its complete version and its forwarding target. References to symbols of equal resolution are
    interchangeable, also through a GOT, PLT or TLS relocation."""
    entry = _elf_info(symbol)
    forwarded = _forwarded_to(symbol)
    linkage = (tuple(entry) if entry is not None else None, _version_identity(symbol),
               forwarded.uuid if forwarded is not None else None)
    referent = symbol.referent
    if isinstance(referent, gtirb.ProxyBlock):
        # Externals are resolved by name (and version) at link time.
        return ("external", symbol.name, *linkage)
    if referent is None:
        return ("value", symbol.value, *linkage)
    return ("block", referent, symbol.at_end, *linkage)


def _not_aliasable(symbol: gtirb.Symbol, attributes) -> str:
    """Why a local alias of ``symbol`` would not reach what the reference reaches, or '' if it would."""
    referent = symbol.referent
    if _common(symbol):
        return "is a COMMON definition, which has no place in the module for an alias"
    if isinstance(referent, gtirb.ProxyBlock):
        return "is external (an alias of an external would be another external)"
    if referent is None and symbol.value is None:
        return "has neither a place nor a value"
    entry = _elf_info(symbol)
    if entry is not None and entry[2] != "LOCAL":
        return f"is {entry[2]} (an alias would not be bound like it)"
    if entry is not None and entry[1] not in _ORDINARY_TYPES:
        return f"is a {entry[1]} symbol"
    section = getattr(getattr(referent, "byte_interval", None), "section", None)
    if section is not None and gtirb.Section.Flag.ThreadLocal in section.flags:
        return "is thread-local"
    if _version(symbol) is not None:
        return f"has the version {_version(symbol)}"
    if _forwarded_to(symbol) is not None:
        return f"forwards to {_forwarded_to(symbol).name}"
    identity = sorted(attribute.name for attribute in _IDENTITY_ATTRIBUTES & set(attributes))
    if identity:
        return f"is referred to by a {'/'.join(identity)} relocation, which depends on its linker identity"
    return ""


def _describe(symbol: gtirb.Symbol) -> str:
    entry = _elf_info(symbol)
    kind = (f"{entry[2]}{'' if entry[3] == 'DEFAULT' else ' ' + entry[3]} {entry[1]} symbol"
            if entry is not None else "symbol")
    version = _version(symbol)
    if version is not None:
        kind += f" of version {version}{' (hidden)' if _version_identity(symbol)[1] else ''}"
    forwarded = _forwarded_to(symbol)
    if forwarded is not None:
        kind += f" forwarding to {forwarded.name}"
    referent = symbol.referent
    if _common(symbol):
        return f"a COMMON definition, a {kind}"
    if isinstance(referent, gtirb.ProxyBlock):
        return f"an undefined {kind}"
    if referent is None:
        return f"an absolute {kind} = {symbol.value:#x}" if symbol.value is not None else f"a {kind} without a place"
    section = getattr(getattr(referent.byte_interval, "section", None), "name", "?") \
        if isinstance(referent, gtirb.ByteBlock) and referent.byte_interval is not None else "?"
    address = getattr(referent, "address", None)
    if address is None:
        return f"a {kind} in {section}"
    return f"a {kind} in {section} at {address + (referent.size if symbol.at_end else 0):#x}"


def _alias(symbol: gtirb.Symbol) -> gtirb.Symbol:
    """The alias of ``symbol``: a symbol at exactly its place, named and numbered from its UUID."""
    module = symbol.module
    name = generate_distinct_label_name(ALIAS_PREFIX, symbol.uuid)
    # The input symbol's UUID names the alias and derives its UUID, so a
    # rewrite prints and serializes the same text in every run.
    alias_uuid = uuid.uuid5(symbol.uuid, "teapot-copy:reference:alias")
    payload = symbol.referent if symbol.referent is not None else symbol.value
    existing = list(module.symbols_named(name))
    if existing:
        # Only the alias made earlier for this symbol may be reused.
        alias = existing[0]
        if (len(existing) == 1 and alias.uuid == alias_uuid and alias.referent is symbol.referent and
                alias.value == symbol.value and alias.at_end == symbol.at_end):
            return alias
        raise AmbiguousReferenceError(
            f"cannot alias {symbol.name!r}: {len(existing)} symbol(s) already have the name {name!r}, which "
            f"Teapot reserves for its alias: {'; '.join(_describe(other) for other in existing)}")
    ir = module.ir
    if ir is not None and ir.get_by_uuid(alias_uuid) is not None:
        raise AmbiguousReferenceError(
            f"cannot alias {symbol.name!r}: another node already has its alias UUID {alias_uuid}")
    return gtirb.Symbol(name=name, uuid=alias_uuid, payload=payload, at_end=symbol.at_end, module=module)


def reference_symbol(symbol: gtirb.Symbol, attributes: Iterable = ()) -> gtirb.Symbol:
    """A symbol whose name the patch assembler resolves to what a reference to ``symbol`` reaches.

    ``attributes`` are the reference's relocation attributes (its expression's).
    """
    module = symbol.module
    if module is None:
        return symbol
    resolution = _resolution(symbol)
    peers = [other for other in module.symbols_named(symbol.name) if _resolution(other) != resolution]
    if not peers:
        return symbol
    reason = _not_aliasable(symbol, attributes)
    if reason:
        others = sorted(peers, key=lambda other: other.uuid.bytes)
        raise AmbiguousReferenceError(
            f"cannot refer to {symbol.name!r}, {_describe(symbol)}, by name: the name also denotes "
            f"{'; '.join(_describe(other) for other in others)}. Teapot aliases only a LOCAL symbol "
            f"referred to by its address, but this one {reason}")
    return _alias(symbol)


def reference_name(symbol: gtirb.Symbol, attributes: Iterable = ()) -> str:
    """The name to print for ``symbol`` in patch text: see the module docstring."""
    return reference_symbol(symbol, attributes).name


def reference_expression(expression):
    """``expression`` with every symbol replaced by its reference symbol, for printing only."""
    if isinstance(expression, gtirb.SymAddrConst):
        symbol = reference_symbol(expression.symbol, expression.attributes)
        if symbol is expression.symbol:
            return expression
        return gtirb.SymAddrConst(expression.offset, symbol, expression.attributes)
    if isinstance(expression, gtirb.SymAddrAddr):
        first = reference_symbol(expression.symbol1, expression.attributes)
        second = reference_symbol(expression.symbol2, expression.attributes)
        if first is expression.symbol1 and second is expression.symbol2:
            return expression
        return gtirb.SymAddrAddr(expression.scale, expression.offset, first, second, expression.attributes)
    return expression
