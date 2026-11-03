"""Symbol names the assembler can read back."""
import gtirb


def _unprintable(name: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7f for character in name)


def rename_unprintable_symbols(module: gtirb.Module) -> int:
    """Give printable names to symbols whose names contain control characters.

    GAS names a numeric local label such as ``1:`` ``.L1\\x02<n>``. RISC-V keeps
    those labels for linker relaxation, so a binary linked with --emit-relocs
    still has them, and DDisasm uses them as branch targets. The printed
    assembly cannot spell such a name. Returns how many were renamed.
    """
    taken = {symbol.name for symbol in module.symbols}
    targets = sorted((symbol for symbol in module.symbols if _unprintable(symbol.name)),
                     key=lambda symbol: (symbol.name, getattr(symbol.referent, "address", None) or 0,
                                         str(symbol.uuid)))
    index = 0
    for symbol in targets:
        while f".L_teapot_local_{index}" in taken:
            index += 1
        symbol.name = f".L_teapot_local_{index}"
        taken.add(symbol.name)
    return len(targets)
