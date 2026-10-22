"""Explicit RV Linux ABI profiles; LP64D remains the default.

Pure code uses the toolchain's integer defaults and a simple objdump check.
"""
import re
import subprocess

DEFAULT = "lp64d"
PURE = "lp64-pure"
PROFILES = (DEFAULT, PURE)
PURE_ABI = {"riscv.calling_abi": "lp64", "riscv.profile": PURE,
            "riscv.fp_policy": "fp-free-fail-closed"}
INTERPRETERS = {DEFAULT: "/lib/ld-linux-riscv64-lp64d.so.1",
                PURE: "/lib/ld-linux-riscv64-lp64.so.1"}
# GCC's canonical decompositions of A/M/C are equivalent, not new hardware.
EXTENSIONS = frozenset({"i", "m", "a", "c", "zicsr", "zifencei", "zicond",
                        "zmmul", "zaamo", "zalrsc", "zca"})


class RiscvProfileError(ValueError):
    """An explicitly selected RISC-V profile cannot be established."""


def profile_name(value=DEFAULT):
    if value not in PROFILES:
        raise RiscvProfileError("unknown RISC-V profile: " + str(value))
    return value


def validate_flags(flags, profile=DEFAULT):
    profile_name(profile)
    if type(flags) is not int or flags < 0:
        raise RiscvProfileError("RISC-V ELF flags must be a nonnegative integer")
    expected = 0 if profile == PURE else 4
    if flags & ~5 or flags & 6 != expected:
        raise RiscvProfileError("RV64 %s required, with optional RVC and no unknown ABI bits" %
                         ("LP64" if profile == PURE else "LP64D"))
    return flags


def validate_arch_string(text):
    """Validate a canonical/versioned ELF attribute against the card ISA."""
    if not isinstance(text, str) or not text.startswith("rv64"):
        raise RiscvProfileError("pure profile requires RV64 architecture attributes")
    pieces = text[4:].lower().split("_")
    first = pieces.pop(0)
    # Both rv64imac and rv64i2p1_m2p0... are assembler spellings.
    base = re.fullmatch(r"([imac]+)(?:[0-9]+p[0-9]+)?", first)
    if base is None or base[1][0] != "i":
        raise RiscvProfileError("unsupported pure RISC-V base ISA: " + text)
    extensions = set(base[1])
    for piece in pieces:
        match = re.fullmatch(r"([a-z][a-z0-9]*?)(?:[0-9]+p[0-9]+)?", piece)
        if match is None:
            raise RiscvProfileError("malformed RISC-V architecture attribute: " + text)
        extensions.add(match[1])
    if extensions - EXTENSIONS:
        raise RiscvProfileError("unapproved pure RISC-V extensions: " + ", ".join(sorted(extensions - EXTENSIONS)))
    return frozenset(extensions)


def _uleb(data, position, limit):
    value, shift = 0, 0
    while position < limit and shift < 64:
        byte = data[position]; position += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, position
        shift += 7
    raise RiscvProfileError("truncated RISC-V attribute integer")


def _string(data, position, limit):
    end = data.find(b"\0", position, limit)
    if end < 0:
        raise RiscvProfileError("unterminated RISC-V attribute string")
    try:
        return data[position:end].decode("ascii"), end + 1
    except UnicodeDecodeError as error:
        raise RiscvProfileError("non-ASCII RISC-V attribute") from error


def validate_arch_attribute_record(elf, require=True):
    """Validate attributes and retain informational privilege-spec values."""
    section = elf.get_section_by_name(".riscv.attributes")
    if section is None:
        if require:
            raise RiscvProfileError("pure profile requires .riscv.attributes")
        return {"architectures": [], "integer_attributes": {}, "priv_spec": {}}
    data = section.data()
    if not data or data[0] != 65:
        raise RiscvProfileError("unsupported RISC-V attribute format")
    position, architectures, integers = 1, [], {}
    while position < len(data):
        start = position
        if position + 4 > len(data):
            raise RiscvProfileError("truncated RISC-V attribute vendor")
        end = start + int.from_bytes(data[position:position + 4], "little")
        if end > len(data) or end <= start + 4:
            raise RiscvProfileError("invalid RISC-V attribute vendor extent")
        vendor, position = _string(data, position + 4, end)
        if vendor != "riscv":
            raise RiscvProfileError("unknown RISC-V attribute vendor: " + vendor)
        while position < end:
            substart = position
            tag, position = _uleb(data, position, end)
            if tag != 1 or position + 4 > end:
                raise RiscvProfileError("unsupported RISC-V attribute scope")
            subend = substart + int.from_bytes(data[position:position + 4], "little")
            position += 4
            if subend > end or subend < position:
                raise RiscvProfileError("invalid RISC-V attribute scope extent")
            while position < subend:
                attribute, position = _uleb(data, position, subend)
                if attribute & 1:
                    value, position = _string(data, position, subend)
                    if attribute != 5:
                        raise RiscvProfileError("unknown string RISC-V attribute: " + str(attribute))
                    validate_arch_string(value); architectures.append(value)
                else:
                    value, position = _uleb(data, position, subend)
                    if attribute not in (4, 6, 8, 10, 12, 14, 16, 18):
                        raise RiscvProfileError("unknown integer RISC-V attribute: " + str(attribute))
                    if attribute == 4 and value != 16:
                        raise RiscvProfileError("pure LP64 requires 16-byte stack alignment")
                    if attribute in integers and integers[attribute] != value:
                        raise RiscvProfileError("conflicting RISC-V integer attribute: " + str(attribute))
                    integers[attribute] = value
            if position != subend:
                raise RiscvProfileError("RISC-V attribute desynchronization")
        if position != end:
            raise RiscvProfileError("RISC-V vendor attribute desynchronization")
    if not architectures or len(set(architectures)) != 1:
        raise RiscvProfileError("missing or conflicting RISC-V architecture attributes")
    return {"architectures": architectures,
            "integer_attributes": {str(tag): value for tag, value in sorted(integers.items())},
            "priv_spec": {name: integers[tag] for tag, name in
                          ((8, "major"), (10, "minor"), (12, "revision")) if tag in integers}}


def validate_arch_attributes(elf, require=True):
    """Compatibility API for callers needing only validated arch strings."""
    return validate_arch_attribute_record(elf, require)["architectures"]


def validate_elf_header(elf, *, role="object", profile=PURE):
    profile_name(profile)
    if elf["e_machine"] != "EM_RISCV" or elf.elfclass != 64 or not elf.little_endian:
        raise RiscvProfileError("pure RISC-V profile requires little-endian ELF64 EM_RISCV")
    validate_flags(elf["e_flags"], profile)
    if role == "object" and elf["e_type"] != "ET_REL":
        raise RiscvProfileError("pure object must be ET_REL")
    if role == "executable":
        if elf["e_type"] not in ("ET_EXEC", "ET_DYN"):
            raise RiscvProfileError("pure executable must be ET_EXEC or PIE ET_DYN")
        try:
            interpreters = [segment.data().split(b"\0", 1)[0].decode("ascii")
                            for segment in elf.iter_segments() if segment["p_type"] == "PT_INTERP"]
        except UnicodeDecodeError as error:
            raise RiscvProfileError("non-ASCII RISC-V executable interpreter") from error
        if interpreters and interpreters != [INTERPRETERS[profile]]:
            raise RiscvProfileError("pure executable has another interpreter: " + repr(interpreters))
    elif role in ("selected", "external") and elf["e_type"] != "ET_DYN":
        raise RiscvProfileError("pure provider must be ET_DYN")
    elif role not in ("object", "selected", "external"):
        raise RiscvProfileError("unknown pure ELF role: " + str(role))
    if role == "selected" and any(segment['p_type'] == 'PT_INTERP'
                                   for segment in elf.iter_segments()):
        raise RiscvProfileError('selected pure library is an executable with PT_INTERP, not a DSO')
    if profile == PURE:
        validate_arch_attributes(elf)


def validate_compiler(compiler):
    """Check, never change, the compiler's default ABI and card ISA."""
    run = subprocess.run([str(compiler), "-dM", "-E", "-x", "c", "/dev/null"],
                         capture_output=True, text=True, check=True)
    macros = dict(re.findall(r"^#define\s+(\S+)\s+(.*)$", run.stdout, re.M))
    if macros.get("__riscv_xlen") != "64" or "__riscv_float_abi_soft" not in macros:
        raise RiscvProfileError("pure profile needs the compiler's RV64 LP64 default")
    forbidden = {"__riscv_flen", "__riscv_f", "__riscv_d", "__riscv_q", "__riscv_v",
                 "__riscv_zfh", "__riscv_zfhmin", "__riscv_zfa", "__riscv_zba",
                 "__riscv_zbb", "__riscv_zbc", "__riscv_zbs"}
    if forbidden & macros.keys():
        raise RiscvProfileError("pure compiler enables unapproved extensions: " +
                         ", ".join(sorted(forbidden & macros.keys())))
    return {key: macros[key] for key in sorted(macros) if key.startswith("__riscv")}




def objdump_for(compiler):
    """Use the selected GCC toolchain's sibling objdump."""
    compiler = str(compiler)
    if not compiler.endswith("gcc"):
        raise RiscvProfileError("specify a GCC toolchain driver for pure components")
    return compiler[:-3] + "objdump"
