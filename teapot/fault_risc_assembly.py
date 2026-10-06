"""Scope RV assembler options around exactly the emitter-owned cold stubs.

This consumes matching GTIRB plus ordinary assembler output before assembly. It
does not edit instructions, relocations, ELF files, original/copy load bytes or
any text outside the two zero-byte boundaries of each recorded stub.
"""
import argparse
from pathlib import Path
import re
import struct

import gtirb

AUX = "teapotFaultRiscAssemblyScopes"
SCHEMA = "mapping<UUID,UUID>"
PREFIX = "__teapot_fault_rv_scope_"
_NAME = re.compile(re.escape(PREFIX) + r"(begin|end)_([0-9a-f]{32})\Z")
_LABEL = re.compile(r"\s*(" + re.escape(PREFIX) + r"(?:begin|end)_[0-9a-f]{32}):\s*\Z")
_SECTION = re.compile(r"\s*\.(section|pushsection)\s+([^,\s]+)")
_SECTION_CHANGE = re.compile(r"\s*\.(?:section|pushsection|popsection|previous|subsection|text|data|bss)\b")
_OPTION = re.compile(r"\s*\.option\s+([^#;\s]+)\s*(?:#.*)?\Z")
_INSERT = ".option push\n.option norvc\n.option norelax\n"


def _scope_markers(module):
    marked = [symbol for symbol in module.symbols if symbol.name.startswith(PREFIX)]
    aux = module.aux_data.get(AUX)
    if aux is None:
        if marked:
            raise ValueError("RV fault scope symbols have no ownership metadata")
        return {}
    arch = module.aux_data.get("archInfo")
    is_rv = module.isa.name == "RISCV64" or (module.isa == gtirb.Module.ISA.ValidButUnsupported and
             arch is not None and isinstance(arch.data, dict) and arch.data.get("ISA") == "RISCV64")
    if (not is_rv or aux.type_name != SCHEMA or
            not isinstance(aux.data, dict) or not aux.data):
        raise ValueError("invalid RV fault scope metadata/ISA")
    owned, spans = {}, []
    info = module.aux_data.get("elfSymbolInfo")
    if info is None:
        raise ValueError("RV fault scope has no ELF symbol binding metadata")
    for begin, end in aux.data.items():
        if not all(isinstance(symbol, gtirb.Symbol) and symbol.module is module for symbol in (begin, end)):
            raise ValueError("RV fault scope does not name this module's symbols")
        bm, em = _NAME.fullmatch(begin.name), _NAME.fullmatch(end.name)
        if not bm or not em or bm[1] != "begin" or em[1] != "end" or bm[2] != em[2]:
            raise ValueError("malformed or mismatched RV fault scope identities")
        for symbol in (begin, end):
            block = symbol.referent
            binding = info.data.get(symbol)
            if (not isinstance(binding, tuple) or len(binding) != 5 or binding[2] != "LOCAL" or
                    symbol.name in owned or symbol.at_end or not isinstance(block, gtirb.ByteBlock) or
                    block.section is None or block.section.name != ".teapot_transient" or
                    block.address is None or block.address & 1):
                raise ValueError("invalid RV fault scope boundary")
        if begin.referent.section is not end.referent.section or begin.referent.address >= end.referent.address:
            raise ValueError("empty, reversed or cross-section RV fault scope")
        owned[begin.name], owned[end.name] = end.name, begin.name
        spans.append((begin.referent.address, end.referent.address))
    spans.sort()
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise ValueError("overlapping RV fault scopes")
    if len(marked) != len(owned) or {s.name for s in marked} != set(owned):
        raise ValueError("duplicate or unowned RV fault scope symbols")
    return owned


def fault_risc_assembler_flags(module):
    """Compiler-driver flags for checked, emitter-owned RV v4 output only.

    GNU as may otherwise append padding beyond the final aligned end marker.
    This is not a relaxation switch; all other output keeps identical argv.
    """
    if not _scope_markers(module):
        return ()
    from teapot.fault_risc import VERSION, ENTRY_SIZE, FLAGS
    from teapot.preprocess.fault_sites import MAGIC, HEADER_SIZE, TABLE_SECTION
    sections = [section for section in module.sections if section.name == TABLE_SECTION]
    if len(sections) != 1 or len(sections[0].byte_intervals) != 1:
        raise ValueError("RV fault assembler flags require one emitted v4 table")
    interval, = sections[0].byte_intervals
    data = interval.contents
    if len(data) < HEADER_SIZE:
        raise ValueError("RV fault assembler flags require a complete v4 header")
    magic, version, header_size, entry_size, count, flags, threshold = struct.unpack_from("<IHHIIII", data)
    if ((magic, version, header_size, entry_size, flags) != (MAGIC, VERSION, HEADER_SIZE, ENTRY_SIZE, FLAGS)
            or not 0 < count <= 1048576 or threshold > 255 or any(data[88:HEADER_SIZE])
            or len(data) != interval.size or len(data) != HEADER_SIZE + count * ENTRY_SIZE):
        raise ValueError("RV fault assembler flags require valid emitted v4 metadata")
    return ("-Wa,--no-pad-sections",)


def emit_fault_risc_scopes(module, assembly):
    owned = _scope_markers(module)
    if not owned:
        if re.search(r"^\s*(?:\.(?:set|equ|equiv)\s+)?" + re.escape(PREFIX), assembly, re.MULTILINE):
            raise ValueError("RV fault scope assembly has no matching IR ownership")
        return assembly                         # disabled output is byte-identical
    section, active, option_depth = None, None, 0
    seen, result = set(), []
    for line in assembly.splitlines(keepends=True):
        stripped = line.strip()
        label = _LABEL.fullmatch(stripped)
        if stripped.startswith(PREFIX) and not label:
            raise ValueError("malformed RV fault scope marker line")
        if re.match(r"\s*\.(?:set|equ|equiv)\s+" + re.escape(PREFIX), line):
            raise ValueError("RV fault scope must be an exact emitted label, not an alias")
        if re.match(r"\s*\.(?:global|globl|weak|weakref|symver)\s+" + re.escape(PREFIX), line):
            raise ValueError("RV fault scope markers must remain LOCAL")
        if label:
            name = label[1]
            if name not in owned or name in seen or section != ".teapot_transient":
                raise ValueError("unexpected, duplicate or wrong-section RV fault scope marker")
            seen.add(name)
            if _NAME.fullmatch(name)[1] == "begin":
                if active or option_depth:
                    raise ValueError("nested RV fault option scope")
                active = name
                result.append(_INSERT)
            else:
                if active is None or owned[active] != name:
                    raise ValueError("unpaired RV fault scope end")
                result.append(".option pop\n")
                active = None
        elif _SECTION_CHANGE.match(line):
            if active:
                raise ValueError("RV fault option scope crosses a section boundary")
            match = _SECTION.match(line)
            section = match[2] if match else None
        elif re.match(r"\s*\.option\b", line):
            option = _OPTION.fullmatch(stripped)
            if active or option is None:
                raise ValueError("nested or malformed assembler option in RV fault scope input")
            if option[1] == "push":
                option_depth += 1
            elif option[1] == "pop":
                if option_depth == 0:
                    raise ValueError("unbalanced assembler option pop")
                option_depth -= 1
        # No directive can hide behind a second statement in an owned span.
        # Pinned printer emits one statement per line; quoted data is raw words.
        if active and (";" in line.split("#", 1)[0] or re.search(r"/\*|\*/", line)):
            raise ValueError("unsupported compound statement/comment in RV fault scope")
        if active and re.match(r"\s*\.(?:include|incbin|macro|endm|irp|irpc|rept|endr|if|ifdef|ifndef|else|elseif|endif|org)\b", line):
            raise ValueError("unsupported assembler control directive in RV fault scope")
        result.append(line)
    if active or seen != set(owned):
        raise ValueError("missing RV fault scope marker; use the matching complete assembler listing")
    return "".join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ir", type=Path)
    parser.add_argument("assembly", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    ir = gtirb.IR.load_protobuf(args.ir)
    if len(ir.modules) != 1:
        parser.error("RV fault assembly preparation requires one ELF module")
    try:
        with args.assembly.open("r", encoding="utf-8", newline="") as stream:
            result = emit_fault_risc_scopes(ir.modules[0], stream.read())
        flags = fault_risc_assembler_flags(ir.modules[0])
    except ValueError as error:
        parser.error(str(error))
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        stream.write(result)
    if flags:
        print("[teapot] RV v4 assembly requires compiler flag: " + " ".join(flags) +
              "; link with -Wl,-z,separate-code and validate the final ELF.", flush=True)


if __name__ == "__main__":
    main()
