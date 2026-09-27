"""Carry ELF source lines through rewriting and emit GNU assembler directives.

Offsets travel in the rewriter's existing, edit-aware comments table. Only after
all instrumentation is finished do we split blocks to attach zero-byte symbols.
No debug symbol can therefore change pass boundaries, liveness or patch placement.
The post-print step uses those symbols, not old addresses or instruction sizes.
"""

from __future__ import annotations

import argparse
import bisect
import json
import posixpath
import re
from pathlib import Path

import gtirb
from elftools.elf.elffile import ELFFile
from gtirb_functions import Function
from gtirb_rewriting import _auxdata_offsetmap
from gtirb_rewriting._modify import make_modify_cache, split_block


_TAG = "TEAPOT_SOURCE_LINE:"
_PREFIX = ".L__teapot_source_"
_AUX = "teapotSourceLines"
_MACHINES = {"x64": "EM_X86_64", "aarch64": "EM_AARCH64", "riscv64": "EM_RISCV"}


def _text(value):
    return value.decode("utf-8", "surrogateescape") if isinstance(value, bytes) else value


def _filename(cu, program, index):
    """pyelftools exposes v4-shaped entries even for DWARF5 line headers."""
    version = program.header["version"]
    files = program.header.get("file_entry", ())
    file_index = index if version >= 5 else index - 1
    if not 0 <= file_index < len(files):
        raise ValueError(f"invalid DWARF{version} file index {index}")
    entry = files[file_index]
    name = _text(entry.name)
    if posixpath.isabs(name):
        return posixpath.normpath(name)
    comp_dir_attr = cu.get_top_DIE().attributes.get("DW_AT_comp_dir")
    comp_dir = _text(comp_dir_attr.value) if comp_dir_attr else ""
    directories = program.header.get("include_directory", ())
    # DWARF5 can omit DW_LNCT_directory_index; pyelftools then supplies None.
    raw_index = entry.dir_index or 0
    directory_index = raw_index if version >= 5 else raw_index - 1
    if raw_index == 0 and (version < 5 or not directories):
        directory = comp_dir
    elif 0 <= directory_index < len(directories):
        directory = posixpath.join(comp_dir, _text(directories[directory_index]))
    else:
        raise ValueError(f"invalid DWARF{version} directory index {raw_index}")
    return posixpath.normpath(posixpath.join(directory, name))


def _line_spans(elf):
    """Yield nonempty address intervals, ending at the sequence terminator.

    Multiple zero-length views at one address collapse to the last row, as in
    an ordinary address-to-line lookup; inline/variable DIEs are not imported.
    """
    dwarf = elf.get_dwarf_info()
    for cu in dwarf.iter_CUs():
        program = dwarf.line_program_for_CU(cu)
        if program is None:
            continue
        previous = None
        # Parsing also populates DW_LNE_define_file entries in DWARF <= 4.
        entries = program.get_entries()
        for entry in entries:
            state = entry.state
            if state is None:
                continue
            if previous is not None and previous.address < state.address:
                if previous.line is not None and previous.line > 0:
                    yield previous.address, state.address, (
                        _filename(cu, program, previous.file), previous.line,
                        previous.column, int(previous.is_stmt), previous.discriminator,
                    )
            previous = None if state.end_sequence else state


class SourceLines:
    """A single module's normal-copy locations, from capture to final labels."""

    def __init__(self, module, elf_path, arch, decoder):
        self.module = module
        self.locations = []
        if _AUX in module.aux_data or any(s.name.startswith(_PREFIX) for s in module.symbols):
            raise ValueError("source-line metadata is already present in this module")
        comments = _auxdata_offsetmap.comments.get(module)
        if comments and any(_TAG in value for value in comments.values()):
            raise ValueError("source-line tracking is already present in this module")

        points = {}
        instructions = {}
        with open(elf_path, "rb") as stream:
            elf = ELFFile(stream)
            if (elf.elfclass != 64 or not elf.little_endian or
                    elf["e_machine"] != _MACHINES[arch] or
                    elf["e_type"] not in ("ET_EXEC", "ET_DYN")):
                raise ValueError("debug ELF must be the original linked ELF64 for this ISA")
            if not elf.has_dwarf_info(strict=True):
                raise ValueError("debug ELF has no DWARF information")
            code_segments = [(segment["p_vaddr"], segment.data())
                             for segment in elf.iter_segments()
                             if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1]
            for start, end, location in _line_spans(elf):
                # GTIRB's interval lookup also handles gaps and overlapping
                # candidate blocks. Never choose a random block with list()[0].
                for block in module.code_blocks_on(range(start, end)):
                    if not block.size or block.address is None:
                        continue
                    if block not in instructions:
                        contents = bytes(block.byte_interval.contents[block.offset:block.offset + block.size])
                        if not any(base <= block.address and
                                   data[block.address-base:block.address-base+block.size] == contents
                                   for base, data in code_segments):
                            raise ValueError("debug ELF code does not match the input GTIRB")
                        decoded = list(decoder.get_instructions(block))
                        instructions[block] = ([i.address - block.address for i in decoded],
                                               {i.address - block.address: i.size for i in decoded})
                    begin = max(start - block.address, 0)
                    finish = min(end - block.address, block.size)
                    offsets, sizes = instructions[block]
                    block_points = points.setdefault(block, {})
                    for offset in offsets[bisect.bisect_left(offsets, begin):bisect.bisect_left(offsets, finish)]:
                        if offset + sizes[offset] <= finish:
                            block_points.setdefault(offset, (sizes[offset], location))

        if not any(points.values()):
            raise ValueError("no DWARF source lines match decoded input instructions")
        comments = _auxdata_offsetmap.comments.get_or_insert(module)
        for block in sorted(points, key=lambda b: (b.address, b.uuid.int)):
            for offset, (size, location) in sorted(points[block].items()):
                index = len(self.locations)
                self.locations.append(location)
                # Anchor the end to the *last byte of this instruction*, not
                # the start of its successor: replacing that successor must
                # not erase the end marker and leak this line into new code.
                for side, at in ((0, offset), (1, offset + size - 1)):
                    token = f"{_TAG}{index}:{side}"
                    key = gtirb.Offset(block, at)
                    existing = comments.get(key, "")
                    comments[key] = existing + ("\n" if existing else "") + token

    def finish(self, decoder):
        """Export labels after the last rewrite, leaving executable bytes alone."""
        module = self.module
        comments = _auxdata_offsetmap.comments.get_or_insert(module)
        endpoints = {}
        for key, value in tuple(comments.items()):
            lines = value.splitlines()
            tokens = [line for line in lines if line.startswith(_TAG)]
            if not tokens:
                continue
            other = [line for line in lines if not line.startswith(_TAG)]
            if other:
                comments[key] = "\n".join(other)
            else:
                del comments[key]
            block = key.element_id
            if isinstance(block, gtirb.CodeBlock) and block.module is module:
                for token in tokens:
                    index, side = map(int, token[len(_TAG):].split(":"))
                    endpoints.setdefault(index, {})[side] = (block, key.displacement + side)

        points = {}
        decoded = {}
        retained = 0
        for index, pair in endpoints.items():
            if len(pair) != 2 or pair[0][0] is not pair[1][0]:
                continue
            block, start = pair[0]
            _, end = pair[1]
            if block not in decoded:
                decoded[block] = {i.address - block.address: i.size for i in decoder.get_instructions(block)}
            if decoded[block].get(start) != end - start:
                continue  # Removed/replaced instructions have no original PC.
            block_points = points.setdefault(block, {})
            block_points[start] = self.locations[index]
            block_points.setdefault(end, None)
            retained += 1

        labels = {}
        files = []
        file_indices = {}
        with make_modify_cache(module, Function.build_functions(module)) as cache:
            for block in sorted(points, key=lambda b: (b.section.name, b.address or 0, b.uuid.int)):
                for offset, location in sorted(points[block].items(), reverse=True):
                    # Descending splits keep remaining offsets relative to the
                    # original block. split_block also maintains CFI/functions.
                    if offset in (0, block.size):
                        target, at_end = block, offset == block.size
                    else:
                        _, target, _ = split_block(cache, block, offset)
                        at_end = False
                    name = f"{_PREFIX}{len(labels)}"
                    symbol = gtirb.Symbol(name=name, payload=target, at_end=at_end, module=module)
                    info = module.aux_data.get("elfSymbolInfo")
                    if info is not None:
                        info.data[symbol] = (0, "NOTYPE", "LOCAL", "DEFAULT", 0)
                    if location is None:
                        labels[name] = None
                    else:
                        filename, *state = location
                        if filename not in file_indices:
                            files.append(filename)
                            file_indices[filename] = len(files)
                        labels[name] = [file_indices[filename], *state]
        if not files:
            raise ValueError("rewriting removed every source-line anchor")
        module.aux_data[_AUX] = gtirb.AuxData(
            json.dumps({"version": 1, "files": files, "labels": labels}), "string")
        print(f"[teapot] source lines: {len(labels)} anchors, {len(files)} files, "
              f"{retained}/{len(self.locations)} original instructions retained", flush=True)


def _asm_string(text):
    # Use byte escapes, not JSON's \u escapes (GNU as does not interpret them).
    data = text.encode("utf-8", "surrogateescape")
    return '"' + "".join(chr(b) if 32 <= b < 127 and b not in (34, 92)
                         else f"\\{b:03o}" for b in data) + '"'


def emit_source_lines(module, assembly):
    """Convert anchors in an ordinary assembler-mode listing into .file/.loc."""
    aux = module.aux_data.get(_AUX)
    if aux is None:
        raise ValueError("IR has no source lines; rewrite with --debug-source ELF first")
    metadata = json.loads(aux.data)
    if metadata.get("version") != 1:
        raise ValueError("unsupported source-line metadata version")
    if re.search(r"^\s*\.file\s+\d+\s", assembly, re.MULTILINE):
        raise ValueError("assembly already has numbered .file directives")
    files, labels = metadata["files"], metadata["labels"]
    result = [f".file {i} {_asm_string(path)}\n" for i, path in enumerate(files, 1)]
    label_pattern = re.compile(r"^\s*(" + re.escape(_PREFIX) + r"\d+):\s*$")
    section_pattern = re.compile(r"^\s*\.(?:section|pushsection|popsection|previous|text|data|bss)\b")
    seen = set()
    mapped = 0
    reset = ".loc 1 0 0 is_stmt 0\n"
    for line in assembly.splitlines(keepends=True):
        result.append(line)
        match = label_pattern.match(line)
        if match:
            name = match[1]
            if name not in labels or name in seen:
                raise ValueError(f"unexpected or duplicate source-line anchor: {name}")
            seen.add(name)
            state = labels[name]
            if state is None:
                result.append(reset)
            else:
                file, number, column, is_stmt, discriminator = state
                result.append(f".loc {file} {number} {column} is_stmt {is_stmt} "
                              f"discriminator {discriminator}\n")
                mapped += 1
        elif section_pattern.match(line):
            # In particular, do not attribute the transient copy, runtime,
            # trampolines or another section to the last normal-copy row.
            result.append(reset)
    if not mapped:
        raise ValueError("no source-line anchors found in assembly; use the matching instrumented IR")
    # The printer's policy may intentionally omit functions; their labels need
    # not be present. An unexpected label is an error; an omitted one is not.
    return "".join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ir", type=Path, help="instrumented GTIRB made with --debug-source")
    parser.add_argument("assembly", type=Path, help="assembler-mode gtirb-pprinter output")
    parser.add_argument("output", type=Path, help="assembly containing source-line directives")
    args = parser.parse_args()
    ir = gtirb.IR.load_protobuf(args.ir)
    if len(ir.modules) != 1:
        parser.error("source-line printing currently requires one ELF module")
    try:
        result = emit_source_lines(ir.modules[0], args.assembly.read_text())
    except ValueError as error:
        parser.error(str(error))
    args.output.write_text(result)


if __name__ == "__main__":
    main()
