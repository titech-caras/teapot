"""Write teapot/dfsan/functional_prototypes.txt from the C library's headers.

DFSan's ABI list names its functional functions but not their parameters, so
Teapot cannot tell which registers they read. This records each one's return
and parameter types, as clang parses them from <ctype.h>, <math.h> and
<wchar.h>. Rerun after updating teapot/dfsan/done_abilist.txt:

    python tools/dfsan_prototypes.py [--clang clang]
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

DFSAN = Path(__file__).resolve().parent.parent / "teapot" / "dfsan"
HEADERS = "#define _GNU_SOURCE\n#include <ctype.h>\n#include <math.h>\n#include <wchar.h>\n"
OUTPUT_HEADER = """\
# The return and parameter types of the functions done_abilist.txt calls
# functional, from the C library headers (tools/dfsan_prototypes.py writes it).
# Types: int (any integer), pointer, float, double, longdouble.
"""


def type_class(qual_type):
    qual_type = qual_type.strip()
    if "*" in qual_type:
        return "pointer"
    if qual_type == "long double":
        return "longdouble"
    if qual_type in ("float", "double"):
        return qual_type
    if re.fullmatch(r"(const )?(unsigned |signed )?(char|short|int|long|long long|wint_t|wchar_t|_Bool)", qual_type):
        return "int"
    raise ValueError(f"unclassified type {qual_type!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    functional = []
    for line in (DFSAN / "done_abilist.txt").read_text().splitlines():
        match = re.fullmatch(r"fun:([A-Za-z0-9_]+)=functional", line.strip())
        if match:
            functional.append(match[1])
    with tempfile.NamedTemporaryFile("w", suffix=".c") as source:
        source.write(HEADERS)
        source.flush()
        ast = json.loads(subprocess.run([args.clang, "-fsyntax-only", "-Xclang", "-ast-dump=json", source.name],
                                        check=True, capture_output=True, text=True).stdout)
    types = {}
    for node in ast["inner"]:
        if node.get("kind") == "FunctionDecl" and node.get("name") in functional:
            types.setdefault(node["name"], node["type"]["qualType"])
    lines = [OUTPUT_HEADER]
    for name in functional:
        match = re.fullmatch(r"(.+?) \((.*)\)", types[name])
        params = [type_class(param) for param in match[2].split(",") if param.strip() not in ("", "void")]
        lines.append(" ".join([name, type_class(match[1])] + params) + "\n")
    (DFSAN / "functional_prototypes.txt").write_text("".join(lines))


if __name__ == "__main__":
    main()
