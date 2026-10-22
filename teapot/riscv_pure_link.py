"""Small integer-only RISC-V disassembly check for objects, archives and ELFs."""
import argparse
import re
import subprocess

FP_VECTOR_CSRS = {1, 2, 3, 8, 9, 10, 15, 0xc20, 0xc21, 0xc22}
FP_VECTOR_NAMES = {"fflags", "frm", "fcsr", "vstart", "vxsat", "vxrm", "vcsr",
                   "vl", "vtype", "vlenb"}
INSTRUCTION = re.compile(r"^\s*[0-9a-f]+:\s+([\w.]+)\s*(.*)$", re.I)


def check_disassembly(text, source="<disassembly>"):
    """Reject FP/vector instructions or CSR access; return instruction count."""
    count = 0
    for line in text.splitlines():
        match = INSTRUCTION.match(line)
        if not match:
            continue
        count += 1
        mnemonic, operands = match[1].lower(), match[2].split("#", 1)[0].lower()
        forbidden = (mnemonic.startswith(("c.f", "v")) or
                     mnemonic.startswith("f") and not mnemonic.startswith("fence"))
        if mnemonic.startswith("csr"):
            parts = [part.strip() for part in operands.split(",")]
            index = 0 if mnemonic in {"csrw", "csrs", "csrc", "csrwi", "csrsi", "csrci"} else 1
            if len(parts) > index:
                csr = parts[index]
                try:
                    value = int(csr, 16 if csr.startswith("0x") else 10)
                    forbidden |= value in FP_VECTOR_CSRS
                except ValueError:
                    forbidden |= csr in FP_VECTOR_NAMES
        if forbidden:
            raise ValueError(f"{source}: forbidden pure instruction: {line.strip()}")
    return count


def check_pure_code(path, objdump="riscv64-unknown-linux-gnu-objdump"):
    output = subprocess.run([str(objdump), "-d", "--no-show-raw-insn", "-M", "no-aliases", str(path)],
                            check=True, text=True, capture_output=True)
    return check_disassembly(output.stdout, str(path))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--objdump", default="riscv64-unknown-linux-gnu-objdump")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    for path in args.files:
        print(f"{path}: {check_pure_code(path, args.objdump)} instructions checked")
