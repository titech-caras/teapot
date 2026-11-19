"""Real outcome stubs, hash decisions, rollback, replay and relocation on each ISA."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from teapot.arch import X64Architecture, AArch64Architecture, RISCV64Architecture
from teapot.pipeline import InstrumentationOptions
from teapot.runtime_contract import RuntimeContractError, capability_bits
from runtime_contract_support import fixture_contract
from test_nested_checkpoint_execution import probe
from test_coverage_execution import x64_probe

RUNTIME = Path(__file__).resolve().parents[1] / "libcheckpoint"


X64_CONDITIONS = "o no b ae e ne be a s ns p np l ge le g c nae nb nc z nz na nbe pe po nge nl ng nle".split()
ARM_CONDITIONS = "eq ne cs cc mi pl vs vc hi ls ge lt gt le hs lo".split()


def condition_flags(arch, condition, taken):
    aliases = dict(c="b", nae="b", nb="ae", nc="ae", z="e", nz="ne", na="be", nbe="a",
                   pe="p", po="np", nge="l", nl="ge", ng="le", nle="g", hs="cs", lo="cc")
    condition = aliases.get(condition, condition)
    for bits in range(32):
        c, p, z, n, v = [bool(bits & (1 << i)) for i in range(5)]
        predicates = dict(o=v, no=not v, b=c, ae=not c, e=z, ne=not z, be=c or z,
            a=not (c or z), s=n, ns=not n, p=p, np=not p, l=n!=v, ge=n==v,
            le=z or n!=v, g=not z and n==v, eq=z, cs=c, cc=not c, mi=n, pl=not n,
            vs=v, vc=not v, hi=c and not z, ls=not c or z, lt=n!=v, gt=not z and n==v)
        if predicates[condition] == bool(taken):
            return ((int(n)<<31)|(int(z)<<30)|(int(c)<<29)|(int(v)<<28) if arch.name=='aarch64'
                    else 2|int(c)|(int(p)<<2)|(int(z)<<6)|(int(n)<<7)|(int(v)<<11))


def branch_case(arch, variant, taken):
    if arch.name == "x64":
        return "j" + X64_CONDITIONS[variant], "target"
    if arch.name == "aarch64":
        if variant >= 5:
            return "b." + ARM_CONDITIONS[variant - 5], "target"
        register, prefix, bit = (("x16", "cb", ""), ("w17", "cb", ""),
                                 ("x16", "tb", "#0, "), ("x17", "tb", "#1, "),
                                 ("x16", "tb", "#63, "))[variant]
        # The fixed registers contain 0x123/0x456. Their bit 63 is clear.
        nonzero = variant != 4
        suffix = "nz" if bool(taken) == nonzero else "z"
        return prefix + suffix, f"{register}, {bit}target"
    mnemonic = ("beq", "bne", "blt", "bge", "bltu", "bgeu")[variant]
    if mnemonic == "beq":
        operands = "t0, t0" if taken else "t0, t1"
    elif mnemonic == "bne":
        operands = "t0, t1" if taken else "t0, t0"
    else:
        less = mnemonic.startswith("blt")
        operands = "t0, t1" if bool(taken) == less else "t1, t0"
    return mnemonic, operands + ", target"


def assembly(arch):
    parts, names = [], []
    variants = range(len(X64_CONDITIONS) if arch.name == "x64" else 5 + len(ARM_CONDITIONS) if arch.name == "aarch64" else 6)
    for variant in variants:
        for spares in range(1 if arch.name == "x64" else 3):
            for taken in range(2):
                index = len(names)
                branch = branch_case(arch, variant, taken)
                emit = x64_probe if arch.name == "x64" else probe
                code = emit(arch, spares, taken, branch_info=branch, site_index=index)
                if arch.name == "x64":
                    flags = condition_flags(arch, X64_CONDITIONS[variant], taken)
                    code = code.replace(f"mov ecx, {1-taken}\ncmp ecx, 0", f"push {flags}\npopfq")
                elif arch.name == "aarch64" and variant >= 5:
                    flags = condition_flags(arch, ARM_CONDITIONS[variant-5], taken)
                    code = code.replace(f"mov x8, #{1-taken}\ncmp x8, #0", f"mov x8, #{flags}\nmsr nzcv, x8")
                old = f"probe_{spares}_{taken}"
                name = f"hashed_probe_{index}"
                names.append(name)
                code = code.replace(old, name)
                if arch.name == "x64":
                    code = code.replace("call probe_outer", f"call probe_outer\n.Lrepeat_{index}:")
                    code = code.replace("call probe_inner_restored", f"call probe_inner_restored\ntest eax,eax\njnz .Lrepeat_{index}")
                elif arch.name == "aarch64":
                    code = code.replace("bl probe_outer", f"bl probe_outer\n.Lrepeat_{index}:")
                    code = code.replace("bl probe_inner_restored", f"bl probe_inner_restored\ncbnz w0,.Lrepeat_{index}")
                else:
                    code = code.replace("call probe_outer", f"call probe_outer\n.Lrepeat_{index}:")
                    code = code.replace("call probe_inner_restored", f"call probe_inner_restored\nbnez a0,.Lrepeat_{index}")
                parts.append(code)
    return (".intel_syntax noprefix\n" if arch.name == "x64" else "") + "\n".join(parts) + \
        '\n.section .note.GNU-stack,"",@progbits\n', names


@contextmanager
def output_directory(arch):
    if os.environ.get("TEAPOT_HASHED_EVIDENCE"):
        root = Path(os.environ["TEAPOT_HASHED_EVIDENCE"]) / arch
        root.mkdir(parents=True, exist_ok=True)
        yield root
    else:
        with tempfile.TemporaryDirectory() as directory:
            yield Path(directory)


class HashedNestedTests(unittest.TestCase):
    def test_contract_policy_is_bidirectional(self):
        options = InstrumentationOptions(enable_nested_speculation=True)
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            single = fixture_contract(arch.name)
            hashed = fixture_contract(arch.name, nested=True)
            self.assertEqual(hashed.anchor, single.anchor + "_hashed")
            self.assertEqual(capability_bits({"hashed_nested"}), 0x800)
            bits, _ = hashed.check(arch, arch.abi, options)
            self.assertTrue(bits & capability_bits({"hashed_nested"}))
            with self.assertRaisesRegex(RuntimeContractError, "requires --enable-nested-speculation"):
                hashed.check(arch, arch.abi, InstrumentationOptions())
            with self.assertRaisesRegex(RuntimeContractError, "hashed"):
                single.check(arch, arch.abi, options)

    def check_arch(self, arch, compiler, emulator):
        if not all(shutil.which(tool) for tool in (compiler, "cmake", *emulator[:1])):
            self.skipTest("requires target compiler, CMake and emulator")
        with output_directory(arch.name) as root:
            def run(args, **kwargs):
                result = subprocess.run(list(map(str, args)), cwd=root, capture_output=True, text=True, timeout=120, **kwargs)
                self.assertEqual(result.returncode, 0, f"{args}\n{result.stdout}\n{result.stderr}")
                return result
            build = root / "runtime"
            configure = ["cmake", "-S", RUNTIME, "-B", build, "-DBUILD_TESTING=OFF",
                         "-DTEAPOT_BUILD_NESTED_RUNTIME=ON", "-DTEAPOT_ENABLE_DIFT_RUNTIME=OFF",
                         f"-DCHECKPOINT_ARCH={'x86_64' if arch.name == 'x64' else arch.name}", f"-DCMAKE_C_COMPILER={compiler}", f"-DCMAKE_ASM_COMPILER={compiler}"]
            if arch.name != "x64":
                configure += ["-DCMAKE_SYSTEM_NAME=Linux", f"-DCMAKE_SYSTEM_PROCESSOR={arch.name}"]
            run(configure)
            run(["cmake", "--build", build, "--target", "checkpoint_nested_hashed", "checkpoint", "-j1"])
            code, names = assembly(arch)
            (root / "probe.S").write_text(code)
            (root / "cases.h").write_text("\n".join(f"extern void {name}(void *);" for name in names) +
                "\nstatic void (*probes[])(void *) = {" + ",".join(names) + "};\n")
            if arch.name == "aarch64":
                nzcv = [condition_flags(arch, ARM_CONDITIONS[v-5], taken) if v >= 5 else
                        (0x60000000 if taken else 0x20000000)
                        for v in range(5 + len(ARM_CONDITIONS)) for spares in range(3) for taken in range(2)]
                with (root / "cases.h").open("a") as cases:
                    cases.write("static const uint64_t expected_nzcv[] = {" + ",".join(map(str,nzcv)) + "};\n")
            flags = ["-O2", "-fno-pie", "-fno-stack-protector", "-DENABLE_NESTED_SPECULATION", "-DENABLE_HASHED_NESTED",
                     "-DDIFT_XOR_MASK=0", "-DTEST_CONTRACT_REQUIRED=LIBCHECKPOINT_CAPABILITY_HASHED_NESTED",
                     "-I", RUNTIME / "include", "-I", RUNTIME / "tests", "-I", build / "include", "-I", root]
            run([compiler, *flags, "-c", Path(__file__).with_name("fixtures") / "hashed_nested.c", "-o", "driver.o"])
            run([compiler, *flags, "-c", "probe.S", "-o", "probe.o"])
            run([compiler, *flags, "-c", RUNTIME / "tests/contract_module_record.c", "-o", "record.o"])
            single_flags = [flag for flag in flags if flag != "-DENABLE_HASHED_NESTED" and
                           not str(flag).startswith("-DTEST_CONTRACT_REQUIRED=")]
            run([compiler, *single_flags, "-c", RUNTIME / "tests/contract_module_record.c", "-o", "single-record.o"])
            for record, archive, suffix in (("record.o", "checkpoint", "_hashed"),
                                             ("single-record.o", "checkpoint_nested_hashed", "")):
                mismatch = subprocess.run(list(map(str, [compiler, "-no-pie", "driver.o", "probe.o", record,
                    build / f"lib{archive}.a", "-lm", "-o", "mismatch"])), cwd=root,
                    capture_output=True, text=True, timeout=30)
                self.assertNotEqual(mismatch.returncode, 0)
                anchor = json.loads((build / "libcheckpoint.contract.json").read_text())["anchor"] + suffix
                self.assertIn(anchor, mismatch.stderr)
                (root / f"mismatch-{record}.stderr").write_text(mismatch.stderr)
            outputs = []
            (root / "input").write_bytes(bytes(range(256)) * 3)
            for layout, base in (("default", None), ("moved", "0x1400000")):
                link = [compiler, "-no-pie", "driver.o", "probe.o", "record.o", build / "libcheckpoint_nested_hashed.a", "-lm"]
                if arch.name == "riscv64":
                    link += ["-Wl,--no-relax"]
                if base:
                    link += [f"-Wl,-Ttext-segment={base}"]
                run([*link, "-o", layout])
                for repeat in (1, 2):
                    result = run([*emulator, root / layout, root / "input"])
                    (root / f"{layout}-{repeat}.stdout").write_text(result.stdout)
                    (root / f"{layout}-{repeat}.stderr").write_text(result.stderr)
                    outputs.append(result.stdout)
            self.assertTrue(all(output == outputs[0] for output in outputs))
            self.assertIn("depth2=", outputs[0])

    def test_x64(self):
        self.check_arch(X64Architecture(), "gcc", [])

    def test_aarch64(self):
        self.check_arch(AArch64Architecture(), "aarch64-linux-gnu-gcc",
                        ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "-R", "0x40000000000", "-s", "33554432"])

    def test_riscv64(self):
        self.check_arch(RISCV64Architecture(), "riscv64-linux-gnu-gcc",
                        ["qemu-riscv64", "-L", "/usr/riscv64-linux-gnu", "-R", "0x4000000000", "-s", "33554432"])
