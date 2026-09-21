#!/usr/bin/env python3
"""Build/run the standalone probes, keeping commands, results and ELF evidence.

No Teapot production option is enabled. --require-backend deliberately rejects
both experimental hardware candidates until policy equivalence is established.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import time


def sha256(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--aarch64-sysroot", default="/usr/aarch64-linux-gnu")
    parser.add_argument("--skip-aarch64", action="store_true")
    parser.add_argument("--runtime-tests", action="store_true",
                        help="Build/run the real AArch64 checkpoint BTI fault tests (shadow and MTE)")
    parser.add_argument("--layout-elf", type=Path,
                        help="Optional existing Teapot AArch64 ELF to inspect without changing it")
    args = parser.parse_args()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parent
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = os.environ.copy()
    compiler_tmp = root / "compiler-tmp"
    compiler_tmp.mkdir(exist_ok=True)
    env["TMPDIR"] = str(compiler_tmp)
    records = []

    def run(name, command, expected=(0,), *, timeout=30):
        start = time.time()
        result = subprocess.run([str(arg) for arg in command], capture_output=True,
                                text=True, env=env, timeout=timeout)
        record = {"command": [str(arg) for arg in command], "returncode": result.returncode,
                  "elapsed_seconds": time.time() - start, "expected_status": list(expected),
                  "TMPDIR": str(compiler_tmp)}
        (root / (name + ".command.json")).write_text(json.dumps(record, indent=2) + "\n")
        (root / (name + ".stdout")).write_text(result.stdout)
        (root / (name + ".stderr")).write_text(result.stderr)
        records.append({"name": name, **record})
        if result.returncode not in expected:
            raise RuntimeError(f"{name}: status {result.returncode}; see {root}")
        return result.stdout

    manifest = {"host": platform.uname()._asdict(), "source_hashes": {}, "binaries": {},
                "results": {}, "backend_supported": False}
    for path in sorted(source.iterdir()):
        if path.is_file():
            manifest["source_hashes"][path.name] = sha256(path)
    run("host-cpu", ["lscpu"])
    run("host-kernel", ["uname", "-a"])
    run("host-libc", ["ldd", "--version"])
    config = Path("/boot") / ("config-" + platform.release())
    if config.is_file():
        text = "\n".join(line for line in config.read_text().splitlines()
                         if "X86_KERNEL_IBT" in line or "X86_USER_SHADOW_STACK" in line)
        (root / "host-cet-kernel-config.txt").write_text(text + "\n")
    variants = [("x64-native", "gcc", "-fcf-protection=branch", "-Wl,-z,ibt", [])]
    if not args.skip_aarch64:
        variants += [("aarch64-qemu-max", "aarch64-linux-gnu-gcc", "-mbranch-protection=bti",
                      "-Wl,-z,force-bti", ["qemu-aarch64", "-cpu", "max", "-R", "0x40000000000",
                                           "-s", "33554432", "-L", args.aarch64_sysroot])]
        run("qemu-aarch64-version", ["qemu-aarch64", "--version"])
    for name, compiler, protection, linker, launcher in variants:
        run(name + "-compiler-version", [compiler, "--version"])
        binary = root / (name + "-probe")
        common = [compiler, "-O2", "-Wall", "-Wextra", "-Werror", protection, linker,
                  source / "target_probe.c", source / "transfer.S", "-o", binary]
        run(name + "-build", common)
        manifest["binaries"][name] = {"path": str(binary), "sha256": sha256(binary)}
        manifest["binaries"][name]["compiler_sha256"] = sha256(shutil.which(compiler))
        readelf = "readelf" if name.startswith("x64") else "aarch64-linux-gnu-readelf"
        objdump = "objdump" if name.startswith("x64") else "aarch64-linux-gnu-objdump"
        run(name + "-elf", [readelf, "-W", "-n", "-l", binary])
        run(name + "-disassembly", [objdump, "-d", binary])
        output = run(name, launcher + [binary])
        rows = [json.loads(line) for line in output.splitlines() if line]
        manifest["results"][name] = rows
        summary = next(row for row in rows if row["kind"] == "summary")
        assert not summary["teapot_backend_supported"]
        assert summary["selected_backend"] == "software"
        assert summary["raw_hardware_policy_mismatches"] > 0
        run(name + "-required", launcher + [binary, "--require-backend"], expected=(77,))
        cases = {(row["name"], row["transfer"]): row for row in rows if row["kind"] == "case"}
        assert cases[("normal_hardware_only", "call")]["software_accepts"] is False
        assert cases[("normal_prefixed_marker_interior", "jump")]["software_accepts"] is True
        assert cases[("trusted_runtime_landing", "jump")]["software_accepts"] is False
        assert cases[("transient_plain_unguarded", "call")]["raw_transfer_executed"] is True
        if summary["enforcement_demonstrated"]:
            assert cases[("normal_software_marker", "call")]["raw_transfer_executed"] is False
            assert cases[("normal_hardware_only", "call")]["raw_transfer_executed"] is True
            assert cases[("transient_plain_guarded", "call")]["raw_transfer_executed"] is False
        if launcher:
            no_bti = launcher[:]
            no_bti[2] = "cortex-a53"
            no_output = run("aarch64-qemu-no-bti", no_bti + [binary])
            no_rows = [json.loads(line) for line in no_output.splitlines() if line]
            assert not next(row for row in no_rows if row["kind"] == "summary")["enforcement_demonstrated"]
            run("aarch64-qemu-no-bti-required", no_bti + [binary, "--require-backend"], expected=(77,))
            manifest["results"]["aarch64-qemu-no-bti"] = no_rows
            # Same CPU and generated pages, without an ELF feature note: the
            # anonymous-page BTI probe must not be confused with loader proof.
            unmarked = root / "aarch64-no-property-probe"
            run("aarch64-no-property-build", [compiler, "-O2", "-Wall", "-Wextra", "-Werror",
                                              source / "target_probe.c", source / "transfer.S",
                                              "-o", unmarked])
            run("aarch64-no-property-elf", [readelf, "-W", "-n", "-l", unmarked])
            unmarked_output = run("aarch64-no-property", launcher + [unmarked])
            unmarked_rows = [json.loads(line) for line in unmarked_output.splitlines() if line]
            assert next(row for row in unmarked_rows if row["kind"] == "elf_loader")["invalid_landing_signal"] == 0
            manifest["results"]["aarch64-qemu-no-property"] = unmarked_rows
            manifest["binaries"]["aarch64-no-property"] = {"path": str(unmarked), "sha256": sha256(unmarked)}
            for path in (Path(args.aarch64_sysroot) / "lib/ld-linux-aarch64.so.1",
                         Path(args.aarch64_sysroot) / "lib/libc.so.6", Path(shutil.which("qemu-aarch64"))):
                manifest.setdefault("execution_files", {})[str(path)] = sha256(path)
    if args.layout_elf:
        run("teapot-layout-elf", ["aarch64-linux-gnu-readelf", "-W", "-S", "-l", "-n", args.layout_elf])
        run("teapot-layout-symbols", ["aarch64-linux-gnu-nm", "-n", args.layout_elf])
        manifest["layout_elf"] = {"path": str(args.layout_elf.resolve()), "sha256": sha256(args.layout_elf)}
    if args.runtime_tests:
        runtime = source.parent.parent / "libcheckpoint"
        emulator = ["/usr/bin/qemu-aarch64", "-cpu", "max", "-R", "0x40000000000",
                    "-s", "33554432", "-L", args.aarch64_sysroot]
        for storage in ("shadow", "mte"):
            name = "runtime-aarch64-" + storage
            build = root / name
            run(name + "-configure", ["cmake", "-S", runtime, "-B", build, "-G", "Ninja",
                                      "-DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc",
                                      "-DCMAKE_ASM_COMPILER=aarch64-linux-gnu-gcc",
                                      "-DCMAKE_SYSTEM_NAME=Linux", "-DCMAKE_SYSTEM_PROCESSOR=aarch64",
                                      "-DCHECKPOINT_ARCH=aarch64", "-DTEAPOT_DIFT_LAYOUT=aarch64-vma42",
                                      "-DTEAPOT_AARCH64_TAG_STORAGE=" + storage,
                                      "-DCMAKE_CROSSCOMPILING_EMULATOR=" + ";".join(emulator)])
            run(name + "-build", ["cmake", "--build", build, "--target", "checkpoint_entry_default_test",
                                  "checkpoint_entry_nested_test", "-j4"], timeout=60)
            run(name + "-ctest", ["ctest", "--test-dir", build, "-R",
                                  "checkpoint_entry_.*_(bti_fault|bti_live_chain|capacity|timing|storage|memlog|report)",
                                  "--output-on-failure", "-j1"])
            for mode in ("default", "nested"):
                binary = build / ("checkpoint_entry_" + mode + "_test")
                manifest["binaries"][name + "-" + mode] = {"path": str(binary), "sha256": sha256(binary)}
                run(name + "-" + mode + "-bti", emulator + [binary, "bti-fault"])
                run(name + "-" + mode + "-bti-live-chain",
                    emulator + [binary, "bti-live-chain"],
                    expected=(0,) if mode == "nested" else (77,))
                if storage == "shadow":
                    unsupported = emulator[:]
                    unsupported[2] = "cortex-a53"
                    run(name + "-" + mode + "-unsupported",
                        unsupported + [binary, "bti-fault"], expected=(77,))
                    run(name + "-" + mode + "-live-chain-unsupported",
                        unsupported + [binary, "bti-live-chain"], expected=(77,))
    manifest["commands"] = records
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"evidence": str(root), "teapot_backend_supported": False,
                      "probe_variants": list(manifest["results"])}))


if __name__ == "__main__":
    main()
