#!/usr/bin/env python3
"""Reproduce the workspace's Python/fork test environment in an isolated image.

Only --out is writable in the container. This helper is specific to the
September 21 multiarch workspace; ordinary installations can use unittest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--full", action="store_true", help="Run all Teapot Python tests")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "tmp").mkdir(exist_ok=True)
    teapot = Path(__file__).resolve().parent.parent.parent
    image = "teapot-multiarch-eval:1586139-tools-v4"
    command = ["docker", "run", "--rm", "--name", "teapot-hardware-policy-" + str(os.getpid()),
               "--memory=24g", "--cpus=4", "--network=none", "--user", f"{os.getuid()}:{os.getgid()}",
               "-v", str(workspace) + ":/eval:ro", "-v", str(teapot) + ":/teapot:ro",
               "-v", str(output) + ":/out", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "TMPDIR=/out/tmp",
               "-e", "PYTHONPATH=/teapot:/eval/sources/gtirb-live-register-analysis:"
               "/eval/sources/gtirb-rewriting-2c0308e/src:"
               "/eval/workers/baseline-unit-20260921/venv-system/lib/python3.8/site-packages",
               "-e", "PATH=/hostbin:/eval/workers/baseline-unit-20260921:"
               "/eval/workers/ddisasm-symbol-identity-20260922/build-v1/build/bin:"
               "/eval/workers/printer-cli-errors-20260922/gates-v1/install/bin:"
               "/eval/shared-build/install/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "-e", "LD_LIBRARY_PATH=/eval/workers/printer-cli-errors-20260922/gates-v1/install/lib:"
               "/eval/workers/root/baseline-20260921/frontend/install/lib:"
               "/eval/shared-build/install/lib",
               "-e", "PPRINTER_PATH=/eval/workers/printer-cli-errors-20260922/gates-v1/install/bin/gtirb-pprinter"]
    for emulator in ("qemu-aarch64", "qemu-riscv64", "qemu-riscv32"):
        command += ["-v", "/usr/bin/" + emulator + ":/hostbin/" + emulator + ":ro"]
    command += ["-w", "/teapot", image, "/usr/bin/python3", "-m"]
    if args.full:
        command += ["pytest", "-p", "no:cacheprovider", "-q", "tests"]
    else:
        command += ["unittest", "discover", "-s", "tests", "-p", "test_indirect_target_policy.py", "-v"]
    (output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    (output / "stdout").write_text(result.stdout)
    (output / "stderr").write_text(result.stderr)
    hashes = {str(path.relative_to(teapot)): hashlib.sha256(path.read_bytes()).hexdigest()
              for directory in (teapot / "teapot", teapot / "tests")
              for path in sorted(directory.rglob("*.py"))}
    (output / "result.json").write_text(json.dumps({"status": result.returncode,
                                                   "source_sha256": hashes}, indent=2) + "\n")
    print(result.stdout, end="")
    print(result.stderr, end="")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
