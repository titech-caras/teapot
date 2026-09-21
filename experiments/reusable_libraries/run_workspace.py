#!/usr/bin/env python3
"""Isolated component rewrite/cache + one-runtime final link in this workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def dump(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--executable", default="main")
    parser.add_argument("--select", action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    workspace, inputs, output, cache = (p.resolve() for p in (
        args.workspace, args.inputs, args.out, args.cache))
    output.mkdir(parents=True, exist_ok=False)
    cache.mkdir(parents=True, exist_ok=True)
    (output / "tmp").mkdir()
    teapot = Path(__file__).resolve().parents[2]
    frontend = workspace / "workers/root/baseline-20260921/frontend/install"
    shared = workspace / "shared-build/install"
    runtime = workspace / "workers/baseline-runtime-20260921/install/x64-host-gcc14/lib"
    hfuzz = workspace / "shared-build/honggfuzz/x86_64/lib"
    image = "teapot-multiarch-eval:1586139-tools-v4"
    archives = [runtime / name for name in ("libcheckpoint.a", "libcheckpoint_dift_math_wrappers.a",
                                          "libcheckpoint_dift_zlib_wrappers.a")]
    archives += [hfuzz / "libhfuzz.a", hfuzz / "libhfcommon.a"]
    libraries = {str(path): sha(path) for root in (frontend / "lib", shared / "lib")
                 for path in sorted(root.glob("*.so*")) if path.is_file()}
    image_id = subprocess.check_output(["docker", "image", "inspect", "--format={{.Id}}", image], text=True).strip()
    contract = {"runtime_profile": "x64-la48-asan-new", "ROB_LEN": 250, "nested": False,
                "image_id": image_id, "archives": {str(path): sha(path) for path in archives},
                "frontend_libraries": libraries,
                "driver_bundle": {path.name: sha(path) for path in sorted(Path(__file__).parent.glob("*.py"))}}
    dump(output / "runtime-contract.json", contract)
    converter = workspace / "workers/shared-library-20260921/teapot/tools/sharedlib/convert.py"
    shutil.copyfile(converter, output / "converter-snapshot.py")
    argv = ["docker", "run", "--rm", "--network=none", "--memory=16g", "--cpus=4",
            "--user", "{}:{}".format(os.getuid(), os.getgid())]
    mounts = [(inputs, "/inputs", "ro"), (output, "/out", "rw"), (cache, "/cache", "rw"),
              (teapot, "/teapot", "ro"), (frontend, "/frontend", "ro"),
              (shared, "/shared", "ro"), (Path("/usr/lib/x86_64-linux-gnu"), "/external", "ro"),
              (workspace / "sources/gtirb-live-register-analysis", "/lra", "ro"),
              (workspace / "sources/gtirb-rewriting-2c0308e/src", "/rewriting", "ro")]
    for source, target, mode in mounts:
        argv += ["-v", "{}:{}:{}".format(source, target, mode)]
    argv += ["-e", "TMPDIR=/out/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1",
             "-e", "PYTHONPATH=/teapot:/lra:/rewriting", "-e", "LD_LIBRARY_PATH=/frontend/lib:/shared/lib",
             image, "python3", "/teapot/experiments/reusable_libraries/rewrite_components.py",
             "--executable", "/inputs/" + args.executable, "--out", "/out/objects", "--cache", "/cache",
             "--converter", "/out/converter-snapshot.py", "--teapot", "/teapot",
             "--rewriting", "/rewriting", "--lra", "/lra", "--runtime-contract", "/out/runtime-contract.json",
             "--ddisasm", "/frontend/bin/ddisasm", "--pprinter", "/frontend/bin/gtirb-pprinter"]
    for name in args.select:
        argv += ["--select", "/inputs/" + name]
    for name in ("libz.so.1", "libc.so.6", "ld-linux-x86-64.so.2"):
        argv += ["--external", "/external/" + name]
    dump(output / "container.command.json", argv)
    with (output / "container.stdout").open("wb") as stdout, (output / "container.stderr").open("wb") as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr)
    dump(output / "container.result.json", {"status": result.returncode})
    result.check_returncode()
    objects = output / "objects"
    components = json.loads((objects / "components.json").read_text())["components"]
    link = ["gcc-14", "-B" + str(workspace / "workers/baseline-runtime-20260921/linker/shim"),
            "-fuse-ld=lld", "-fsanitize=address", "-no-pie", "-nostartfiles",
            "-Wl,--no-as-needed", "-Wl,--build-id=sha1", "-Wl,-z,noexecstack",
            "-Wl,-T," + str(objects / "layout.ld"), "-Wl,-Map=" + str(output / "link.map"),
            "-o", str(output / "instrumented")]
    link += [str(objects / "component-{:03d}.o".format(i)) for i in range(len(components))]
    link += [str(path) for path in archives[:3]]
    link += ["-Wl,-u,LIBHFUZZ_module_instrument", "-Wl,-u,LIBHFUZZ_module_memorycmp"]
    link += [str(path) for path in archives[3:]]
    link += ["-lz", "-lasan", "-ldl", "-pthread", "-lrt", "-lm", "-lc", "-lgcc_s"]
    dump(output / "link.command.json", link)
    with (output / "link.stdout").open("wb") as stdout, (output / "link.stderr").open("wb") as stderr:
        result = subprocess.run(link, stdout=stdout, stderr=stderr)
    dump(output / "link.result.json", {"status": result.returncode})
    result.check_returncode()
    validation = argv[:argv.index(image) + 1] + [
        "python3", "/teapot/experiments/reusable_libraries/validate_link.py",
        "--binary", "/out/instrumented", "--objects", "/out/objects",
        "--out", "/out/link-validation.json"]
    dump(output / "validate.command.json", validation)
    with (output / "validate.stdout").open("wb") as stdout, (output / "validate.stderr").open("wb") as stderr:
        result = subprocess.run(validation, stdout=stdout, stderr=stderr)
    dump(output / "validate.result.json", {"status": result.returncode})
    result.check_returncode()
    dump(output / "result.json", {"status": "linked_not_yet_behavior_verified",
                                  "binary_sha256": sha(output / "instrumented"),
                                  "components": components})
    print("Linked {} components, {} from the instrumentation cache".format(
        len(components), sum(c["cache_hit"] for c in components)), flush=True)


if __name__ == "__main__":
    main()
