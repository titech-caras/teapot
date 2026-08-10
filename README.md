# Teapot

Teapot is a static binary rewriting & dynamic fuzzing based Spectre gadget detector, 
described in the paper "Teapot: Efficiently Uncovering Spectre Gadgets in COTS Binaries" in [CGO 2025](https://dl.acm.org/doi/10.1145/3696443.3708936).

[Listen to Teapot on suno.ai!](https://suno.com/song/907f1bb5-ad72-4a9f-9e08-053d121c696c)

This repository contains the Teapot binary rewriter.
The submodule `libcheckpoint` contains the runtime library.

## Requirements

Teapot static rewriter requires Python 3.8 or newer.
It also requires the following packages for interfacing with GTIRB format:

- `gtirb`
- `gtirb-rewriting`
- `gtirb-functions`
- `gtirb-capstone`
- `gtirb-live-register-analysis`

`requirements.txt` pins Teapot's `gtirb-rewriting` fork because its scoped
rewrite preparation reduces runtime and peak memory on large RV64 modules.

Teapot also requires `llvmlite` for generating optimized DIFT instrumentation.
If the debug symbol manipulation functions are used, `pyelftools` is also required.

Teapot live-register analysis uses conservative call liveness on every ISA:
calls do not make ABI caller-saved GPRs available for instrumentation.
Keep this behavior until Teapot has a more precise cross-call analysis.

See [`libcheckpoint/README.md`](libcheckpoint/README.md) for runtime
build options, ASan/MTE tag-storage requirements, DIFT layout profiles,
optional wrapper libraries, and architecture-specific qemu notes.

Using the provided Dockerfile is an easy way to quickly test Teapot,
which contains all the necessary dependencies.
It also includes an isolated Ubuntu arm64 sysroot with MTE-capable glibc at
`/opt/aarch64-mte-sysroot` and a newer static qemu runner at
`/usr/local/bin/qemu-aarch64-mte`; the normal `/usr/aarch64-linux-gnu` cross
sysroot is left unchanged.

## Usage

1. Create a disassembly of the program of interest using Datalog Disassembly, generating the disassembled GTIRB file.
```shell
ddisasm --ir a.out.gtirb a.out
```
When validating frontend or pretty-printer changes, regenerate this GTIRB from
the binary instead of reusing an older IR file.

2. Call teapot to create an instrumented GTIRB file.
```shell
teapot a.out.gtirb a.inst.gtirb
```
The DIFT address-space profile is selected at instrumentation time with
`--dift-layout`. The runtime library must be built with the same profile via
`-DTEAPOT_DIFT_LAYOUT=...`. The profile definitions live in
`libcheckpoint/cmake/DiftLayoutData.cmake` and are shared by Teapot and the
runtime build.

On AArch64, Teapot ASan-style tag storage defaults to ASan shadow bytes.  The
experimental `--aarch64-tag-storage=mte` mode stores those tags in MTE
allocation tags instead; build libcheckpoint with
`-DTEAPOT_AARCH64_TAG_STORAGE=mte` and assemble Teapot output with an MTE-capable
target such as `armv8.5-a+memtag`.  Teapot still reads and checks tags in
software by comparing the pointer logical tag with the memory allocation tag.
MTE tag faults are disabled because recovering from tag-check signals is too
expensive for speculative simulation.  MTE mode does not need ASan for tag
storage; avoid linking ASan unless another experiment explicitly needs it.
The Docker sysroot's glibc supports `GLIBC_TUNABLES=glibc.mem.tagging=1` for
malloc MTE tagging, which uses the same pointer/allocation-tag matching
semantics.

Nested speculation is disabled by default.  Use
`--enable-nested-speculation` to also insert checkpoints in the transient copy,
and link the instrumented binary with the nested-capable `checkpoint_nested`
runtime target rather than the default `checkpoint` target.

3. Dump the assembly of the instrumented GTIRB file. 
Then, apply a sedscript to the assembly file due to limitations of `gtirb-pprinter`.
If using the provided Dockerfile, the script is available at `/teapot-scripts/fix_asm.sed`.
```shell
gtirb-pprinter --ir a.inst.gtirb --asm a.inst.S
sed -i -f scripts/fix_asm.sed a.inst.S 
```
For RV64, use a RISC-V-capable `gtirb-pprinter` build and assembler path; see
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for the current smoke-test notes.

4. Recompile the instrumented assembly file.
```shell
gcc -o a.inst a.inst.S -no-pie -nostartfiles -lcheckpoint -lhfuzz -lasan
```
For AArch64 MTE tag storage, compile with an MTE-capable target and omit
`-lasan`:
```shell
aarch64-linux-gnu-gcc -march=armv8.5-a+memtag -o a.inst a.inst.S -no-pie -nostartfiles -lcheckpoint
```
In the provided Docker image, run MTE smoke tests with:
```shell
qemu-aarch64-mte -cpu max -R 0x40000000000 -s 33554432 -L /opt/aarch64-mte-sysroot ./a.inst
```
Build and link optional DIFT wrapper libraries only when Teapot rewrites calls
to those wrapper symbols.

5. For ASan-linked shadow-tag binaries, set some environment variables to silence it.
This is preset in the provided Dockerfile.
```shell
export ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=false
```

6. The program can be executed, and it provides information the Spectre gadgets found to `stderr` in CSV format.
Alternatively, the program can be tested with a fuzzer.
```shell
$ ./a.inst input.txt
[teapot], Gadget Type, Gadget Address, Mem Access Address, Tag, Instruction Counter, Checkpoint Addresses
[teapot], 41 KASPER_MDS, 0x413a43, 0x603000000068, 0x207bc601, 149, 0x41381c, 0x409c56, 0x40b093, 0x409e54, 0x412c48, 0x401566,
[teapot], 42 KASPER_CACHE, 0x413b2b, 0x1f81b610, 0x11, 149, 0x41381c, 0x409c56, 0x40b093, 0x409e54, 0x412c48, 0x401566,
[teapot], 41 KASPER_MDS, 0x41416f, 0x603000000068, 0x207bc601, 153, 0x413f4d, 0x409c56, 0x40b093, 0x409e54, 0x412c48, 0x401566,
[teapot], 42 KASPER_CACHE, 0x414257, 0x1f81b610, 0x11, 153, 0x413f4d, 0x409c56, 0x40b093, 0x409e54, 0x412c48, 0x401566,
```

## Troubleshooting

See [TROUBLESHOOTING.md](https://github.com/lin-toto/teapot/blob/main/TROUBLESHOOTING.md) for common issues.
