# Teapot

Teapot is a static binary rewriting & dynamic fuzzing based Spectre gadget detector, 
described in the paper "Teapot: Efficiently Uncovering Spectre Gadgets in COTS Binaries" (To appear in CGO 2025).

This repository contains the Teapot binary rewriter. 
The submodule `libcheckpoint_x64` contains the runtime library.

## Requirements

Teapot static rewriter requires a Python version between 3.8 and 3.10.
It also requires the following packages for interfacing with GTIRB format:

- `gtirb`
- `gtirb-rewriting`
- `gtirb-functions`
- `gtirb-capstone`
- `gtirb-live-register-analysis`

Teapot also requires `llvmlite` for generating optimized DIFT instrumentation.
If the debug symbol manipulation functions are used, `pyelftools` is also required.

Teapot runtime library requires `libasan`. 
If coverage is enabled, executing the instrumented binaries requires `libhfuzz` 
or any other fuzzer library that implements the Sanitizer Coverage interface.  

Note that newer `libasan` versions cause failures in DIFT initialization 
(with the error message `Map address 0x400000000000 failed`).
This is because the heap start address with ASan enabled was changed in 
[this commit](https://github.com/llvm/llvm-project/commit/fb77ca05ffb4f8e666878f2f6718a9fb4d686839).

Using the provided Dockerfile is an easy way to quickly test Teapot,
which contains all the necessary dependencies.

## Usage

1. Create a disassembly of the program of interest using Datalog Disassembly, generating the disassembled GTIRB file.
```shell
ddisasm --ir a.out.gtirb a.out
```

2. Call teapot to create an instrumented GTIRB file.
```shell
teapot a.out.gtirb a.inst.gtirb
```

3. Dump the assembly of the instrumented GTIRB file. 
Then, apply a sedscript to the assembly file due to limitations of `gtirb-pprinter`.
If using the provided Dockerfile, the script is available at `/teapot-scripts/fix_asm.sed`.
```shell
gtirb-pprinter --ir a.inst.gtirb --asm a.inst.S
sed -i -f scripts/fix_asm.sed a.inst.S 
```

4. Recompile the instrumented assembly file.
```shell
gcc -o a.inst a.inst.S -no-pie -nostartfiles -lcheckpoint_x64 -lhfuzz -lasan
```
Note: the builtin DIFT support library currently also requires `-lm` and `-lz` 
due to dependencies in tested applications, even if it is not used in the instrumented program.
We intend to eventually decouple this so that linking to these libraries even unused is not necessary.

5. The usage of ASan in the instrumented binary makes it unhappy, 
so set some environment variables to silence it.
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
