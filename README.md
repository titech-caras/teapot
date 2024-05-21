# Teapot

Teapot is a static binary rewriting & dynamic fuzzing based Spectre gadget detector, 
described in the paper "Efficiently Uncovering Spectre Gadgets in COTS Binaries with Speculation Shadows" (under review).

This repository contains the Teapot binary rewriter. 
The submodule `libcheckpoint_x64` contains the runtime library.

## Notes on Anonymous Repository

As this repository was anonymized, the `libcheckpoint_x64` submodule can be accessed [here](https://anonymous.4open.science/r/libcheckpoint_x64-C810).
(The link inside the paper is broken for various reasons :( so please use this one.)

## Notes on naming

Teapot was codenamed NaHCO3 in its development.
We are currently in the process of migrating the code to match the names described in the paper.

## Requirements

Teapot static rewriter requires a Python version between 3.8 and 3.10.
It also requires the following packages for interfacing with GTIRB format:

- `gtirb`
- `gtirb-rewriting`
- `gtirb-functions`
- `gtirb-capstone`
- `gtirb-live-register-analysis`

Teapot requires `llvmlite` for generating optimized DIFT instrumentation, and the version we use only support LLVM 14.
If the debug symbol manipulation functions are used, `pyelftools` is also required.

Teapot runtime library requires `libasan`. 
If coverage is enabled, executing the instrumented binaries requires `libhfuzz` 
or any other fuzzer library that implements the Sanitizer Coverage interface.  

Note that newer `libasan` versions cause failures in DIFT initialization 
(with the error message `Map address 0x400000000000 failed`).
This is because the heap start address with ASan enabled was changed in 
[this commit](https://github.com/llvm/llvm-project/commit/fb77ca05ffb4f8e666878f2f6718a9fb4d686839).

Using the provided Dockerfile is an easy way to quickly test Teapot.

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
```shell
gtirb-pprinter --ir a.inst.gtirb --asm a.inst.S
sed -i -f scripts/fix_asm.sed a.inst.S 
```

4. Recompile the instrumented assembly file.
```shell
gcc -no-pie -nostartfiles -lcheckpoint_x64 -lhfuzz -lasan -o a.inst a.inst.S
```

5. The usage of ASan in the instrumented binary makes it unhappy, 
so set some environment variables to silence it.
```shell
export ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=false
```

6. The program can be executed, and it provides information the Spectre gadgets found to `stderr`.
Alternatively, the program can be tested with a fuzzer.

