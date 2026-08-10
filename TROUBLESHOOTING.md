# Teapot Troubleshooting

Common issues when executing Teapot and instrumented binaries are collected here.

**Instrumentation stuck at InsertCheckpointsPass 100%**

`InsertCheckpointsPass` is the last Teapot instrumentation pass, and from here we hand the control to GTIRB to apply the calculated instrumentations on the binary.
This may look like Teapot is frozen, but GTIRB is in fact still working to apply the instrumentation, and this can sometimes take a very long time.
We could not display a progress bar since it is difficult to track the GTIRB internals.

**Conservative call liveness**

Teapot must keep conservative call liveness enabled for all ISAs: instrumentation should not treat ABI caller-saved GPRs as dead after calls.
Do not disable this to make register allocation easier; add a principled cross-call analysis or an architecture-specific safe scratch strategy instead.

**Execution of instrumented binary fails with `Map address 0x400000000000 failed: Address already in use`**

Check AddressSanitizer (ASan) version in the system; it may be too new for Teapot to function (see [README.md](https://github.com/lin-toto/teapot/blob/main/README.md)).
On x86-64, use the newer-ASan DIFT profile instead: instrument with `teapot --dift-layout x64-la48-asan-new ...` and build `libcheckpoint` with `-DTEAPOT_DIFT_LAYOUT=x64-la48-asan-new`.
Alternatively, download an old version of `libasan.so` and `LD_PRELOAD` it into the instrumented binary.

**RISC-V instrumented binary fails under qemu with DIFT mapping errors**

For Sv39, run qemu with the low user VA space reserved: `qemu-riscv64 -R 0x4000000000 -L /usr/riscv64-linux-gnu ...`.
The binary must also be linked with ASan; libcheckpoint does not provide a fallback ASan shadow.
The RV64 smoke path also depends on a RISC-V-capable `gtirb-pprinter` runtime.
If `ddisasm --asm` or `gtirb-pprinter` fails with missing RISC-V support, check
that the local pprinter build is the one being used. Some GNU assembler builds
reject `%got_pcrel_hi(...)` forms that LLVM accepts; use the LLVM assembler path
or a known-good cross toolchain for RV64 ASan links.

**AArch64 instrumented binary faults in DIFT shadow memory under qemu**

Use matching AArch64 DIFT profiles for instrumentation and libcheckpoint.
For shadow-tag qemu user-mode smoke tests, `aarch64-vma39` with `qemu-aarch64 -R 0x8000000000 -L /usr/aarch64-linux-gnu ...` may be sufficient.
For AArch64 MTE tag-storage smoke tests, use `aarch64-vma42` with `qemu-aarch64-mte -cpu max -R 0x40000000000 -s 33554432 -L /opt/aarch64-mte-sysroot ...`; under qemu, `aarch64-vma39` can place DIFT shadow memory where the dynamic loader or stack lives.
The provided Docker image keeps the old Focal cross sysroot in `/usr/aarch64-linux-gnu`, and adds a newer MTE-capable arm64 glibc sysroot in `/opt/aarch64-mte-sysroot`.
`GLIBC_TUNABLES=glibc.mem.tagging=1` enables glibc malloc MTE tagging in that sysroot; Teapot's MTE software check accepts matching logical/allocation tags and reports mismatches as poisoned.
Wider profiles pre-map larger DIFT ranges and can spend longer in startup or consume high host RSS.
If the fault is reported as a stack overflow immediately after startup, increase qemu's target stack with `-s 33554432`.
When adding AArch64 instrumentation, do not reuse a shadow-stack frame offset or fixed scratchpad save window across passes or subpatches that may be nested. DIFT, memlog, ASan, gadget, coverage, control-flow, text-DIFT, and generic ABI first-spill frames must stay disjoint.

**AArch64/RV64 libhtp compressed-response smoke differs from baseline**

The libhtp compressed-response tests include compression-bomb timing behavior.
Full Teapot instrumentation can make those paths cross libhtp's time budget, so
semantic smoke builds should call
`htp_config_set_compression_time_limit(cfg, 1000000)` in the affected fixtures.
This uses libhtp's supported one-second cap; otherwise truncated decompression
under qemu can look like rollback corruption.

**Linker error `undefined reference to 'xxxyyy__dift_wrapper__'`**

Teapot DIFT does not yet support this external library function.
Teapot currently only provides DIFT support for the external library functions used by the programs in [teapot-testcases](https://github.com/lin-toto/teapot-testcases/).
If this error occurs, create a DIFT wrapper for the missing function under `libcheckpoint/src/dift_wrappers/`, and recompile `libcheckpoint`.

Note that even for the programs in [teapot-testcases](https://github.com/lin-toto/teapot-testcases/), the compiler may sometimes optimize the library calls into DIFT unsupported functions.
Similarly, in this case, a DIFT wrapper also needs to be implemented.

**Warnings during instrumentation**

The following warnings are expected behavior of Teapot.
Because of our rather special usage of GTIRB, it gets surprised from time to time.
These warnings are absolutely safe to ignore.

- successor to CodeBlock(uuid=UUID(...), ...) is ambiguous
- WARNING: Moving symbol to first block of section: __bss_start
- WARNING: found overlapping element at address xxyy

On the other hand, these warnings may require attention, although in most cases they are also safe to ignore.

- Warning: DIFT Propagation does not support <CsInsn 0x123abc [xxyy]: instruction>
- Warning: unsupported symexp at <CsInsn 0x456def [xxyyzz]: instruction [rip+0x7890]>

These warnings indicate that some instrumentation passes of Teapot encountered an instruction that it cannot handle.

Generally speaking, Teapot DIFT does not support `rep` prefixes well, which may slightly affect detection capability.
One exception to this is `repz ret`, which is found for binaries targeted for AMD platforms.
This instruction is merely a workaround of `ret`, and is supposed to modify exactly no DIFT tags anyway.

Please open an issue if these warnings do lead to binaries crashing or major gadgets going undetected.

**Warning during recompilation of instrumented binary: `Warning: segment override on 'lea' is ineffectual`**

This warning is safe to ignore.
