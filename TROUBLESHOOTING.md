# Teapot Troubleshooting

Common issues when executing Teapot and instrumented binaries are collected here.

**Execution of instrumented binary fails with `Map address 0x400000000000 failed: Address already in use`**

Solution: check AddressSanitizer (ASan) version in the system; it may be too new for Teapot to function (see [README.md](https://github.com/lin-toto/teapot/blob/main/README.md)).
Alternatively, download an old version of `libasan.so` and `LD_PRELOAD` it into the instrumented binary.

**Linker error "undefined reference to 'xxxyyy__dift_wrapper__'"**

Solution: Teapot DIFT does not yet support this external library function.
Teapot currently only provides DIFT support for the external library functions used by the programs in [https://github.com/lin-toto/teapot-testcases/](teapot-testcases).
If this error occurs, create a DIFT wrapper for the missing function in `libcheckpoint_x64/dift_wrappers.c`, and recompile `libcheckpoint_x64`.

Note that even for the programs in [https://github.com/lin-toto/teapot-testcases/](teapot-testcases), the compiler may sometimes optimize the library calls into DIFT unsupported functions.
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

**Warning during recompilation of instrumented binary: `Warning: segment override on `lea' is ineffectual`**

This warning is safe to ignore.
