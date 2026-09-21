# Teapot Troubleshooting

Common issues when executing Teapot and instrumented binaries are collected here.

**Instrumentation stuck at InsertCheckpointsPass 100%**

`InsertCheckpointsPass` is followed by GTIRB patch application. Use
`--rewrite-progress` to distinguish active patching from a stalled process. Make
sure the container was built from the pinned requirements, or mount the local
fork at `/workspace/gtirb-rewriting`; older images prepare the entire expanded
module and can take hours on RV64 `test_all`.

**Live-register metadata and fallback**

Teapot prefers ddisasm's interprocedural `liveRegisterNames` and
`liveRegisterSets` metadata. External calls follow the target ABI; unresolved
indirect transfers, replaceable weak targets and missing instruction entries
remain all-live. Regenerate old frontend metadata before relinking weak
placeholders against a different implementation. If the
table is absent or incompatible, Teapot uses Python analysis, which keeps every
allocatable scratch GPR live at calls on every ISA. This also preserves inputs
to local assembly helpers with private register conventions. Do not weaken
either conservative path to make register allocation easier.
Individual invalid entries are dropped with a warning and become all-live;
valid DDisasm entries remain in use. Source transitions are logged after refresh.
Offset validation does not establish validity after a change to register effects
or CFG semantics. `refresh()` conservatively invalidates old module masks;
`refresh(preserve_liveness=True)` is reserved for dependency-preserving edits,
as used by Teapot's instrumentation rounds. It is not an equivalence checker.

If a local DDisasm rebuild reports that `gtirb::schema::ArchInfo` is missing,
check its pprinter include path as well as `LD_LIBRARY_PATH`. The old image
headers are not interchangeable with the local pprinter library; mount both
the matching source headers and build directory at CMake's recorded paths.

**Execution of instrumented binary fails with `Map address 0x400000000000 failed: Address already in use`**

Check AddressSanitizer (ASan) version in the system; it may be too new for Teapot to function (see [README.md](https://github.com/lin-toto/teapot/blob/main/README.md)).
On x86-64, use the newer-ASan DIFT profile instead: instrument with `teapot --dift-layout x64-la48-asan-new ...` and build `libcheckpoint` with `-DTEAPOT_DIFT_LAYOUT=x64-la48-asan-new`.
Alternatively, download an old version of `libasan.so` and `LD_PRELOAD` it into the instrumented binary.

For the newer-ASan profile, shared objects and the stack must stay in its
`0x700000000000..0x800000000000` application window. High-entropy ASLR can
occasionally put a shared object in the `0x600000000000` DIFT reservation.
For fixed-layout research runs, launch with `setarch x86_64 -R ./program ...`.
Do not replace existing mappings or treat a failed reservation as usable shadow.

**RISC-V instrumented binary fails under qemu with DIFT mapping errors**

For Sv39, run qemu with the low user VA space reserved: `qemu-riscv64 -R 0x4000000000 -L /usr/riscv64-linux-gnu ...`.
The binary must also be linked with ASan; libcheckpoint does not provide a fallback ASan shadow.
The RV64 smoke path also depends on a RISC-V-capable `gtirb-pprinter` runtime.
If `ddisasm --asm` or `gtirb-pprinter` fails with missing RISC-V support, check
that the local pprinter build is the one being used. Some GNU assembler builds
reject `%got_pcrel_hi(...)` forms that LLVM accepts; use the LLVM assembler path
or a known-good cross toolchain for RV64 ASan links.
Signal recovery uses the native Linux `ucontext_t` layout. The image's QEMU
4.2.1 fails the signal-return PC/mask regression; host QEMU 10.0.8 passes it.
Use the current host emulator rather than guessing alternate signal-frame slots.
The standalone RV64 landing-state fixture also faults with the image emulator
but passes all six variants on host QEMU 10.0.8. For Python regression runs,
setting checkout `PYTHONPATH` alone is insufficient: select the local DDisasm
in `PATH`, local `PPRINTER_PATH`/printer library, and verified QEMU executables.
The current local frontend build is `var/ddisasm-lra-rebuild/bin/ddisasm`;
`var/ddisasm-local-riscv-env-build2` predates later symbolization fixes.
For the old image's CTest, set the build directory as the working directory;
`--test-dir` is ignored there, and "No tests were found" is not a passing suite.

RV64 GP references require fresh symbolic metadata from the local frontend.
Teapot expands them before copying code and reports destination-reuse, spare and
spill counts. Do not preserve old numeric GP displacements or add hidden spills
when printing. The generated AUIPC/LO pair has finite reach; a linker range error
must not be bypassed by truncating the expression. Unwinding inside its temporary
16-byte spill frame is outside the current contract.

If assembly reports a missing `%pcrel_hi` despite a valid IR anchor, check that
the printer places zero-sized instruction labels after block alignment. A label
before `.align` can differ from the AUIPC address even when both share an IR
offset. Use the corrected local printer; do not remove alignment or guess a
different anchor in the assembly.

**AArch64 instrumented binary faults in DIFT shadow memory under qemu**

Use matching AArch64 DIFT profiles for instrumentation and libcheckpoint.
For shadow-tag qemu user-mode smoke tests, `aarch64-vma39` with `qemu-aarch64 -R 0x8000000000 -L /usr/aarch64-linux-gnu ...` may be sufficient.
For AArch64 MTE tag-storage smoke tests, use `aarch64-vma42` with `qemu-aarch64-mte -cpu max -R 0x40000000000 -s 33554432 -L /opt/aarch64-mte-sysroot ...`; under qemu, `aarch64-vma39` can place DIFT shadow memory where the dynamic loader or stack lives.
If shadow-tag mode reports `Map address 0x2000000000 ... File exists` at startup,
also select `aarch64-vma42` on both sides and reserve `-R 0x40000000000`.
The provided Docker image keeps the old Focal cross sysroot in `/usr/aarch64-linux-gnu`, and adds a newer MTE-capable arm64 glibc sysroot in `/opt/aarch64-mte-sysroot`.
`GLIBC_TUNABLES=glibc.mem.tagging=1` enables glibc malloc MTE tagging in that sysroot; Teapot's MTE software check accepts matching logical/allocation tags and reports mismatches as poisoned.
MTE report counts can vary across repetitions of the same binary. Record the
binary, sysroot, tagging environment and QEMU `-seed` when comparing counts;
check program output separately. Fixed-seed spot checks help isolate variation
but are not a general determinism guarantee.
Wider profiles pre-map larger DIFT ranges and can spend longer in startup or consume high host RSS.
If the fault is reported as a stack overflow immediately after startup, increase qemu's target stack with `-s 33554432`.
When adding AArch64 instrumentation, do not reuse a shadow-stack frame offset or fixed scratchpad save window across passes or subpatches that may be nested. DIFT, memlog, ASan, gadget, coverage, control-flow, text-DIFT, and generic ABI first-spill frames must stay disjoint.

For ASan smoke runs, set `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1` in the
launcher's environment before invoking qemu, not only through qemu's `-E`.
In the tested AArch64 libasan.so.5 setup, `-E` alone still ran LeakSanitizer
and failed at exit; the same binary passed with the launcher environment set.

**Saved-return poisoning coverage warnings on AArch64/RV64**

Shadow mode requires one full-width, aligned LR/RA stack save and matching
reloads with provable SP/FP offsets and CFG lifetimes. Poisoning follows the
store; clearing precedes each reload and its operand checks. Missing unwind
rows are not a reason to omit it. Multiple lifetimes, helper-managed saves,
unknown frames and unresolved control flow produce per-function warnings and
coverage counts; mandatory simulation passes remain enabled. Analysis tracks
SP/FP-relative accesses, not arbitrary pointer aliases. Exceptions and `longjmp`
can leave stale poison, as on x64. MTE saved-return poisoning remains omitted.

**AArch64 returns into a report site outside simulation**

Prefer a label on the single `blr` instruction being suppressed. The runtime
also recognizes the rewriter's exact `adrp x16` + `add/ldr x16` + `blr x16`
expansions of labelled `bl` calls and suppresses only their final call. Arbitrary
address-setup sequences are not recognized; check the actual labelled bytes.

**MTE libhtp aborts in the allocator while reporting**

The old permissions reader used `fopen`, `calloc` and `getline` during simulation;
one allocator abort was traced to that path at depth one. Reporting now uses
bounded storage and syscall I/O without heap-backed streams or libc formatting.
Relinking the same full-pipeline objects with this runtime changes the MTE sweep
from 102/120 to 120/120 matches. This is distinct from compressed-input timeouts
and does not establish native MTE correctness. Do not reintroduce libc output
buffers on poisoned runtime storage: `snprintf` itself is intercepted by ASan.

**AArch64/RV64 libhtp compressed-response smoke differs from baseline**

The libhtp compressed-response tests include compression-bomb timing behavior.
Full Teapot instrumentation can make those paths cross libhtp's time budget, so
semantic smoke builds should call
`htp_config_set_compression_time_limit(cfg, 1000000)` in the affected fixtures.
This uses libhtp's supported one-second cap; otherwise truncated decompression
under qemu can look like rollback corruption.

**Versioned-symbol relocations fail when linking ASan**

Keep `.symver` directives for dependencies that were not redirected to wrappers.
GNU ld can reject these ASan links with unresolvable PLT/GOT relocations; the
evaluation image's older lld can produce invalid AArch64 copy relocations.
LLVM lld 19 links the tested x64 and AArch64 objects with versions retained.
When cross-linking, keep the target sysroot and ASan preinit object consistent.

**AArch64 ASan crashes before the application starts**

First test an empty program linked with the same sanitizer and target sysroot.
On the validation host, the unmodified Debian `libasan8-arm64-cross`
`14.2.0-19cross1` library faults in `__interception::InterceptFunction` while
initializing: its `real_strcat` pointer is an OBJECT in read-only `.text`.
This reproduces without Teapot. Do not make sanitizer code pages writable or
disable interceptors to bypass it. The validation image's dynamic ASan5 and
matching `libasan_preinit.o` work with the AArch64 shadow runtime; select a
verified sanitizer/sysroot combination and link ASan only after rewriting.
Keep the failing library's version/hash and the empty-program result with the
validation evidence, rather than treating this startup failure as a rewrite bug.

**Linker error `undefined reference to 'xxxyyy__dift_wrapper__'`**

Teapot DIFT does not yet support this external library function.
Teapot currently only provides DIFT support for the external library functions used by the programs in [teapot-testcases](https://github.com/lin-toto/teapot-testcases/).
If this error occurs, create a DIFT wrapper for the missing function under `libcheckpoint/src/dift_wrappers/`, and recompile `libcheckpoint`.

Note that even for the programs in [teapot-testcases](https://github.com/lin-toto/teapot-testcases/), the compiler may sometimes optimize the library calls into DIFT unsupported functions.
Similarly, in this case, a DIFT wrapper also needs to be implemented.

**Reports differ sharply across architectures**

Check that input calls such as `fread` reference `__dift_wrapper__` symbols in
the printed assembly. RV64 PLT references may be AUIPC anchors, not callable
aliases; use call relocations and symbol forwarding without renaming anchors.
Older RV64 sweeps with no wrappers do not establish input-tagged DIFT coverage.
AArch64 scalar writeback must retain address-only tags, not loaded/stored data
tags. Compare source-site membership, not just totals; fix `QEMU_RAND_SEED` when
comparing MTE runs to avoid mixing propagation changes with tag randomization.

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

x64 REP string DIFT preserves the original instruction in normal execution
and updates tags from its completed iteration count. Transient execution uses
a bounded element loop: charge one budget unit before each iteration, log data
and tag writes, and apply enabled memory/port policies. A zero count costs zero;
CMPS/SCAS stop on their actual comparison result. Backward/overlapping transfers
and address-size overrides are supported. Other REP forms are not string DIFT.
`repz ret`, found in some AMD-targeted binaries, does not require tag propagation.
An old printer can drop string prefixes, including the address size or FS/GS
source segment. Use the local prefix-preserving printer, not a sed workaround.
Noncanonical `REPNE` MOVS/STOS/LODS cause a warning at their address and rollback
before transient execution: they are not the documented repeat forms and
Capstone can omit their implicit counter accesses. Normal instruction bytes
remain intact. Disabling checkpoints while instrumenting transient REP is
rejected because the element loop requires an iteration budget.

Please open an issue if these warnings do lead to binaries crashing or major gadgets going undetected.

**Warning during recompilation of instrumented binary: `Warning: segment override on 'lea' is ineffectual`**

This warning is safe to ignore.
