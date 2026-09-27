# Teapot

Teapot is a static binary rewriting & dynamic fuzzing based Spectre gadget detector, 
described in the paper "Teapot: Efficiently Uncovering Spectre Gadgets in COTS Binaries" in [CGO 2025](https://dl.acm.org/doi/10.1145/3696443.3708936).

[Listen to Teapot on suno.ai!](https://suno.com/song/907f1bb5-ad72-4a9f-9e08-053d121c696c)

This repository contains the Teapot binary rewriter.
The submodule `libcheckpoint` contains the runtime library.

### Checkpoint efficiency options

Python LRA supplies x64 arithmetic-flag and AArch64 NZCV liveness within each
function, using may-preserve/read-before-write summaries for known callees.
Local calls may preserve flags under IPA register allocation; returns and tail
exits retain flags left unwritten from entry. External/PLT and indirect calls
use the ABI boundary. DDisasm still supplies GPR masks. `--conservative-flags`
restores the older flag policy. `--force-checkpoint-df` uses the DF-saving x64
entry everywhere; normally a CFG scan selects it only where DF may be set.

`--x64-vector-state=auto` (default) selects each checkpoint independently:
integer-only saves no vector registers, low-XMM saves XMM0–7 with eight MOVAPS,
and full saves supported extended state with XSAVEOPT (XSAVE/FXSAVE on older
hosts). Separate fixed entries record their restore stub in each checkpoint;
rollback jumps through that pointer, including for mixed-profile nesting.
MXCSR is preserved independently, even when all vector registers are dead.
Checkpoint choices use DDisasm's per-instruction vector-piece masks (including
the `liveRegisterSetsHigh` word). Missing masks require full saves. Python
vector analysis is only a diagnostic `--debug-vector-liveness` cross-check;
the Python flag analysis remains authoritative for flags. Known local calls,
tails and returns carry vector dependencies interprocedurally: even ABI-volatile
vectors may survive a local call under IPA register allocation. Only external
and unknown calls use the vector ABI kill/argument summary. Returns also retain
XMM0–1, and missing masks, opaque state or unresolved
jumps force full. Explicit `xmm0-7`, `sse` and `avx` are **unsafe overrides**:
they bypass the liveness and extended-state safety checks and can silently
corrupt program results. In particular, forcing `xmm0-7` loses live higher
XMM registers, wide vector lanes, mask registers and x87 state. Use `auto` or
`full` unless the narrower state requirement has been independently proved;
choosing a smaller profile is not itself such a proof. Runtime builds can
override the profile with `-DTEAPOT_X64_VECTOR_STATE=...`, with the same risk.
Report callbacks always preserve full supported vector/x87 state.

Coverage callbacks are off in ordinary runtime builds. Build the runtime with
`-DTEAPOT_ENABLE_COVERAGE=ON` when linking honggfuzz; using `hfuzz-clang` or
`hfuzz-gcc` as the CMake compiler selects that default automatically. This does
not disable gadget reports or their DIFT instrumentation.

## Requirements

Teapot static rewriter requires Python 3.8 or newer.
It also requires the following packages for interfacing with GTIRB format:

- `gtirb`
- `gtirb-rewriting`
- `gtirb-functions`
- `gtirb-capstone`
- `gtirb-live-register-analysis`

Instructions are decoded with Capstone 6.0.0-Alpha11 (`capstone==6.0.0a11`,
also through `gtirb-capstone` 1.1.2 or newer); Capstone 5 is not supported.

Use the DDisasm and gtirb-pprinter revisions pinned in the Dockerfile. They
consume native Capstone 6 operands and recover relocatable startup addresses,
direct-transfer targets and AArch64 page references in the frontend. Teapot
no longer repairs these older frontend outputs: re-lift existing inputs with
the pinned DDisasm before rewriting them.

`requirements.txt` pins Teapot's `gtirb-rewriting` fork because its scoped
rewrite preparation reduces runtime and peak memory on large RV64 modules.
The Docker image verifies this API while building. For local development, mount
the fork at `/workspace/gtirb-rewriting`; the image's `PYTHONPATH` gives that
checkout precedence over the installed pinned package.

Teapot also requires `llvmlite` for generating optimized DIFT instrumentation.
Text DIFT uses LLVM `-O3` lowering, targeting RV64IMAFD on RISC-V and Armv8-A
FP/Advanced SIMD on AArch64. RISC-V patches declare that ISA to the assembler
without compression, preserving the rewriter's four-byte padding alignment;
compressed application instructions remain supported. Generated RISC snippets preserve any FP/SIMD
registers and control state they use; this does not extend application DIFT
tracking to vector registers. No RVV or SVE requirement is introduced.
RISC DIFT propagation, operand capture and LLVM replay use liveness to select
spare GPRs and omit unnecessary saves. Live fallback registers still use the
existing spill areas; missing liveness is all-live, and FP/SIMD saves remain.

Transient DIFT defaults to `--transient-dift=lazy`: the same LLVM tag model
batches propagation until a policy/tag reader or block boundary. A load's
queued tag is applied after its destination update. Memory-tag changes are
logged before mutation so rollback restores them; unread pending effects are
discarded on rollback. `--transient-dift=eager` flushes the same LLVM model at
every instruction for comparisons; it is not a separate tag implementation.
x64 REP keeps its dedicated per-element handling.

Teapot prefers ddisasm's interprocedural `liveRegisterNames` and
`liveRegisterSets` metadata. Known internal calls are analyzed through the CFG,
including conditional tail calls and returns across recovered function boundaries;
external calls use the target ABI, and unresolved indirect transfers remain
conservative. Direct transfers to weak definitions retain the conservative
register policy, since relinking can replace their bodies. Rewriting migrates
masks for surviving instructions; normal and
transient copies retain independent entries. Each rewrite round refreshes the
analysis cache and explicitly retains masks for its state-preserving edits.
The LRA API's default refresh instead invalidates old masks after unspecified
edits, including potentially affected predecessors and callers, without running
Python analysis. Inserted/replaced instructions without metadata are all-live,
not reanalyzed in Python. Invalid individual entries are removed with a warning,
leaving the remaining DDisasm results intact. Missing or incompatible tables produce a fallback warning;
the Python fallback keeps all registers live at block exits and every scratch
GPR live at calls, preserving private assembly-helper conventions.

Relayout preserves unmapped integral ELF symbols as absolute values. RISC-V
instruction anchors may be zero-size private CodeBlocks outside the function
metadata; passes walking section blocks must ignore empty blocks.

Outside a source checkout, select the configuration installed by the matching
runtime build (adjust `/opt/teapot-runtime` to its install prefix):
```shell
export TEAPOT_AARCH64_SHADOW_STACK_CONFIG=/opt/teapot-runtime/include/aarch64_shadow_stack.h
export TEAPOT_DIFT_LAYOUT_FILE=/opt/teapot-runtime/share/libcheckpoint/DiftLayoutData.cmake
```
These files remain owned by libcheckpoint. Other runtime constants, among them
the scratchpad and memory-history layout, are copied by hand into
`teapot/configs/runtime.py` and `teapot/configs/slots.py` and must match
`libcheckpoint/include/checkpoint.h`.

See [`libcheckpoint/README.md`](libcheckpoint/README.md) for runtime
build options, shared AArch64 shadow-stack configuration, ASan/MTE tag-storage requirements, DIFT layout profiles,
optional wrapper libraries, and architecture-specific qemu notes.

Using the provided Dockerfile is an easy way to quickly test Teapot,
which contains all the necessary dependencies.
The image builds the pinned frontend from source and applies the two small
GTIRB/libehp patches kept in this repository. See [docker/README.md](docker/README.md)
for build options and local source contexts for unpublished commits.
It also includes an isolated Ubuntu arm64 sysroot with MTE-capable glibc at
`/opt/aarch64-mte-sysroot` and a newer static qemu runner at
`/usr/local/bin/qemu-aarch64-mte`; the normal `/usr/aarch64-linux-gnu` cross
sysroot is left unchanged.

## Current Analysis Limits

- AArch64/RV64 saved-return poisoning tracks one decoded LR/RA save and its
  matching reloads through the CFG, independently of unwind metadata. It
  poisons after the store and clears before each reload. Unsupported lifetimes
  produce per-function warnings, coverage counts and a reason histogram; arbitrary pointer aliases
  and nonlocal exits are not modeled. MTE omits return-slot poisoning rather
  than poison neighboring data sharing its 16-byte allocation-tag granule.
- Generic multi-byte DIFT loads currently sample the first byte's tag, not the
  union over the entire access. Tags appearing only in later bytes can be missed.
- x64 REP MOVS/STOS/LODS/CMPS/SCAS propagate tags in normal execution, including
  every byte of each completed element, direction, overlap and early stopping.
  LLVM batches flush at REP boundaries. Transient REP executes one element per
  instruction-budget unit, checking the limit before each iteration. Each
  executed element receives DIFT, memory history and enabled access policies;
  this is an iteration-cost approximation, not a hardware uop model.
  DIFT-blacklisted functions omit propagation, but retain the element loop,
  memory history and enabled checks.
  Reentrant signal-handler tag observations are not supported.
  Noncanonical REPNE copy/load/store encodings trigger a warning and rollback
  before transient execution, rather than aborting the rewrite. Transient REP
  requires checkpoints enabled to enforce its iteration budget.
- AArch64 GPR LDP/LDNP/LDPSW/STP/STNP use separate per-element tags in both
  common and LLVM text DIFT, including all bytes of each element. This does not
  establish equivalent precision for vector or atomic-pair transfers.
  Scalar pre/post-indexed loads and stores also keep address writeback tags
  separate from transferred data tags, retaining first-byte load sampling.
- RV64 GP-relative loads, stores and address calculations are normalized before
  the transient copy, using a destination register, a conservative LRA spare,
  or a 16-byte stack-spill frame. Later passes instrument those spill accesses.
  Unsupported metadata and out-of-range PC-relative relocations are errors.
  Raw copies of `gp` are also refused without symbolic metadata. Nonempty
  `riscvUnresolvedPcrelReferences` frontend diagnostics prevent rewriting;
  missing diagnostics produce a warning. Regenerate older inputs with the local
  frontend to obtain this check; an absent table is not an empty checked table.
  Unwinding through the temporary spill window is not supported. This does not
  fix raw printer-only GP relayout or add Teapot RV32 support.
- The allocation-free reporting runtime passes all 120 AArch64 MTE `test_fuzz`
  inputs and all 341 `test_all` cases under QEMU. Native MTE remains separate;
  see [runtime tests](libcheckpoint/README.md).

## Usage

Keep relocation evidence when building the input. For whole-program rewriting,
build PIE, or link a fixed-address executable with `-Wl,--emit-relocs` (for
example, `cc -fPIC -no-pie -Wl,--emit-relocs ...`). Keep its symbol and relocation
sections. The selected-library converter requires the latter, non-PIE form.
The frontend rejects ambiguous absolute data words instead of guessing whether
an integer is a pointer. Its explicit `--allow-ambiguous-data-pointers` option
restores the old heuristic, with a warning; it is not a safe default for
rewriting. Rebuild affected inputs with relocations rather than adding that
override to a batch.

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
ASan shadow checks cover every granule touched by an access, including unaligned
crossings. Checks up to eight bytes use an unrolled path; wider accesses use a
range loop. AArch64 MTE uses the corresponding 16-byte granule checks in software.

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
The script is `scripts/fix_asm.sed` in this checkout; the image does not contain it, so mount the checkout
(the image expects it at `/workspace/teapot`).
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

## Source-line debug information (optional)

Source-line preservation is **off by default**. It supports linked ELF64 inputs
on x64, AArch64 and RV64, with DWARF 4 or 5. Keep the original, unstripped ELF:
the input GTIRB does not contain its DWARF. `pyelftools` (in `requirements.txt`)
reads the original line tables. For example:

```shell
ddisasm --ir app.gtirb app
teapot --debug-source app app.gtirb app.inst.gtirb
gtirb-pprinter --ir app.inst.gtirb --asm app.raw.S
python -m teapot.debug_lines app.inst.gtirb app.raw.S app.inst.S
sed -i -f scripts/fix_asm.sed app.inst.S
```

Then assemble/link `app.inst.S` with the matching target compiler and Teapot
runtime as above. Use the printer's normal **assembler** mode, not its debug
listing mode. Do not strip debug sections from the linked result. The extra
post-print step emits `.file`/`.loc` directives; GNU as creates the relocated
DWARF line table and compilation-unit information. No manual directives or
extra NOPs are needed. `--compact-output` is supported.

The normal copy's surviving original instructions map to their input source
files, lines, columns and discriminators. Paths resolve against each input
compilation unit's directory, so equally named files in different directories
remain distinct. A debugger can use these locations for line breakpoints,
source listing and stepping. Source files must still be available locally
(use the debugger's source-path substitution if the build directory moved).

This is **line information**, not a transplant of variable/type/inline DIEs or
a repair of unwind information. Backtrace unwinding still depends on the
existing frame information. Generated instrumentation and the transient copy
are deliberately unmapped (line zero). Original instructions wholly replaced
or removed by normalization are not assigned guessed locations; the rewrite
prints how many original instructions retain mappings. Gaps and non-instruction
line-table addresses are skipped safely. A mismatched ELF, absent DWARF, or no
matching lines is an error. This CLI path accepts one module, not the experimental
component-cache driver. With the option omitted, no source metadata, labels or
additional rewrite round is created.

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues.
