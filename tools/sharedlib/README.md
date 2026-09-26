# Binary-only selected-library conversion prototype

This is a deliberately narrow research prototype, not a general-purpose
ELF static linker. Full conversion/behavior evidence covers x86-64,
AArch64 shadow/MTE and RV64 under the contract below; Arm/RV execution is
QEMU evidence, not native. `convert.py` accepts one non-PIE executable, selected compiled
shared libraries and explicitly supplied external ELF dependencies. It never
uses workload sources, original objects, original application archives, or a
dynamic library disguised as an archive member.

The tested strategy is:

1. Validate the ELF binding/startup/unwind contract and complete dependency set.
2. Lift each input independently with the pinned DDisasm frontend.
3. Preserve symbolic GOT/PLT references, data pointers, symbol versions and CFI.
   Retain recovered in-text data boundaries as sized local OBJECT symbols so
   a fresh lift after relinking does not reinterpret those bytes as code.
   Print assembly, then assemble genuine target-architecture `ET_REL` objects.
4. Put only reconstructed selected objects into a deterministic archive. Link
   the executable object and whole selected archive into one non-PIE `ET_EXEC`.
   Verify that selected SONAMEs are absent from `DT_NEEDED` and every selected
   exported code/data symbol is defined in the output.
5. Validate ordinary behavior before instrumenting. Freshly lift the linked
   executable so selected cross-library calls are visible to interprocedural
   liveness and control-flow instrumentation.
6. Run all Teapot passes and link one matching runtime, with ASan added only
   afterwards. There is no original application archive in this final link.

`convert.py` is the portable core (Python 3.8+, GTIRB and pyelftools). The other
scripts are reproducible evaluation launchers tied to the dated worker layout.
They are not installed as Teapot CLI commands and do not change existing defaults.

## Opt-in archive extensions under validation

The input DSO may contain PIC, but the output remains an ordinary relocatable
archive linked into a **non-PIE executable before instrumentation**. No PIC
instrumentation, loadable instrumented DSO, or scratchpad/spilling redesign is
part of these extensions.

AArch64's exhaustive candidate decoder may warn while reading literal tables.
Only addressed operand diagnostics covered completely by recovered DataBlocks
and independently by an input OBJECT or `$d` mapping range are accepted. Any
overlapping recovered code, missing byte coverage, or other warning still
rejects conversion; the accepted evidence is saved per input.

- `--resolve-selected-versions` binds each selected SONAME/name/version to a
  stable static-link identity, retaining the correct default alias. External
  libc versions remain versioned. Old/default-version fixtures pass ordinary
  execution and byte-identical archive reuse across two callers on all three
  architectures, plus full instrumentation of caller A on all three (including
  AArch64 BTI). This is not yet an OpenSSL full-pipeline result.
- `--preserve-selected-lifecycle` retains custom selected init/fini callbacks
  and arrays. A normal `-fno-pic -fno-pie` helper, linked before instrumentation,
  preserves the tested constructor/registered-exit/finalizer ordering. RISC-V
  uses its array-based startup contract. Single-selected-library fixtures have
  ordinary reuse and full-instrumentation evidence on all three architectures;
  arbitrary sibling-DSO
  and external-library lifecycle interleaving is not yet established.
- `--preserve-nonlocal-jumps` permits the original libc context-restoration
  calls without redirecting them to Teapot rollback. Signal-mask restoration,
  saved continuations and surviving memory writes pass the signal/nonlocal-jump
  full-pipeline fixture on all three architectures (AArch64 software and BTI).
  Allowing an arbitrary input is not itself an instrumented-behavior pass.
- `--preserve-weak-imports` retains undefined weak binding and the pinned
  original breadth-first external dependency scope. Supplied-but-unneeded
  providers are not linked. Present/absent weak-provider fixtures pass ordinary
  x64 execution and archive reuse across distinct callers. Replaceable weak
  definitions and ambiguous selected exports remain rejected.

The ordinary-library cache excludes the unrelated caller's executable hash
but retains library/dependency/tool/converter/layout-policy inputs. It caches
uninstrumented reconstructed bytes, not caller-independent instrumentation.
Unnamed FDE starts are accepted only when their complete positive-length range
belongs to executable code; recovered-CFI validation remains mandatory.

## Tested outcome

Original x64 evidence lives under `workers/shared-library-20260921/`;
multi-architecture evidence is under `workers/shared-library-multiarch-20260921/`.

| Check | Result |
| --- | --- |
| Two-library x64 fixture | Calls, indirect function pointers, shared mutable data, data-pointer identity, 64-byte alignment and cross-library backtrace depth 6 preserved |
| Default shared libhtp 0.5.30, approved pinned corpus | 118/118 original dynamic runs; 118/118 ordinary monolith matches |
| Full x64 Teapot monolith | 118/118 status/stdout/application-log/non-report-stderr matches |
| Fresh monolith with NOP-preserving printer | 118/118 ordinary and instrumented behavior matches; all 810 mapped reports, including counters, match static baseline |
| Rejections | 29 expected failures, before lifting or creating a monolith |
| Ordinary cache | Warm IR/object reuse, ELF/dependency invalidation and corruption rejection; 33 additional behavior comparisons |
| RV64 link-before path | Corrected startup and native-branch printer: 118/118 ordinary and fully instrumented behavior; all 472 mapped reports including counters agree with the same-PIC reference |
| AArch64 link-before path | 118/118 ordinary and instrumented behavior for shadow/MTE; MTE matches all 1086 mapped reports/counters against the same-PIC reference; shadow matches 117/118 report cases, with its one difference traced to differing poisoned bytes beyond input |
| Arm/RV two-library fixtures | 11/11 ordinary cases each; current RV cold/warm cache hits all three entries, retains byte-identical executable/archive, and passes 11/11 each |
| Other architectures, PIE or stripped inputs | Explicitly unsupported, not silently converted |

The real workload validation is the approved 118-input `test_fuzz` corpus at
testcases revision `eddfd261a78affa0a9b47713d45d12e841a5984f`, not an invented 120th
corpus and not a claim that the separate C++ `test_all` suite was converted.
The ground-truth source build is unmodified apart from supplying the same
required, inactive specvariant header as the accepted baseline. It is compiled
with GCC 14, `-O2 -g -fPIC`, shared libhtp, a non-PIE executable and dynamic zlib.
No compression time-limit or workload-specific semantic patch is applied.

The converter container mounts only individual converter code, staged ELF files,
the pinned toolchain, external compiled libraries, output and optional cache.
`groundtruth/`, fixture C sources and original build objects are not mounted.
Container commands and input/tool hashes are retained with each conversion.

## Explicit semantic contract

- ELF64 little-endian x86-64, AArch64 and RV64.
  Executable input must be `ET_EXEC`, shared inputs `ET_DYN`, and executable
  entry must name the preserved `_start`. All input/output machines must agree.
  Architecture-specific relocation numbers, interpreter, linker emulation and
  cache identity are checked. RV64 requires LP64D with optional RVC; other ABI
  flags are refused. Arm/RV GNU property notes require a separate preserved
  enforcement contract and are currently refused, not stripped.
- Complete supplied dependency closure, unique selected SONAMEs and unambiguous
  strong global binding are required. Selected dependency cycles, unreachable
  selections, selected/external conflicting definitions, GNU-unique bindings,
  replaceable weak definitions, and (without the explicit opt-in above)
  non-CRT weak imports are refused.
  The executable's standard `data_start` alias is recognized explicitly.
- Default/local/hidden definitions, ordinary GOT/PLT calls and data relocations
  are reconstructed symbolically. COPY relocations and protected/internal
  visibility are refused. Dynamic symbol interposition via `LD_PRELOAD`, audit
  modules or hot-swapped providers is outside the contract.
- External version requirements are retained with `.symver`; selected version
  definitions/references require the explicit resolver above. There is no
  GOT/PLT/version text stripping.
- Selected TLS, IFUNC, unsupported dynamic-loader flags, text/RELR relocations,
  executable stacks, `dlopen`/`dlsym`/`dlvsym`/`dl_iterate_phdr` and related runtime
  lookup entry points are refused. Unselected system libraries can still use
  their normal loader features because they remain dynamic.
  `NOW`, `SYMBOLIC` under the unique-definition contract, and selected
  process-lifetime `NODELETE` are accepted; runtime unload remains unsupported.
- CFI is regenerated, not discarded as raw stale `.eh_frame` bytes. Original
  non-PLT FDE starts must have recovered `.cfi_startproc`; emitted objects must
  contain the corresponding FDEs. The fixture checks actual cross-library
  stack unwinding. C++ exceptions/LSDA and unsupported frontend diagnostics are
  refused; nonlocal jumps require the opt-in above. This is not universal
  unwind support.
- Selected library CRT callbacks, their arrays, local state and per-DSO
  `__dso_handle` are retained. Accepted callbacks must match narrow per-ISA glibc/GCC
  CRT instruction templates **and actual branch/GOT/data targets**. Names alone
  are not sufficient. Callable gmon/TM hooks and clone tables are rejected.
- Only byte-validated gmon-only `.init` and empty `.fini` stubs can be omitted from
  selected objects. Their dynamic tags must name those exact sections. Array
  address/size tags must describe retained arrays. Preinit arrays are rejected
  except for RV64's validated single executable `load_gp` CRT entry, which is
  retained with its callback. Its exact GP initialization and `_start` call are
  checked; selected-library/custom preinit remains unsupported.
  Without the lifecycle opt-in, custom constructors/destructors, renamed or
  body-mutated callback lookalikes, and redirected startup tags remain negative
  tests. The opt-in validates code ownership and preserves those callbacks.
- Array priorities respect the selected dependency graph. The accepted CRT
  registration callbacks are order-independent under the restricted contract;
  this is **not** a general emulation of loader ordering between sibling DSOs.
- Symbol tables are currently required to identify startup/unwind ownership.
  Stripped input support is not claimed. All binary recovery still depends on
  DDisasm's ordinary reconstruction accuracy; a successful link is not a proof
  over untested behavior.

## Experimental multi-architecture startup gates

Fresh dynamic libhtp builds on AArch64/RV64 pass the 118-input ordinary corpus
under QEMU 10.0.11. That is ground truth, **not** conversion evidence. The staged
converter inputs contain only compiled executable/DSO bytes and explicit
external ELF providers; their original source/objects stay outside the mount.

`test_startup_multiarch.py` validates both dependency closures and rejects 35
mutations covering ABI/interpreter mismatches, machine mixing, foreign/COPY
relocations, callback instruction/hook changes, array tags and RV64 preinit/GP
retargeting. The existing 29 x64 rejection cases still pass. This is an ELF-only
test; it does not claim link, unwind, execution or full instrumentation success.

Both first full attempts stopped at a DDisasm diagnostic for a unique local
GOT target (`_DYNAMIC`), before object generation. A separate generic C++ fix
passes four new tests and the 31-test C++ suite; the unique-local regression
fails on the original code. Independent fresh lifts of both input executables
are warning-free and retain liveness metadata. Later full conversions pass the
behavior gates above; the converter's diagnostic gate remains enabled.
Evidence and source-isolated commands are retained under
`workers/shared-library-multiarch-20260921/`. The accepted x64 tools, artifacts
and default Teapot behavior remain unchanged. No cross-architecture reusable
instrumentation or speculation-budget policy change is part of this extension.

The RV64 ordinary gate subsequently passed in `rv64-conversion-v5/`: all 118
cases match status/stdout/stderr/application logs, with genuine ET_REL archive
members and libhtp absent from final DT_NEEDED. That early result did not by
itself establish a Teapot or cross-library-unwind pass. `test_riscv_cfi.py` checks the RV64 ET_REL CFI
reader against the linker's decoded tables at two layouts, all 17 arithmetic
cases, five rejection cases and a real 21-FDE reconstructed object. The reader
does not rewrite object bytes. Fixed-width relocation semantics follow the
[RISC-V psABI](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#_relocations).
Unknown/variable-length forms and unresolved symbols fail closed. Nonzero SUB
addends are explicitly unsupported because the pinned GNU ld 2.42 applies them
with a different sign; zero-addend assembler-generated CFI is covered.

An early full-Teapot attempt caught a final-link startup defect even though
ordinary execution agreed: GNU relaxation changed the reconstructed GP initializer
into `mv gp,gp`. The private converter now disables RV link relaxation and rechecks
the actual final GP/preinit/_start instruction targets. The regression rejects
that retained v5 output and mutated call pairs; accepted original/cold/warm
executables pass. Current conversion, two-library cache and full-pipeline
results use this corrected validator. No Teapot GP-normalization guard was weakened.

### Matched controls and required frontend/instrumentation fixes

The original Arm static baseline uses GCC9 whereas the selected DSO uses GCC14.
Report comparisons therefore also use direct-link reference executables made
from the exact existing PIC objects. Those objects remain exclusively under
`groundtruth/` and never enter the binary-only converter. These are additional
verification controls, not alternative conversion outputs.

Required tool changes are generic: the DDisasm unique-local-GOT fallback
(`c9efdc01`), relocatable split fragments (`6e78c4dc`) and AArch64 owning-section
anchors (`73506f25`); Teapot RV pre-transfer insertion (`9303bf0`) and
external AUIPC/JALR wrapper recognition (`c2cd6da`); and printer preservation
of same-section RV conditional branches (`3fc00dd`). The last fix lets GAS
relax only branches that need it and removes all observed RV counter deltas.
The new printer passes 141 tests (one pre-existing Windows-only test is
inapplicable on Linux); this adds no PE/DLL conversion support.

All three DDisasm fixes were subsequently compiled together in a clean build
(binary SHA-256 `6098a63b10f9573e594e7b5fc77cc3133e7f336de75bddb8db8b87aa1ee3eaaa`).
It passes 31 C++ and nine focused Python tests with recorded before/after
source and tool hashes. Fresh ordinary conversions using that build, the
current converter and current printer pass all 118 inputs on each architecture.
All three final executables are byte-identical to the accepted conversions;
Arm object/archive hashes differ before linking. Existing passing instrumented
artifacts were not replaced. See `*-combined-frontend-v1/` in the multiarch
worker and `workers/baseline-runtime-20260921/ddisasm-combined-private-v1/`.
These are targeted gates, not a claim of a passing all-architecture DD suite.

Current multi-architecture corpus evidence:

- RV: `rv64-native-branches-v1/`, all 118 ordinary/full-pipeline checks and
  all 472 mapped report/counter comparisons pass.
- Arm MTE: `arm64-current-mte-v1/` and
  `arm64-matched-reference-mte-v1/report-compare-v3/`, all 118 checks and
  all 1086 mapped report/counter comparisons pass.
- Arm shadow: `arm64-matched-reference-shadow-v1/report-comparison-v2/`,
  all 118 behavior checks and 117/118 report cases match. In `40-auth-basic.t`,
  speculation reads `#` versus `?` from already-different poisoned bytes past
  the input; only the latter reaches the base64 table load and ensuing
  conditional, explaining two additional reports. See `arm64-shadow-trace-v1/`.
  Raw inequality is retained, not normalized away or labeled an exact pass.
- Frozen converter gates: 29 negative contracts, two positive/35 mutated
  startup closures, RV CFI arithmetic/layout/rejection tests, and final-linked
  RV startup mutation tests. Final evidence is in
  `workers/baseline-unit-20260921/private-converter-final-gate-v1/`.

These link-before results do not establish reusable per-library instrumentation
on Arm/RV. The separate x64 reusable prototype retains the ROB-cutoff limitations
documented below; default liveness, ROB250 and nesting-off settings are unchanged.

## Reports and the instruction-budget difference

The full converted monolith produces 396 MDS, 94 CACHE and 320 PORT reports.
These totals equal the accepted static-link x64 baseline, but totals are not the
only comparison. `attribute_reports.py` retains raw reports and maps report call
instructions to the original selected library's functions. All 35 observed sites
belong to selected libhtp code, not merely executable/runtime code.

All 118 inputs match the multisets of:

`function, gadget kind, report-call ordinal within that function/kind, tag,
checkpoint-function sequence`.

For the original `instrumented-v2` artifact, including the instruction counter
reduces exact per-input matches to 34/118:
724/810 individual reports have the same counter and 86/810 are exactly +3.
The difference is in `htp_normalize_uri_path_inplace`: ordinary printing expands
a reachable four-byte NOP into four one-byte NOPs. The freshly lifted monolith
therefore charges four instruction-budget units instead of one. The retained
ordinary disassemblies and normalized diff show this change; no assembly filter
was applied to conceal it. This can affect untested paths near ROB=250, so the
runs are **not fully report-equivalent**. This older artifact is retained;
the fresh validation below does not retroactively change its result.

Source attribution identifies function-entry source lines and static report-call
ordinals, not exact original gadget source instructions. Raw memory/checkpoint
addresses are kept but are not assumed equal across layouts. No cross-ISA
equivalence or general determinism claim is made.

### Fresh NOP-preserving printer validation, September 21

A generic printer fix preserves the exact bytes of each multi-byte x86 NOP,
rather than expanding it into several one-byte instructions. It uses the
printer's native byte directive for both ELF and MASM output. No workload names,
assembly filters, instruction-budget policy changes or disabled passes are
involved. A separate fresh pipeline used this printer for both reconstruction
and instrumented assembly, retaining the accepted baseline tools and binaries.
The fix is committed locally in gtirb-pprinter as
`be4b787708bf4ee0e241da8cc9f013e019d6d298`. Its full Python suite passes
**139 tests**, with **one Windows-only skip**; all three new regression tests
pass, including 40 encoding/ISA/syntax reassembly combinations. Final evidence
is under `workers/baseline-unit-20260921/pprinter-candidate-full-v10-20260921/`.
The candidate was built before that commit, so the retained source hashes/diff,
not its older embedded version string alone, identify the tested code.

- Ordinary binary-only monolith: **118/118** strict behavior matches.
- Full default instrumentation, ROB=250, nesting off, ASan linked afterwards:
  **118/118** strict behavior matches.
- Report multisets, using the attribution keys above **plus instruction
  counters**, match the static baseline on **118/118 inputs / 810 reports**.
  The old converted artifact's 86 counter differences are absent.
- Ordinary binary SHA-256:
  `d243da441e187812b58193c2f4a1dfb8e2efae52f3aeae342c686c4d815a05d4`.
- Instrumented binary SHA-256:
  `c891a763e8489b71c39e28864227f1437632b7e31c037747f84c24b299181956`.

Commands, tool/source hashes, original inputs, recovered objects, assembly,
binaries and per-input records are under
`workers/nop-boundaries-20260921/libhtp-validation-v1/`; report mappings and
comparisons are in its sibling `report-comparison-v1/`. The separate
`report-comparison-ordinary-corrected-20260921/` fixes a comparison-helper path
mistake: the original ordinary-disassembly diff accidentally used the
instrumented binary. That mistake did not affect the report comparison. The
corrected ordinary-function diff has only one additional trailing NOP; it is
not a claim of byte-identical executable layout.

This closes the observed link-before NOP counter difference on the tested
corpus, not the separate liveness-dependent cutoff issue in reusable component
instrumentation. Nor is corpus agreement proof of equivalence on untested
inputs. Earlier timings apply to the old converted binary, not this fresh one.

A subsequent timing run does use the NOP-preserving binary above. On the same
native x64 host/CPU 0, one warmup plus ten deterministically shuffled 118-input
rounds per variant produced **5,192/5,192** strict behavior passes. Median round
times were 0.443 s for the original dynamic binary, 2.351 s for the accepted
static instrumentation, 2.351 s for the new converted binary and 2.413 s for
reusable v3. The median paired converted/static ratio was **1.002** (range
0.976–1.021); this does not establish a runtime speedup. Startup and report/log
I/O are included, and other host workloads remained active. Results are in
`workers/baseline-runtime-20260921/timing-compare-nop-preserved-20260921/`.
Its legacy JSON key `converted_v2` names the new executable here; the manifest's
path and SHA-256, not that old label, identify the measured binary.

## Ordinary-artifact cache, not an instrumentation cache

`--cache-dir` stores two immutable, content-addressed stages:

| Stage | Key / reuse boundary |
| --- | --- |
| Recovered IR | Input ELF contents and basename; DDisasm binary and loaded native libraries; frontend source/patch provenance; frontend options |
| Ordinary ET_REL | Above plus converter source hash, role/array priority, complete executable/selected/external contents and ordering, printing policy, printer/compiler/assembler/ar/linker identities, native dependencies, Python executable/package contents, and source provenance |

Every cached artifact has a SHA-256 entry in its manifest. Retrieval checks the
recipe, exact file set and hashes, rejects symlinks, and copies rather than
hardlinks files. Cache entries are installed atomically and not overwritten.
Corruption fails with `CACHE_INTEGRITY`; it is not quietly treated as success.
Manifests are trusted local metadata, not signatures against a malicious writer.

The ET_REL key is intentionally conservative: even an executable/binding-order
change invalidates object reuse; unchanged component IR can still be reused.
Instrumentation and runtime-layout fields are explicitly null because these
objects are ordinary. The tested warm fixture performs no new lift/print/assembly
and produces a byte-identical monolith. The final monolith is always relinked.

Teapot currently treats one module/`.text` as the instrumentation domain. Merely
instrumenting DSOs separately would retain rollback at unresolved external direct
calls, embed component-local indirect-target bounds, and emit duplicate global
guard symbols/local guard indices. Renaming those globals alone would not make
cross-library transient calls/returns or coverage correct. Retained GTIRB/ET_REL
artifacts here are **not reusable per-library instrumentation**. The coordinator
owns a separate experimental implementation of that strategy; no pipeline or
pass changes for it are included in this converter worktree.

A future instrumented cache additionally needs binding/redirection contracts,
rewriter/Teapot/LRA source and patches, all pass options, ROB/nesting settings,
runtime ABI and tag-storage/DIFT/ASan/MTE/shadow-stack layouts, global range and
coverage registration layout, external-wrapper selections, and backend tool
identities. The ordinary cache is not a substitute for those keys or validation.

## Reproduction in this evaluation workspace

Run from `workers/shared-library-20260921`; choose fresh output revision names.
All containers use `--rm`, read-only inputs/toolchain, no network, at most eight
CPUs and an initial 40-GiB limit. Evidence and temporary files stay in this worker.

```sh
# Source-isolated reconstruction, after groundtruth ELF staging exists:
python3 teapot/tools/sharedlib/run_conversion.py \
  fixture-v2 fresh-fixture main libalpha.so libbeta.so --cache cache/ordinary
python3 teapot/tools/sharedlib/run_conversion.py \
  libhtp fresh-libhtp test_fuzz libhtp.so.2 --cache cache/ordinary

# Strict ordinary corpus comparison:
python3 teapot/tools/sharedlib/compare_corpus.py \
  --binary artifacts/libhtp/fresh-libhtp/monolith \
  --out artifacts/libhtp/fresh-ordinary \
  --baseline artifacts/libhtp/dynamic-baseline-v1
```

`build_inputs.py` and `build_negative.py` are separate ground-truth builders, never
converter inputs. `test_negative.py` runs in the source-free test container with
the exact mounts recorded in the evidence; its output includes every expected
reason and confirms rejection occurs before lifting/final output. `test_cache.py`
records hit/invalidation/corruption and ordinary behavior evidence.

`run_instrumentation.py` records the full container, rewrite and one-runtime link
commands. It uses ROB 250 (matching default runtime), nesting off, every required
pass enabled, fresh DDisasm liveness and `x64-la48-asan-new`. There is no Python
liveness fallback in the tested run. Dynamic `libasan.so.8` is first in
`DT_NEEDED`; execution uses `setarch x86_64 -R` and only
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`. ASan link-order checks are not
suppressed. Optional zlib/math wrapper archives and Honggfuzz are linked as
required; the final application contribution is only the rewritten object.

## Artifact index and provenance

- `inputs/fixture-v2/`, `inputs/libhtp/`: ELF-only input staging.
- `groundtruth/`: separate sources/build objects and build-command logs.
- `artifacts/fixture-v2/root-check-v1/`: coordinator's independent fixture rebuild.
- `artifacts/libhtp/v3/`: hardened ordinary reconstruction, all IR/assembly/objects,
  archive, link map, manifests and process logs.
- `artifacts/libhtp/dynamic-baseline-v1/`, `ordinary-v2/`: all 118 ordinary records.
  `v2/monolith` and hardened `v3/monolith` are byte-identical.
- `artifacts/libhtp/instrumented-v2/`, `instrumented-v2-corpus/`: full rewrite,
  exact final link, raw reports and all 118 strict comparisons.
- `artifacts/report-attribution-v2/`: per-input/site comparison and NOP difference.
- `artifacts/negative-v2/`: all 29 explicit rejection results.
- `artifacts/cache-tests-v1/`: cache validation, 33 behavior checks and timings.
- `artifacts/*/cache-cold/manifest.json`: full source/tool/native-library/Python
  fingerprints; `cache/ordinary/` contains only ordinary cached artifacts.

Key SHA-256 values:

```text
dynamic test_fuzz:
21a957c525fd0774f5975ee0dcb6387862a6421ef7efe5e0b3df2d1155a03a50
ordinary libhtp monolith (v2/v3):
53dc51a09ef9df9630ec687a9a851f34c73a3ac2e78825ab6a174fef009984b3
fully instrumented libhtp monolith:
2c0f44c8b0198e801b12b4e772895068eaecda7b1ed93ad79396806fe3971c10
matching x64 libcheckpoint.a:
b86e7035f68c547a9b58b6e24a0a568cfa3ba68d405816b4342ed6a72e9ee3a8
```

Source base: Teapot `09b3e16`, runtime `311c700`, DDisasm integration `3173e508`,
printer integration `a39dbac`, plus the preserved GTIRB/libehp baseline patches.
Full revisions and patch fingerprints are in conversion manifests. The tested
frontend's version strings predate merge commits; binary hashes and the baseline
build-provenance records identify what actually ran. The container is
`teapot-multiarch-eval:1586139-tools-v4`, with C++ Capstone 5.0.1 and pinned LLVM
LLD 19. System packages and main source worktrees were not modified.
