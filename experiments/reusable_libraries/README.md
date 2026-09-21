# Reusable instrumented x64 components (experimental)

This is an opt-in, binary-only **final-link** experiment. It is not support for
loading instrumented DSOs independently. Existing Teapot CLI behavior and all
non-component defaults are unchanged. Do not use a cached object with an
arbitrary linker script/runtime or call the internal `LinkedComponent` API
without the driver's input checks.

The input contract is the selected-library converter's narrow x64 ELF subset:
one non-PIE executable, selected compiled DSOs, and explicitly supplied external
ELFs. Unsupported TLS, binding/versioning, IFUNC, custom startup, runtime lookup,
nonlocal unwind, PIE and other architectures are rejected. Workload source and
original application objects/archives are not converter inputs. See
`tools/sharedlib/README.md` in the separately integrated converter changeset.

## Implementation

1. Validate the complete binding/dependency/startup contract before lifting.
   Each selected exported function must be uniquely recovered in `.text`.
2. Lift original inputs separately and retain original DDisasm liveness/CFI in
   `lift.gtirb`. Do not print/re-lift an ordinary monolith before instrumenting
   individual components.
3. Conservatively mark **all tracked registers and flags live** in the working
   IR. A reusable object cannot trust dead-register assumptions obtained without
   every future caller. This over-approximates validated frontend metadata; it
   is not Python fallback or omitted instrumentation. Missing masks already
   mean all-live in the register manager. A more efficient inter-component
   liveness contract is future work, not assumed safe here.
4. Run all default instrumentation, ROB 250, nesting off, x64 LA48/ASan layout.
   Exported normal entries receive the complete existing marker/redirection
   before normal-path stack poisoning, in the same rewriting round. Direct
   transfers to validated providers can continue into their instrumented code;
   nonzero symbol addends do not receive that exemption. Unknown/external
   transfers, barriers and syscalls retain their existing rollback/checks.
5. Preserve shared symbolic references and CFI, then print/assemble real ET_REL
   objects. The only assembly postprocessing is the existing section-flags
   script, whose hash is part of the cache recipe.
6. Resolve application-wide normal/transient bounds at final link. Runtime
   `.text`, PLT, init/fini and trampolines are excluded from those ranges.
   Every component uses a link-time coverage-index base and distinct guard
   storage. The base is calculated from the actual guard-start symbol **after
   input-section alignment**, not the location counter before `KEEP`.
7. Link one matching runtime and dynamic ASan afterwards. Final ELF checks
   verify bounds, full exported markers, coverage offsets/non-overlap, selected
   definitions, reconstructed CFI, ASan-first ordering and absent selected DSOs.
   Successful structural checks are explicitly not behavior verification.

## Instrumentation cache

Immutable content-addressed entries contain original/instrumented IR, raw/fixed
assembly, the instrumented object, command logs and SHA-256 manifests. Recipes
include input ELF bytes, role/initializer priority, complete selected dependency
contents and binding names, external provider bytes, Teapot/rewriter/LRA Python
sources, converter/driver/section-fix hashes, frontend/native libraries, fixed
image identity, pass options, conservative liveness policy, ROB/nesting/layout,
and matching runtime/wrapper archives. Corrupt artifacts fail hash validation;
objects copied to an output directory do not alias the cached files.

A library recipe deliberately excludes unrelated executable **bytes**, but not
its provider-name/binding contract. Different main programs with the same
validated contract can therefore reuse exactly the same instrumented libraries.
Changing a selected library or the contract conservatively invalidates the set.
The final executable is always relinked and structurally checked. This cache is
distinct from the ordinary IR/object cache in `tools/sharedlib`.

## Evidence and limitations

Evidence is retained under `workers/reusable-library-20260921/`, with independent
test evidence under `workers/baseline-unit-20260921/` and
`workers/baseline-runtime-20260921/`. The root coordinator's `STATUS.md` records
which revision has completed which checks. Earlier artifacts remain identifiable
and are not silently relabelled as passing a later contract.

- Original fixtures cover cross-library direct/indirect calls, shared data and
  function pointers, alignment, unwinding and tail calls.
- Root GDB traces of the cross-call fixture demonstrate direct, register-
  indirect and tail transfers into another component's transient code at depth
  one. Final shared counters show speculative writes did not leak. New revisions
  require their own execution checks.
- The unwind fixture's original depth is 6; both instrumentation strategies
  report 7. Root traces identify the extra returned frame as ASan's backtrace
  interceptor. The original-vs-instrumented stdout comparison is therefore not
  called an exact match; the two instrumented strategies match each other.
- Preliminary libhtp component runs pass all 118 approved inputs with strict
  status/stdout/application-log/non-report-stderr checks. All 810 observed
  reports match the static/link-before runs by function, kind, static report-call
  ordinal, tag and checkpoint-function sequence. These preliminary runs preceded
  the explicit all-live contract and are retained as comparison evidence only.
- **Full report equivalence is not established.** In the preliminary run,
  instruction counters differ for 177/810 reports against the static baseline:
  176 are -11 in `htp_utf8_decode_allow_overlong`, one is -3 in
  `htp_list_array_get`. The same basic-block costs are still charged, but at
  different positions. Preserved metadata marks the UTF-8 return flags live in
  the linked monolith and dead in the original DSO; the existing restore-point
  pass chooses different flag-safe insertion points. This prompted the stricter
  caller-independent contract above. The all-live revision must be compared
  independently; it does not magically restore baseline counter timing.
- Link-before conversion also expands a reachable four-byte NOP into four
  one-byte NOPs before re-lifting (86 reports gain 3). Direct component rewriting
  avoids that extra lift. No assembly filter hides the difference. Counter
  placement/instruction differences can change observations near ROB=250, so
  corpus agreement is not a proof of identical cutoff behavior on untested paths.
- No AArch64/MTE/RISC-V component implementation, parallel execution, nested
  speculation, independently loaded DSO runtime, arbitrary constructor ordering
  or full C++ exception support is claimed.

## Workspace reproduction

These launchers intentionally use the dated evaluation workspace's pinned tools
and runtime. Use fresh output directories; retain failure logs. Containers have
no network, read-only inputs/toolchains, 16-GiB memory and four-CPU limits, and
`--rm`. Only the output/cache are writable. Do not expose workload build trees
through the ELF-only input directory.

```sh
python3 experiments/reusable_libraries/run_workspace.py \
  --workspace /home/lin/teapot-multiarch \
  --inputs /absolute/elf-only-input-directory \
  --executable main --select libalpha.so --select libbeta.so \
  --out /absolute/fresh-output-directory \
  --cache /absolute/component-cache
```

The launcher records exact commands, input/tool/runtime hashes and the final
structural-validation result. Behavior and report comparison are separate
steps. Native x64 validation uses `setarch x86_64 -R` and
`ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`, without suppressing ASan link-order
checks. Object manifest `rewrite_seconds` records the original cold build, not
time spent on a cache hit.

## Final v3 checks (September 21)

- Expanded Teapot suite: **147/147** (`reusable-teapot-full-147` in the unit
  worker). Existing defaults are included in this regression screen.
- All-live cross-call fixtures A and B: **9/9 each**, matching original status,
  stdout and non-report stderr; exactly one expected runtime header. B reused
  both instrumented library objects, byte-identically, while rewriting its
  changed executable. Root's `cross-component-A3.trace.log` verifies real
  transient direct/indirect/tail execution and rollback for this revision.
- All-live libhtp: **118/118** strict comparisons, 396 MDS / 94 CACHE / 320 PORT
  reports (`reusable-libhtp-v3-corpus` in the runtime worker). Binary SHA-256:
  `9c81304936714a45f45dfe8b3c22fdc9918d1cc54fa25aec9d5242208269a426`.
- Fresh v3 attribution matches sites/tags/checkpoint functions for **118/118**;
  counters match on **29/118** complete inputs. There are 177 changed report
  instances versus static and 263 versus converted link-before, with the same
  difference pattern described above. All-live preservation did not eliminate
  the existing insertion-point/NOP differences. It is not full cutoff equivalence.
- A warm libhtp run hit both instrumented component entries and produced the
  byte-identical final executable in **3.43 seconds**, including validation and
  relinking. The cold rewrite portions alone took 9.87 seconds for the harness
  and 192.62 seconds for libhtp. These are observed single-run timings, not a
  controlled speedup benchmark. Native corpus process-wall sums were 2.48 seconds
  for components and 2.75 for the earlier link-before run, also not a rigorous
  runtime-overhead comparison.
- A private copied-cache corruption test was refused with
  `cached artifact hash mismatch: component.o`; no executable was produced.
  Original cache hashes remained unchanged (`cache-integrity-negative` in the
  unit worker). Neither the real cache nor accepted binaries were corrupted.

The remaining promotion gate is report/cutoff policy, plus broader supported-
input and architecture coverage. This is an independently reviewable prototype,
not a default-path replacement or a claim of identical behavior on every input.
