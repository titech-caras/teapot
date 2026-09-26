# Opt-in AArch64 BTI experiment (2026-09-22)

This is an isolated prototype, not the default backend or a production merge.
The user approved replacing the first marker with BTI and requested AArch64
only for now; this supersedes the earlier literal-marker objection for this opt-in
path. x64 and RV64 remain software.

## Contract

Select `--target-identification=aarch64-bti` when rewriting. Build the matching
runtime with `-DTEAPOT_EXPERIMENTAL_AARCH64_BTI=ON`, then link the rewritten
application with `-Wl,-T,/path/to/libcheckpoint/cmake/AArch64Bti.ld`. ASan is linked
after rewriting, as with the software pipeline. The strong initialization symbol
ensures an ordinary runtime archive cannot silently satisfy this new backend.

The first marker word becomes `bti jc`; the second magic word is retained.
Normal-to-transient redirection after the marker is unchanged. For an aligned
BR/BLR target, the transient checker retains both normal and transient range
checks, omitting only the two normal-marker loads. Unaligned normal targets
retain the full byte-address predicate. Application RET and any transfer not
proved BTI-checked retain full software checking and the existing main-return
exception. No checkpoint, memlog, DIFT, report, ASan or liveness pass is skipped.
Default nesting remains off; the speculation window remains 250 instructions.

The linker puts transformed normal text in its own 64-KiB-aligned region. The
runtime validates the application/guard/transient bounds and enables PROT_BTI
only on that region. It does not emit an ELF-wide BTI property or guard shadow,
runtime, trampoline, or external-library pages. Both range checks are essential:
a hardware landing in some other library is not an admitted application target.

Before activation, the runtime scans every aligned normal-text word. Every
non-trapping hardware-compatible landing (BTI and compatible PAC hints) must be
the complete new two-word marker. Unexpected non-trapping landings left in
guarded text cause a clear exit 78, not excess acceptance. BRK/HLT have exception
priority over BTI and are allowed only with the matching runtime trap path and
startup enforcement probes described below. This permits unchanged in-text
data that happens to encode a trap; it does not admit execution past that word.
The private feature-smoke changes outline decoded native
PAC/BTI/BRK/HLT instructions into `.teapot_bti_native`, outside both application
target ranges. A direct branch executes the original instruction and returns
without changing LR/SP/registers merely for the detour. This does not relax the
non-trapping landing scan, range checks, or software RET check. At
least one transformed marker is required. **This prototype requires normal
executable text to remain unchanged after validation.** Self-modifying normal
code and later changes to its protection are outside the supported contract;
report-site NOP patching is in the unguarded transient copy, not this region.

The outlining addition is still experimental: executed regressions cover
classic SP-only PACIASP/PACIBSP plus authentication, with QEMU pointer
authentication enabled and disabled. They do **not** establish PC-dependent
FEAT_PAuth_LR/PACM semantics, asynchronous unwinding while inside a helper, or
source-PC identity for application BRK/HLT handlers. These are outstanding
compatibility limits, not a claim that arbitrary native landing sequences are
fully supported or that this private change is merge-ready.

Startup checks HWCAP2_BTI and mprotect success, executes valid and invalid
destinations before protection, then forks a short enforcement probe on the
actual final normal mapping. It requires the valid destination to execute and
the invalid one to raise the expected signal at the exact target with BTYPE set.
Separate children verify BRK and HLT deliver their expected trap signals at the
exact destination with saved BTYPE, on the same protected mapping.
An advertised feature, a successful-but-ineffective mprotect, or a property note
alone is insufficient. Failure refuses activation; it does not silently run the
load-free checker without hardware enforcement. Use the software rewrite on an
unsupported host.

## Signal path

BTI fault PC is the destination, not the originating branch. The handler requires
SIGILL, an expected native/QEMU si_code, exact si_addr/PC, an aligned guarded PC,
and nonzero saved BTYPE. It uses `checkpoint_cnt` to distinguish ordinary and
simulated execution:

- At depth zero, clear only saved BTYPE and resume the **same PC**, not PC+4.
  Guarding remains enabled, so another invalid transfer faults again.
- At positive depth, clear BTYPE and redirect to the existing
  `restore_checkpoint_MALFORMED_INDIRECT_BR` path. Memory/DIFT/register/guard/
  budget recovery remains the runtime's normal checkpoint restore.
- Other signals still use the previous forwarding/rollback rules. A genuine
  illegal instruction retried at depth zero faults with BTYPE zero and is not
  repeatedly mistaken for a BTI landing violation.

The opt-in runtime additionally installs SIGTRAP handling. A guarded indirect
target whose actual word is BRK (SIGTRAP/TRAP_BRKPT) or HLT (SIGILL) is never
treated as an ordinary BTI same-PC retry: at depth zero its original signal and
unchanged context go to the saved disposition. At positive depth it uses the
same malformed-target rollback as an invalid BTI landing. Exact aligned PC,
si_addr, signal code and saved BTYPE are checked before classifying such a trap.
Ordinary runtime builds without the experimental option do not intercept
SIGTRAP. All of this uses the runtime's existing signal-forwarding contract;
it does not promise additional POSIX signal-action semantics.

The runtime's three trusted saved-PC continuations use `ret x16` in this mode,
avoiding a BTI fault when returning to an interior normal instruction. These are
runtime-controlled continuations, not additional allowed application targets;
application returns still have the full software predicate.

## Evidence so far

Host is x64 Linux, execution is **QEMU AArch64 10.0.11 `-cpu max`**, not native Arm.
The 64-KiB layout accommodates 4/16/64-KiB page isolation by construction; actual
native 16/64-KiB execution has not been tested.

- Full private Teapot suite: 162 passed (one expected RV metadata warning).
- Shadow runtime: 19 checkpoint/signal tests passed, including enabled-backend
  normal same-PC recovery and a live depth 0→1→2→1→0 rollback chain.
- MTE runtime: the same 19 tests plus two MTE setup tests passed (21/21). This
  is runtime coverage, not a new full-workload BTI/MTE instrumentation sweep.
- Thirteen activation gate tests passed: valid activation; no HWCAP; mprotect
  rejection; deliberately ignored protection; bad second word; overlapping
  shadow; unexpected BTI c/j/jc and PACIASP/PACIBSP. The September23 trap update
  changes BRK/HLT data cases from rejection to accepted activation, with actual
  trap-priority probes. All13 gates pass under that revised contract.
- September23 trap regression: old runtime reproduces exit78 on the OpenSSL
  table word. New runtime passes23 shadow,25 MTE and18 ordinary-mode runtime
  checks, without skips. The trap fixtures cover BR/BLR via x0/x16/x17, default
  dispositions and saved siginfo handlers, exact PC/BTYPE forwarding, and real
  checkpoint memory/DIFT/register/guard/budget restoration. An independent
  24-case probe covers guarded and unguarded branch source pages. This remains
  QEMU evidence, not a claim of native Arm verification.
- Fresh current-DDisasm/current-printer libhtp ordinary roundtrip: 118/118 exactly
  matching original status/stdout/stderr/application logs.
- Fresh full software and BTI pipelines: 118/118 each, both producing 605 MDS,
  141 cache and 293 port reports. Each BTI run verified enforcement on 1,703,936
  guarded bytes with 1,590 validated markers. Report totals alone are not a
  proof of equal report sites, order, counters or memory provenance.

All 1,039 ordered reports matched in generated-site identity, function ownership,
kind, tag, instruction counter and exact checkpoint-block UUID across all 118
inputs. Local labels were recovered via a debug-only relink whose every allocated
section matched the executed binary byte-for-byte. All 8,616 static report
identities also corresponded. Generator IDs plus function ownership are not
independent original-instruction provenance; finite agreement is not a universal
equivalence proof.

Raw memory addresses are deliberately not hidden. Of 269 unequal addresses,
268 map to the same `.rodata` offsets in the two link layouts. One report on
`40-auth-basic.t` reads different elements of the same base64 decoding table.
Read-only QEMU/GDB traces show why: before the matching checkpoint, at depth
zero, the byte at `0x1555ba00a0f` is already `0x76` (software) vs `0x4c` (BTI).
The input ends at `0x1555ba009fe`, and this later byte is ASan-poisoned (`0xfa`).
The simulated decoder reads past the input and subtracts 43, yielding table
indices 75 and 33 respectively. Both executions report at counter 229 with the
same checkpoint/site/tag, then roll back normally. This is an explained
pre-existing poisoned-memory-content difference, not byte-identical memory
reports, and no guest state was modified to make the comparison pass.

Two serial whole-corpus sweeps each measured software 45.454/45.481 seconds and
BTI 46.721/46.698 seconds: about **2.7% slower** with BTI in this QEMU setup.
These figures include process startup, validation/fork probe, ASan and emulation;
they do not isolate the branch-check cost or predict native performance. No
native speedup is claimed. Existing native BTI/PAC sequences may be conservatively
rejected; mixed marked/unmarked system DSOs remain external and unguarded.

## Server-local reproduction and artifacts

Workspace `/home/lin/teapot-multiarch`:

- Private worktrees: `workers/aarch64-bti-20260922/teapot` and its separate
  `libcheckpoint` worktree; production sources are unchanged.
- `workers/bti-execution-20260922/python-v2` and `runtime-build-v2` retain commands,
  source hashes and raw test logs.
- `workers/aarch64-bti-20260922/run_libhtp.py` performs a new lift, full rewrite,
  printing, assembly, matching runtime build, final ASan link and smoke run.
  `compare_libhtp.py` pins all 118 approved seeds and compares application output
  exactly. Only recognized report/header/activation records are separated.
- `libhtp-input-v1`, `libhtp-software-v1`, `libhtp-bti-v1` retain IR, assembly,
  objects, binaries, linker maps, ELF inspections, hashes and stage timings.
- `corpus-original-v3`, `corpus-ordinary-v1`, `corpus-software-v1`, `corpus-bti-v1`
  retain every command, status, output and ordered report stream.
- `activation-gates-v2` records the 13 small real-code gate cases. Its fixture
  stubs unrelated runtime initialization, not activation or the enforcement
  probe. The main corpus uses the full runtime and dynamically linked ASan5.
- `report-attribution-v3`, `memory-trace-{software,bti}-v1`, `gdb-{sw,bti}-v2`,
  and `corpus-timing-{software,bti}-r{1,2}` retain attribution, before-checkpoint
  memory evidence and serial timing. `runtime-mte-v1/Testing/Temporary/LastTest.log`
  retains the 21 MTE runtime results.

These artifacts are local to the evaluation server; Git does not carry them.

## Architectural references

- [Arm BTI tutorial](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/enabling-pac-and-bti-on-aarch64)
  describes guarded destinations and return behavior.
- [QEMU AArch64 translator](https://raw.githubusercontent.com/qemu/qemu/master/target/arm/tcg/translate-a64.c)
  documents the wider landing set and exception-priority cases; the experiments
  above, not a CPU-name assumption, establish enforcement on the installed QEMU.
