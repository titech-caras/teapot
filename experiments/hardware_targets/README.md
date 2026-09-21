# Hardware target identification: rejected replacement, reproducible probes

Status (2026-09-21): **no production hardware backend is enabled or added**.
Software remains the default and only implemented target-identification policy;
RV64 is unchanged. These experiments establish actual AArch64 BTI enforcement
under QEMU and counterexamples to replacing Teapot's policy with landing checks.
The native x64 host does not provide IBT. There is no equivalent-backend speedup
claim and no hidden instrumentation-disable option.

## Exact contract

The current emitted predicate is

```
accept(t) = (transient_start <= t < transient_end)
         OR (text_start <= t < text_end AND both 32-bit marker words match at t)
```

It accepts every byte offset in the transient interval, not only instruction or
block starts. A later alignment, instruction-fetch, or execution fault is a
different event. The normal marker bouncer redirects to the corresponding
transient copy whenever the checkpoint count is nonzero. The current two-word
comparison may read beyond `text_end` when the target itself is inside the range;
the regression preserves this detail, not a new eight-byte in-range condition.

The existing transient pass checks indirect calls/jumps and returns, retaining
its existing `main__teapot__` return exception. An external or trusted-runtime
landing is not admitted just because it contains a hardware landing instruction.
Checkpoints, conservative liveness, memory history, DIFT and reporting are
unchanged. Default nesting remains off, the runtime remains single-threaded,
and the normal speculation window remains 250.

## What was measured

The native host is AMD EPYC 9V33X, Linux 6.12.86+deb13-amd64. CPUID reports
IBT=0 and SHSTK=1. `ARCH_SHSTK_STATUS` succeeds with an enabled mask of zero.
The kernel is configured for kernel IBT and user shadow stacks, but a binary
with `GNU_PROPERTY_X86_FEATURE_1_IBT` still executes a non-ENDBR target.
This is not user IBT enforcement. Linux's documented user shadow-stack API is
not an IBT-enable API. See the [kernel CET documentation](https://www.kernel.org/doc/html/next/x86/shstk.html)
and [v6.12 user API](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/x86/include/uapi/asm/prctl.h).

AArch64 evidence is **QEMU user emulation 10.0.11, `-cpu max`, not native Arm**.
The fixture checks HWCAP2_BTI, successful `PROT_BTI`, a valid landing, an invalid
landing fault at the exact target PC, and execution of that same instruction
after removing `PROT_BTI`. It also checks a GNU-property-marked ELF against an
otherwise equivalent unmarked ELF: the marked ELF's invalid landing faults and
the unmarked ELF's invalid landing executes. A `cortex-a53` negative control
has no HWCAP2_BTI, rejects PROT_BTI with EINVAL, and does not enforce landings.
ELF notes alone are compatibility declarations, not proof of execution behavior;
see [Arm's ELF/loader ABI](https://github.com/ARM-software/abi-aa/blob/main/sysvabi64/sysvabi64.rst),
[Linux arm64 hwcaps](https://cdn.kernel.org/doc/html/latest/arch/arm64/elf_hwcaps.html),
and [glibc's BTI mapping code](https://raw.githubusercontent.com/bminor/glibc/master/sysdeps/aarch64/dl-bti.c).

QEMU reports these BTI violations as SIGILL, si_code=ILL_ILLOPN (2), with the
fault PC/address equal to the attempted target. Linux v6.12's native
[`do_el0_bti`](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/arm64/kernel/traps.c)
uses ILL_ILLOPC (1). The probes retain this difference and the saved BTYPE bits;
they do not relabel the QEMU result as native behavior.

| Executable target | Current software predicate | QEMU BTI transfer |
| --- | --- | --- |
| Normal two-word Teapot marker | Accept | Call/jump faults |
| Normal unrelated `bti jc` | Reject | Call succeeds |
| `bti jc` prepended to the old marker, at prefix | Reject | Call succeeds |
| Same sequence, at the old marker (`+4`) | Accept | Jump faults |
| Normal unmarked instruction reached by `RET` | Reject | Executes |
| Unmarked transient instruction, unguarded page | Accept | Executes |
| Same transient instruction after guarding page | Accept | Call faults |
| Outside-range external/trusted hardware landing | Reject | Executes |

Thus both excess acceptance and lost acceptance are demonstrated. BTI is not
an eight-byte marker comparison. `RET` does not require a BTI landing; Arm
documents this in its [BTI tutorial](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/enabling-pac-and-bti-on-aarch64).
Intel likewise distinguishes indirect CALL/JMP tracking from shadow-stack
return protection in its [CET description](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html).

## Why a bounded hybrid was not enabled

Keeping the complete software predicate and adding normal-page BTI is still
unsafe for today's literal marker set: the accepted marker is not a BTI. Merely
prepending BTI fails at both the prefix and the still-accepted interior marker.
Applying BTI to transient pages narrows their intentionally unrestricted range.

Protection is page-granular. In the accepted AArch64 libhtp shadow ELF inspected
for this experiment, normal text ends at `0x3b3060`, sharing a 4-KiB page with
`restore_checkpoint_SIGSEGV` at `0x3b3810`. Transient text starts at `0x3bffb8`
inside the final `.text` page and ends at `0x88f608`, sharing a page with `.init`
and trampolines (`0x88f620`). The normal start is `0x21fd00`. This ELF has no BTI
GNU property. Rounding these ranges is not an isolation proof. 16/64-KiB native
pages need their own verified layout, not the observed QEMU 4-KiB layout.

A future opt-in design could **replace**, rather than prepend to, the first
marker word with `bti jc`, retain a second magic word, and isolate normal text
on guarded pages. That is a different literal marker set, not proved equivalent
to today's policy, and has not been implemented here. It would require:

- Explicit accepted-target correspondence, including incidental marker sequences,
  marker neighbors, near-end reads, normal-to-transient mapping and returns.
- Full software range and second-word checks; full software checking on returns;
  demonstrably unguarded transient pages and separately handled runtime entries.
- Auditing PAC-compatible BTI landings, all branch-register BTYPE cases, veneers,
  linker-generated PLTs, external calls, skipped text and nested checkpoint paths.
- ELF/loader/page enablement checks on the actual final binary and an invalid
  landing fault test; fail closed when the required platform contract is absent.
- Runtime signal recovery with the saved BTYPE accounted for before entering
  guarded recovery/trampoline code. A bare page probe does not prove that path.

x64 would additionally require actual user-mode IBT hardware/OS/loader support,
with an enforcement probe. Adding ENDBR or enabling shadow stacks is not such
support. No enablement is attempted through obsolete or guessed kernel APIs.
No runtime/trampoline entry is added to the application target set.

## Reproduce

On an x64 Linux host with GCC, AArch64 cross GCC/binutils, QEMU AArch64,
CMake and Ninja, from the Teapot checkout:

```sh
python3 experiments/hardware_targets/run_probes.py \
  --out /absolute/workspace/path/hardware-evidence --runtime-tests
```

Optionally add `--layout-elf /path/to/existing/aarch64/teapot-program` to record
its sections, segments, symbols, notes and hash without modifying it. The runner
stores commands, statuses, stdout/stderr, compiler/emulator/loader/binary hashes
and a `manifest.json`. Compiler temporary files stay inside the output directory.
The BTI-marked negative fixture deliberately contains one invalid landing, so
the `-z force-bti` missing-property warning from its assembly object is expected
and retained; that flag is not used on Teapot application/runtime output.

The standalone probe's `--require-backend` request returns **77 (unsupported)**
even when BTI enforcement is demonstrated, because policy equivalence is not.
The ordinary probe returns zero after recording its results and the unchanged
software selection; it is not an instrumented Teapot execution.

`tests/test_indirect_target_policy.py` executes the actual generated x64,
AArch64 and RV64 checks over every byte of small normal/transient ranges and
executes the normal bouncer at checkpoint counts 0/1/2. It covers both marker
words, prefix/interior neighbors, boundaries, returns and trusted-runtime
exclusion. Run it in the same Python/fork environment as other Teapot tests:

```sh
python3 -m unittest discover -s tests -p test_indirect_target_policy.py -v
```

For this task's prepared workspace, `run_workspace_tests.py --workspace
/home/lin/teapot-multiarch --out /absolute/worker/output` records the exact
isolated-image command and hashes. It mounts source trees read-only and only
the requested output directory writable, with networking disabled and a 24-GiB
memory limit. Add `--full` for the complete Teapot suite; the September 21 run
passed **139/139 tests** (134 prior tests plus five policy regressions).

The runtime runner builds the normal, unmodified runtime sources in shadow and
MTE configurations and runs 13 checkpoint-entry cases per configuration. Its
`bti-fault` case uses a real protected-page violation, checks original-handler
forwarding outside simulation, and verifies memory-history, guard-list, DIFT-tag,
instruction-counter and GPR restoration. It retains the original initialized-
depth-one case. The separate nested-only `bti-live-chain` test now creates both
checkpoints from depth zero, mutates the same memory at each depth, faults at the
actual invalid landing at depth two, restores the inner state to depth one, and
then performs an explicit budget rollback of the still-live outer checkpoint.
It verifies both metadata slots remain distinct, the outer snapshot survives
inner recovery, both sets of saved GPRs, memory-history/guard tops, DIFT tags,
instruction counters and per-depth/reason statistics. Its signal observer
delegates to the installed runtime handler without changing the fault context.
The default (nesting-off) test binary explicitly skips the live-chain request.

Both shadow and MTE entry groups pass 13/13 under QEMU 10.0.11, with explicit
no-BTI CPU and nesting-off skip controls. Recovery code remains unguarded, like
the existing runtime; this does not prove recovery into BTI-guarded runtime
pages or native Arm behavior. Entry fixtures use the existing ASan-call stubs;
they are not a new full-pipeline ASan validation. Unsupported environments are
explicit CTest skips (77), not hardware passes. Production nesting stays off.

## Performance scope

No equivalent opt-in backend passed the semantic gate, so hardware-versus-software
backend overhead is **not measurable from this prototype**. Probe elapsed times
in the manifest include subprocess startup and are not performance results.
No bare-landing timing is presented as an acceleration. Production code is
unchanged, so the existing software-path baseline remains the applicable result.
A future benchmark must first pass equivalence, use the same inputs/runtime/layout,
retain all instrumentation, and report native and emulator timings separately.
