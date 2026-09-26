# Exact-policy hardware gate — September 22 follow-up

This copy is retained in the private hardware branch. Relative evidence paths
refer to `/home/lin/teapot-multiarch/workers/hardware-targets-20260921/` on the
evaluation server, not this repository directory.

No backend has been enabled. This is a design/research conclusion, not a claim
that every conceivable hardware-assisted implementation is impossible.

The current sources were re-read at Teapot `c5a6fd3`: x64/AArch64 control-flow
patches, text target transformation, transient indirect checking and AArch64
checkpoint assembly. The acceptance predicate remains

```
P(t) = transient_start <= t < transient_end
    or (text_start <= t < text_end and word0(t) == M0 and word1(t) == M1)
```

This includes byte-interior transient addresses, both marker words, near-end
reads and the existing checked-return/main-return distinction. Normal markers
also perform normal-to-transient redirection. Trust in runtime code is not
membership in this application predicate.

## Why the simple hybrid still fails

Let `H(t)` denote the hardware landing constraint for a particular call/jump and
page configuration. Retaining all software checks while guarding normal text
implements `P(t) and H(t)`, not necessarily `P(t)`. Equivalence needs every
software-accepted target to satisfy the added hardware constraint. The saved
enforced QEMU probes provide a direct counterexample: the current normal marker
is accepted by `P` but faults under guarded-page BTI. Guarding transient text
adds another counterexample because its accepted range contains ordinary
non-BTI instructions. Conversely, range checks plus hardware landings without
the two-word check admit unrelated BTI landings inside normal text.

Prepending a landing does not close this: the new prefix is rejected by the
current marker predicate, while the old marker at +4 is still accepted by that
predicate and still rejected by BTI. Replacing the first marker word changes the
literal predicate. Page rounding cannot establish isolation: the retained Arm
libhtp ELF shares normal/transient boundary pages with runtime/init/trampolines.

Those are measured counterexamples in
`../root/baseline-20260921/hardware-live-chain-independent-1/`, independently
rechecked in `../root/baseline-20260921/audit-current-20260922/saved-baseline-check.json`.
They are not inferred from feature flags alone.

## Other approaches considered, not implemented

| Approach | Remaining proof obligation |
|---|---|
| Full software predicate, then a separate BTI thunk | Can retain the policy if state/redirection are proved, but does not remove the existing checks; a thunk-only timing would not demonstrate faster target identification |
| Precomputed target table / guarded alias slots | Must equal the current byte predicate, including incidental markers, interval interiors, near-end reads and changes to the observed bytes; function-entry metadata alone is insufficient |
| Resume software-accepted targets after a BTI fault | Changes signal handling rather than merely adding enforcement; must distinguish genuine application faults, preserve fault/rollback reasons and all state, and still reject invalid targets that hardware accepts |
| New BTI-plus-magic marker and isolated pages | Requires an explicitly agreed new target correspondence/marker contract, full software return/range checks and tested loader/runtime recovery boundaries |

The table is coordinator analysis of additional obligations, **not** an executed
prototype or proof of impossibility. No immutable-code contract, alternate
marker set, new accepted runtime entry, or relaxed pass is silently assumed.
The task explicitly requires asking before semantic compromises, so the last
option is not implemented while that decision is unanswered.

## Host and platform evidence

The native x64 probe records IBT absent and SHSTK present but disabled. Enabling
shadow stacks would not create an IBT backend. Linux documents the two features
separately and its documented user API exposes shadow stack/WRSS, not an IBT
enable switch. This was checked against the [kernel CET documentation](https://www.kernel.org/doc/html/next/x86/shstk.html)
and the running kernel family's [v6.12 UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/x86/include/uapi/asm/prctl.h).

AArch64 enforcement exists in the retained QEMU tests, not on a native Arm host.
The [Arm BTI example](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/enabling-pac-and-bti-on-aarch64)
also demonstrates that declaring BTI compatibility without the correct landing
instructions can fault; notes are not an equivalence proof. Native Linux v6.12
delivers a BTI fault through SIGILL/ILL_ILLOPC in [`do_el0_bti`](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/arm64/kernel/traps.c).
The retained emulator's different si_code remains explicitly recorded.

## Consequence for delivery

An equivalent hardware/software overhead result is still absent. There is no
meaningful speedup number to obtain by timing only a landing probe and labeling
it a complete backend. Software remains the default and only production policy;
RV is unchanged. The independent library strategy can be measured without
changing any target semantics, and its measurements are a separate result.

User decision outstanding: retain the exact current policy and hand off this
unsupported-platform/non-equivalent-backend result, or authorize a separately
specified marker/page-layout experiment. Neither is assumed chosen here.
