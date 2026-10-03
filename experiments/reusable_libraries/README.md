# Reusable instrumented components (experimental)

`rewrite_components.py` instruments an executable and the shared libraries it selects as separate components,
caches each instrumented component by content, and leaves one final link to combine them with a single runtime. A
library instrumented once is reused by every executable with the same binding contract; the executable itself is
always rewritten and relinked. `validate_link.py` checks the structure of the linked result.

This is a final-link pipeline. Its output is one non-PIE executable, never an instrumented DSO that could be loaded
on its own. The input contract is the selected-library converter's (`tools/sharedlib/README.md`): a non-PIE
executable, the selected compiled shared libraries and explicitly supplied external ELFs, all x86-64, AArch64 or
RV64. Whatever that contract does not cover is refused before anything is lifted.
Build the ordinary executable input with `-no-pie -Wl,--emit-relocs` and keep its
relocation and symbol tables; see the converter's input-build guidance. A
non-PIE link without this evidence can leave integer constants indistinguishable
from absolute data pointers, which the frontend now rejects rather than guessing.

## Modes

The instrumentation mode fixes the DIFT layout, the AArch64 tag storage and the ASan runtime that the final link
must use (`targets.py`).

| Mode | ISA | DIFT layout | Tag storage | ASan runtime |
| --- | --- | --- | --- | --- |
| `x64` (x86-64 default) | X64 | `x64-la48-asan-new` | shadow | `libasan.so.8` |
| `aarch64-vma42` (AArch64 default) | ARM64 | `aarch64-vma42` | shadow | `libasan.so.5` |
| `aarch64-vma39` | ARM64 | `aarch64-vma39` | shadow | `libasan.so.5` |
| `aarch64-vma48` | ARM64 | `aarch64-vma48` | shadow | `libasan.so.5` |
| `aarch64-vma42-mte` | ARM64 | `aarch64-vma42` | MTE | none |
| `aarch64-vma48-mte` | ARM64 | `aarch64-vma48` | MTE | none |
| `riscv64` (RV64 default) | RISCV64 | `riscv64-sv39` | shadow | `libasan.so.8` |

## Rewriting

```
python3 experiments/reusable_libraries/rewrite_components.py \
    --executable APP --select libfoo.so [--select ...] --external libc.so.6 [--external ...] \
    --out OUT --cache CACHE [--mode MODE] --converter tools/sharedlib/convert.py \
    --teapot TEAPOT --rewriting GTIRB_REWRITING --lra LIVE_REGISTER_ANALYSIS \
    --runtime-contract CONTRACT.json --ddisasm DDISASM --pprinter GTIRB_PPRINTER [--cc CC] [--jobs N] \
    [--target-identification software|aarch64-bti-pac] \
    [--resolve-selected-versions] [--preserve-selected-lifecycle] [--preserve-nonlocal-jumps] \
    [--preserve-weak-imports]
```

`--teapot`, `--rewriting` and `--lra` name the source trees whose Python files enter the cache key. The driver checks
that the imported packages really come from those paths and hashes the imported package directories. The dependency
paths may be checkout roots or their installed `site-packages` package directories. The driver imports Teapot
from its own checkout, so `--teapot` must name it; the other two come through `PYTHONPATH`.
The runtime
contract is the `libcheckpoint.contract.json` beside the libcheckpoint archive of the final link. Its ABI
fingerprint enters the key, so archives with the same ABI share components; each component's record lists
the capabilities it needs, and `validate_link.py` compares every record with the runtime record the link
holds. The four opt-in flags are the converter's.

### AArch64 BTI+PAC (opt-in)

`--target-identification aarch64-bti-pac` works with the AArch64 layout/tag-storage modes above;
BTI and PAC are one feature, enabled together. Build libcheckpoint
with `-DTEAPOT_EXPERIMENTAL_AARCH64_BTI=ON` and the same layout and tag storage.
Every executable and selected library must use the same target-identification mode. The
mode is part of each cache key and manifest. Software objects cannot be mixed into a BTI/PAC link.

Use the generated `layout.ld` **instead of** also passing `AArch64Bti.ld`: it collects all
components' `.teapot_bti_normal` inputs into one 64 KiB-aligned guarded output section,
defines the bounds once, and places the enforcement probes and padding beyond the allowed
application targets. The transient copy, native-landing detours, runtime and writable data
remain outside that region. Export markers start with `bti jc`; return and range checks remain.

Include **every** object in the manifest's `link_support`, including `bti-startup.o`. Its
preinit entry installs the runtime signal handler and verifies/enables BTI before selected
constructors, without enabling speculation early. Main enables speculation as before. The
new strong runtime entry rejects linking an old/non-BTI archive, and runtime activation
refuses unsupported CPUs/OS mappings rather than silently falling back. Constructors and
external, unrewritten code are not newly made speculative by this mode.

For each component the driver:

1. Validates the binding, dependency and startup contract. Each selected exported function must be recovered
   uniquely in `.text`.
2. Lifts the original ELF on its own and keeps DDisasm's standalone ABI liveness and CFI. Missing liveness masks
   mean all-live; the liveness of a particular linked caller is never imported.
3. Runs every default Teapot pass with ROB 250 and nesting off, in the mode's layout. Exported entries receive the
   complete indirect-branch marker before normal-path stack poisoning. Direct transfers to a validated provider may
   continue into its instrumented code; unknown or external transfers keep their rollback and checks.
4. Prints and assembles a real `ET_REL` object. The printed assembly is assembled as it is.

`OUT` then holds `component-000.o` (the executable), one object per selected library, any lifecycle support objects,
the linker script `layout.ld`, and the `components.json` and `inputs.json` manifests.

## Linking and validation

Link `component-000.o`, the library objects (or an archive of them) and the support objects as a non-PIE executable
without start files, using `OUT/layout.ld`, one runtime built for the same mode (libcheckpoint with its DIFT
wrapper archives, and honggfuzz's libhfuzz) and the mode's ASan runtime. The script gathers every component's
normal and transient code into two application-wide ranges and gives each component its own coverage-guard
storage, based on the guard-start symbol after input-section alignment.

```
python3 experiments/reusable_libraries/validate_link.py --binary APP.instrumented --objects OUT \
    --out validation.json [--isa ISA] [--mode MODE] [--target-identification software|aarch64-bti-pac]
```

The validator derives ISA, mode, DIFT layout and tag storage from the manifests and checks every component agrees.
Optional `--isa` and `--mode` arguments assert the requested contract; a mismatch is an error, not a mode override.
Older manifests without this contract must be rebuilt. It checks the two ranges and that no other code falls inside them, every exported entry and its marker,
the coverage-guard bases and that no two components' guards overlap, the selected definitions, the reconstructed
FDEs, and the ASan runtime's place in `DT_NEEDED` (or its absence in MTE modes), with no selected SONAME still
needed. Passing it is a structural
result, not behavior verification.
For BTI it also verifies isolated RX guard pages, the probe/bound aliases, absence of unmatched
native BTI/PAC landings in normal text, and the actual preinit pointer. Hardware enforcement
is separately checked at startup on the final mapping.

## Cache

Each cache entry is immutable and content-addressed. It holds the original and instrumented IR, the printed
assembly, the object, the command logs and SHA-256 manifests, and every file is re-hashed on a hit. The key covers
the input ELF bytes, its role and initializer priority, the selected and external libraries' bytes and binding
names, the Teapot, gtirb-rewriting and live-register-analysis sources, the converter, the driver, the runtime
contract, the pass options, the ROB length, the mode and its layout. It also covers the bytes of every tool that
shapes the output, with its shared libraries: DDisasm, gtirb-pprinter, the compiler driver and the `as` and `cc1` it
runs (clang has no separate `cc1`). The Python side enters as the interpreter; the `.py` and `.so` files of gtirb,
pyelftools and protobuf; every file of llvmlite and its LLVM, mcasm, capstone, gtirb-capstone, gtirb-functions,
gtirb-layout and leb128; and the version of every installed distribution. Tool paths are not key material; each
run records them in `tools.json`. A library's key leaves out the executable's bytes but not its binding contract,
so another program with the same contract reuses the same instrumented library. This cache is separate from the
converter's cache of ordinary IR and objects.

## Limitations

- Restore points are placed from each component's standalone liveness. Near the ROB limit, instruction counters,
  and so which reports appear, can therefore differ from a whole-program rewrite of the same program.
- No nested speculation, no parallel execution and no constructor ordering beyond the converter's contract.
