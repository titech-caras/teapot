# Selected shared-library conversion

`convert.py` turns one non-PIE executable and selected compiled shared libraries into a single non-PIE `ET_EXEC`
before instrumentation, so Teapot can instrument the whole program at once. Each selected library becomes genuine
`ET_REL` members of one archive that is linked into the executable; unselected system libraries stay dynamic. It is a
deliberately narrow converter, not a general-purpose ELF static linker: it works from compiled ELF files only, never
from workload sources, original objects or archives, and refuses what its contract below does not cover. Supported
targets are x86-64, AArch64 and RV64.

The library-rewriting pipeline, `experiments/reusable_libraries/rewrite_components.py`, builds on this converter: it
instruments each selected library once and reuses the instrumented archive across executables.

```
python3 tools/sharedlib/convert.py --executable APP --select libfoo.so [--select ...] \
    --external libc.so.6 [--external ...] --ddisasm DDISASM --pprinter GTIRB_PPRINTER --out DIR \
    [--cc gcc] [--ar ar] [--linker ld] [--cache-dir DIR] [--jobs N] [opt-in flags below]
```

The steps are:

1. Validate the ELF binding, startup and unwind contract and the complete dependency set.
2. Lift each input independently with DDisasm.
3. Preserve symbolic GOT/PLT references, data pointers, symbol versions and CFI. Recovered in-text data boundaries
   are kept as sized local `OBJECT` symbols, so a fresh lift after relinking does not reinterpret those bytes as code.
   Print assembly and assemble real target-architecture `ET_REL` objects.
4. Put only the reconstructed selected objects into a deterministic archive and link the executable object and the
   whole archive into one non-PIE `ET_EXEC`. Check that selected SONAMEs are gone from `DT_NEEDED` and that every
   selected exported code and data symbol is defined in the output.
5. Check ordinary behavior before instrumenting, then lift the linked executable afresh, so calls between the selected
   libraries are visible to interprocedural liveness and control-flow instrumentation.
6. Run all Teapot passes and link one matching runtime, adding ASan only afterwards.

## Opt-in extensions

The input libraries may contain PIC, but the output is always an ordinary archive linked into a non-PIE executable
before instrumentation. There is no PIC instrumentation and no loadable instrumented DSO.

- `--resolve-selected-versions` binds each selected SONAME, name and version to a stable static-link identity and keeps
  the correct default alias. External libc versions stay versioned.
- `--preserve-selected-lifecycle` keeps custom init/fini callbacks and arrays of the selected libraries; RISC-V uses its
  array-based startup contract. Interleaving with sibling or external libraries' lifecycles is not established.
- `--preserve-nonlocal-jumps` allows the original libc context-restoration calls instead of redirecting them to Teapot
  rollback.
- `--preserve-weak-imports` keeps undefined weak bindings and the original breadth-first external dependency scope.
  Supplied but unneeded providers are not linked; replaceable weak definitions and ambiguous selected exports are still
  refused.

AArch64's exhaustive candidate decoder may warn while reading literal tables. Only operand diagnostics covered
completely by recovered data blocks and, independently, by an input `OBJECT` or `$d` mapping range are accepted; any
other warning rejects the conversion.

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


## Ordinary-artifact cache

`--cache-dir` stores two immutable, content-addressed stages. Both hold ordinary, uninstrumented artifacts; the final
executable is always relinked and instrumented afresh.

| Stage | Key / reuse boundary |
| --- | --- |
| Recovered IR | Input ELF contents and basename; DDisasm binary and loaded native libraries; frontend source/patch provenance; frontend options |
| Ordinary ET_REL | Above plus converter source hash, role/array priority, the selected/external contents and ordering (and, for the executable's own object, the executable's contents), printing policy, printer/compiler/assembler/ar/linker identities, native dependencies, Python executable/package contents, and source provenance. A selected library's key leaves out the executable, so another executable with the same libraries reuses its object |

Every cached artifact has a SHA-256 entry in its manifest. Retrieval checks the recipe, the exact file set and hashes,
rejects symlinks and copies rather than hardlinks. Entries are installed atomically and never overwritten; corruption
fails with `CACHE_INTEGRITY`. Manifests are trusted local metadata, not signatures against a malicious writer. The
`ET_REL` key is deliberately conservative: even a change of executable or binding order invalidates object reuse, while
unchanged library IR can still be reused.
