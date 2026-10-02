# Source-built evaluation image

From the Teapot repository root:

```sh
docker build -t teapot-eval .
```

The frontend is built from pinned commits in the Dockerfile, not from
`grammatech/ddisasm:latest`. It includes Capstone 6.0.0-Alpha11 and DDisasm
support for x86-64, AArch64, RV32 and RV64 (Teapot itself targets RV64).
The existing AArch64 MTE sysroot and runner are retained.

## The three upstream patches

- `dependency-patches/gtirb.patch`, against GTIRB
  `eb6a7af1bb9754de004147f292dc1c7728f62e56`: allow the C++ reader to load
  large GTIRB messages. This does not remove Python protobuf's serialization
  limit; Teapot's output compaction remains necessary.
- `dependency-patches/libehp.patch`, against libehp
  `5e41e26b88d415f3c7d3eb47f9f0d781cc519459`: preserve the operand-free
  AArch64 unwind opcode as an instruction instead of rejecting it.
- `dependency-patches/lief.patch`, against LIEF 0.16.6
  `d52c66d6da4d67c69438989df83a5415236ae08b`: upstream's iterator fix for
  issue #1228, released in 0.16.7. Its original commit, `60c648a4`, which the
  evaluation stack used, is no longer on GitHub; this is the same change.

Each is checked with `git apply --check`, then applied before compilation.
An incompatible or already-patched input fails the image build. libehp is
built as a static library and linked into DDisasm after patching. None of
these dependencies needs a separately maintained Teapot fork.

## Building unpublished commits

Every source stage is a named BuildKit context. By default it retrieves the
exact GitHub commit in the Dockerfile. Before those commits are pushed, provide
clean local source snapshots for the unpublished dependencies:

```sh
docker build -t teapot-eval \
  --build-context ddisasm-src=/absolute/path/to/ddisasm-snapshot \
  --build-context pprinter-src=/absolute/path/to/pprinter-snapshot \
  --build-context lra-src=/absolute/path/to/lra-snapshot \
  .
```

A context replaces the corresponding source stage, including its download.
The snapshot root must contain the project's source files, not a parent
directory. Export the pinned commit with `git archive` or use a clean checkout.
The `rewriting-src` context is the exception: use a clean Git clone with its
`.git` directory and tags, because its Python package derives its version from
Git metadata. The default GitHub stage is a shallow clone without tags, so the
Dockerfile then supplies the version a full clone of the pinned commit derives,
`GTIRB_REWRITING_VERSION`. Update it together with that pin.
Local overrides are deliberately the caller's responsibility and do not
implicitly select the Dockerfile's commit. Keep them at the pinned commits
for reproducible version labels. The build refuses a gtirb-rewriting or
live-register-analysis stage whose Git HEAD is a commit other than its
requirements.txt pin, and a `GTIRB_REWRITING_VERSION` that names another
commit. To build another commit, either update its pin in requirements.txt
(and `GTIRB_REWRITING_VERSION`, for a tagless gtirb-rewriting stage) or pass
`--build-arg ALLOW_UNPINNED_FORKS=1`. Only the HEAD commit is compared, not the
working tree. A stage without usable Git metadata, such as the `git archive`
snapshot above or a worktree whose `.git` file names a host path, is not
compared; the build log says so (use `--progress=plain` to see it). A stage
with a `.git` directory that git cannot read fails the build.

The other override names are `capstone-src`, `gtirb-src`, `libehp-src`,
`souffle-src`, `lief-src`, and `rewriting-src`. In particular, GTIRB and
libehp inputs must be pristine upstream sources: do not provide the old
locally patched trees.

libehp comes from GitHub's source archive of its commit, without the ELFIO
submodule. That submodule points at `third-party-mirrors/ELFIO`, which no longer
exists, and the build leaves libehp's `USE_ELFIO` option off.

`--build-arg BUILD_JOBS=N` controls compile parallelism per frontend stage
(default 8). Independent dependency stages can build concurrently, so budget
memory for more than one stage. Source trees and object files remain in builder
stages; the evaluation image gets the installed tools and development files.

Teapot and its runtime are still mounted/built as described in the main README.
The Python environment is installed in `/opt/venv`, and the frontend in
`/opt/teapot-frontend`; both are on the image's default search paths.
requirements.txt pins llvmlite 0.49.0 (LLVM 22; Python 3.10 or newer): Teapot's text
DIFT uses opaque pointers and LLVM's new pass manager. The image build checks those
APIs and the LLVM major version explicitly.
