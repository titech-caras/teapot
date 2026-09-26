# Source-built evaluation image

From the Teapot repository root:

```sh
docker build -t teapot-eval .
```

The frontend is built from pinned commits in the Dockerfile, not from
`grammatech/ddisasm:latest`. It includes Capstone 6.0.0-Alpha11 and DDisasm
support for x86-64, AArch64, RV32 and RV64 (Teapot itself targets RV64).
The existing AArch64 MTE sysroot and runner are retained.

## The two upstream patches

- `dependency-patches/gtirb.patch`, against GTIRB
  `eb6a7af1bb9754de004147f292dc1c7728f62e56`: allow the C++ reader to load
  large GTIRB messages. This does not remove Python protobuf's serialization
  limit; Teapot's output compaction remains necessary.
- `dependency-patches/libehp.patch`, against libehp
  `5e41e26b88d415f3c7d3eb47f9f0d781cc519459`: preserve the operand-free
  AArch64 unwind opcode as an instruction instead of rejecting it.

Each is checked with `git apply --check`, then applied before compilation.
An incompatible or already-patched input fails the image build. libehp is
built as a static library and linked into DDisasm after patching. Neither
dependency needs a separately maintained Teapot fork.

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
Git metadata. The default GitHub stage preserves that metadata automatically.
Local overrides are deliberately the caller's responsibility and do not
implicitly select the Dockerfile's commit. Keep them at the pinned commits
for reproducible version labels.

The other override names are `capstone-src`, `gtirb-src`, `libehp-src`,
`souffle-src`, `lief-src`, and `rewriting-src`. In particular, GTIRB and
libehp inputs must be pristine upstream sources: do not provide the old
locally patched trees.

`--build-arg BUILD_JOBS=N` controls compile parallelism per frontend stage
(default 8). Independent dependency stages can build concurrently, so budget
memory for more than one stage. Source trees and object files remain in builder
stages; the evaluation image gets the installed tools and development files.

Teapot and its runtime are still mounted/built as described in the main README.
The Python environment is installed in `/opt/venv`, and the frontend in
`/opt/teapot-frontend`; both are on the image's default search paths.
requirements.txt pins llvmlite 0.43.0 (LLVM 14, Python 3.12 compatible): Teapot's text
DIFT still uses LLVM's legacy initialization/pass-manager APIs, which newer
llvmlite releases remove. The image build checks those APIs explicitly.
