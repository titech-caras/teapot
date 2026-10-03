# syntax=docker/dockerfile:1.7

# These named source stages can be overridden with BuildKit --build-context,
# including before a reviewed commit has been pushed. Defaults are immutable
# upstream/fork commits; see docker/README.md for the local-source build.
FROM scratch AS capstone-src
ADD --keep-git-dir=true https://github.com/capstone-engine/capstone.git#b2bf6327b5c7dc43829130b7ccdb02ef9a65a990 /

FROM scratch AS gtirb-src
ADD --keep-git-dir=true https://github.com/GrammaTech/gtirb.git#eb6a7af1bb9754de004147f292dc1c7728f62e56 /

# libehp's only submodule, ELFIO, points at a GitHub mirror that no longer
# exists, and a Git source always fetches submodules. The build does not use
# ELFIO (USE_ELFIO stays OFF), so take the commit's source archive instead.
FROM --platform=linux/amd64 ubuntu:24.04 AS libehp-archive
ADD https://github.com/GrammaTech/libehp/archive/5e41e26b88d415f3c7d3eb47f9f0d781cc519459.tar.gz /libehp.tar.gz
RUN mkdir /libehp && tar -xzf /libehp.tar.gz -C /libehp --strip-components=1

FROM scratch AS libehp-src
COPY --from=libehp-archive /libehp/ /

FROM scratch AS souffle-src
ADD --keep-git-dir=true https://github.com/souffle-lang/souffle.git#b60c8e9f3b9cc6b3e8b980a44fa53033328accee /

# Upstream 0.16.6. dependency-patches/lief.patch adds its iterator fix, which the
# evaluation stack already uses; GitHub no longer serves that fix's commit.
FROM scratch AS lief-src
ADD --keep-git-dir=true https://github.com/lief-project/LIEF.git#d52c66d6da4d67c69438989df83a5415236ae08b /

FROM scratch AS pprinter-src
ADD --keep-git-dir=true https://github.com/lin-toto/gtirb-pprinter.git#0107fb639ab60a51a021c60ed93477cfb41557e1 /

FROM scratch AS ddisasm-src
ADD --keep-git-dir=true https://github.com/lin-toto/ddisasm.git#b509ae48a6778807115147238e67c782e074ec94 /

FROM scratch AS rewriting-src
ADD --keep-git-dir=true https://github.com/lin-toto/gtirb-rewriting.git#e47b9e40b2ac2475a52193dcd4cb9def80154caf /

FROM scratch AS lra-src
ADD --keep-git-dir=true https://github.com/lin-toto/gtirb-live-register-analysis.git#3116e33fdcfbf1e1c5213d84b478ca31b3651790 /

FROM --platform=linux/amd64 ubuntu:24.04 AS frontend-build-base
ENV DEBIAN_FRONTEND=noninteractive
# Compilation of the generated Datalog is memory hungry. Do not use nproc.
ARG BUILD_JOBS=8
ENV CMAKE_BUILD_PARALLEL_LEVEL=${BUILD_JOBS}
ENV CMAKE_PREFIX_PATH=/opt/teapot-frontend
ENV PATH=/opt/teapot-frontend/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/teapot-frontend/lib
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git build-essential cmake ninja-build pkg-config \
    python3 bison flex mcpp libffi-dev zlib1g-dev \
    libprotobuf-dev protobuf-compiler \
    libboost-filesystem-dev libboost-program-options-dev libboost-system-dev \
    && rm -rf /var/lib/apt/lists/*

FROM frontend-build-base AS capstone-build
COPY --from=capstone-src / /src/capstone/
RUN cmake -S /src/capstone -B /build/capstone -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/teapot-frontend \
    -DCMAKE_INSTALL_LIBDIR=lib -DCAPSTONE_BUILD_SHARED_LIBS=ON \
    -DCAPSTONE_BUILD_STATIC_LIBS=ON -DCAPSTONE_BUILD_CSTOOL=ON \
    -DCAPSTONE_BUILD_CSTEST=OFF -DCAPSTONE_BUILD_LEGACY_TESTS=OFF \
    && cmake --build /build/capstone --target install

FROM frontend-build-base AS gtirb-build
COPY --from=gtirb-src / /src/gtirb/
COPY docker/dependency-patches/gtirb.patch /patches/gtirb.patch
# Never silently use unpatched or already-patched inputs.
RUN cd /src/gtirb && git apply --check /patches/gtirb.patch \
    && git apply /patches/gtirb.patch \
    && cmake -S /src/gtirb -B /build/gtirb -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/teapot-frontend \
    -DCMAKE_INSTALL_LIBDIR=lib -DGTIRB_ENABLE_TESTS=OFF \
    -DGTIRB_RUN_CLANG_TIDY=OFF -DGTIRB_PY_API=OFF \
    -DGTIRB_CL_API=OFF -DGTIRB_JAVA_API=OFF \
    && cmake --build /build/gtirb --target install

FROM frontend-build-base AS libehp-build
COPY --from=libehp-src / /src/libehp/
COPY docker/dependency-patches/libehp.patch /patches/libehp.patch
RUN cd /src/libehp && git apply --check /patches/libehp.patch \
    && git apply /patches/libehp.patch \
    && cmake -S /src/libehp -B /build/libehp -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/teapot-frontend \
    -DCMAKE_INSTALL_LIBDIR=lib -DEHP_BUILD_SHARED_LIBS=OFF \
    && cmake --build /build/libehp --target install

FROM frontend-build-base AS souffle-build
COPY --from=souffle-src / /src/souffle/
RUN cmake -S /src/souffle -B /build/souffle -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/teapot-frontend \
    -DSOUFFLE_DOMAIN_64BIT=ON -DSOUFFLE_USE_CURSES=OFF \
    -DSOUFFLE_USE_SQLITE=OFF -DSOUFFLE_ENABLE_TESTING=OFF \
    -DBUILD_TESTING=OFF -DSOUFFLE_GIT=OFF -DSOUFFLE_VERSION=2.4 \
    -DPACKAGE_VERSION=2.4 \
    && cmake --build /build/souffle --target install

FROM frontend-build-base AS lief-build
COPY --from=lief-src / /src/lief/
COPY docker/dependency-patches/lief.patch /patches/lief.patch
RUN cd /src/lief && git apply --check /patches/lief.patch \
    && git apply /patches/lief.patch \
    && cmake -S /src/lief -B /build/lief -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/teapot-frontend \
    -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF \
    -DLIEF_PYTHON_API=OFF -DLIEF_TESTS=OFF -DLIEF_EXAMPLES=OFF \
    && cmake --build /build/lief --target install

FROM frontend-build-base AS pprinter-build
COPY --from=capstone-build /opt/teapot-frontend/ /opt/teapot-frontend/
COPY --from=gtirb-build /opt/teapot-frontend/ /opt/teapot-frontend/
COPY --from=pprinter-src / /src/pprinter/
RUN cmake -S /src/pprinter -B /build/pprinter -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/teapot-frontend \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_INSTALL_RPATH=/opt/teapot-frontend/lib \
    -DGTIRB_PPRINTER_BUILD_SHARED_LIBS=ON -DGTIRB_PPRINTER_STATIC_DRIVERS=OFF \
    -DGTIRB_PPRINTER_ENABLE_TESTS=OFF \
    -DGTIRB_PPRINTER_BUILD_REVISION=0107fb639ab60a51a021c60ed93477cfb41557e1 \
    -DCAPSTONE=/opt/teapot-frontend/lib/libcapstone.so \
    -DCSTOOL=/opt/teapot-frontend/bin/cstool \
    && cmake --build /build/pprinter --target gtirb-pprinter gtirb-layout \
    && cmake --install /build/pprinter

FROM frontend-build-base AS ddisasm-build
COPY --from=pprinter-build /opt/teapot-frontend/ /opt/teapot-frontend/
COPY --from=libehp-build /opt/teapot-frontend/ /opt/teapot-frontend/
COPY --from=souffle-build /opt/teapot-frontend/ /opt/teapot-frontend/
COPY --from=lief-build /opt/teapot-frontend/ /opt/teapot-frontend/
COPY --from=ddisasm-src / /src/ddisasm/
# libehp is static: its patch must be compiled before linking DDisasm.
# These are the same ISA switches as the validated Capstone 6 frontend build.
RUN cmake -S /src/ddisasm -B /build/ddisasm -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/teapot-frontend \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_INSTALL_RPATH=/opt/teapot-frontend/lib \
    -DCAPSTONE=/opt/teapot-frontend/lib/libcapstone.so \
    -DCSTOOL=/opt/teapot-frontend/bin/cstool \
    -DDDISASM_BUILD_REVISION=b509ae48a6778807115147238e67c782e074ec94 \
    -DDDISASM_ENABLE_TESTS=OFF -DDDISASM_GENERATE_MANY=ON \
    -DDDISASM_X86_64=ON -DDDISASM_ARM_64=ON \
    -DDDISASM_RISCV_32=ON -DDDISASM_RISCV_64=ON \
    -DDDISASM_X86_32=OFF -DDDISASM_ARM_32=OFF -DDDISASM_MIPS_32=OFF \
    && cmake --build /build/ddisasm --target install \
    && ddisasm --version && gtirb-pprinter --version \
    && cstool -v \
    && ldd /opt/teapot-frontend/bin/ddisasm /opt/teapot-frontend/bin/gtirb-pprinter \
        | tee /build/frontend-libraries.txt \
    && ! grep -E 'not found|libcapstone.so.5' /build/frontend-libraries.txt

FROM --platform=linux/arm64 ubuntu:24.04 AS aarch64-mte-sysroot

FROM --platform=linux/amd64 debian:trixie-slim AS qemu-user-mte

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y install --no-install-recommends qemu-user-static && \
    rm -rf /var/lib/apt/lists/*

FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=false
ENV PYTHONPATH=/workspace/gtirb-rewriting/src:/workspace/gtirb-live-register-analysis:/workspace/teapot
ENV AARCH64_MTE_SYSROOT=/opt/aarch64-mte-sysroot
ENV AARCH64_MTE_QEMU=/usr/local/bin/qemu-aarch64-mte
ENV PATH=/opt/venv/bin:/opt/teapot-frontend/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/teapot-frontend/lib

# Build this image as a reusable evaluation environment. The Teapot source
# tree and the live-register-analysis checkout are expected to be mounted at
# runtime, for example:
#
#   podman run --rm -it \
#     -v "$PWD:/workspace/teapot:Z" \
#     -v "$HOME/gtirb-rewriting:/workspace/gtirb-rewriting:Z" \
#     -v "$HOME/gtirb-live-register-analysis:/workspace/gtirb-live-register-analysis:Z" \
#     teapot-eval

RUN apt-get update && \
    apt-get -y install \
    ca-certificates \
    python3 python3-pip python3-venv \
    build-essential make cmake ninja-build pkg-config file \
    gcc g++ llvm clang lld git \
    binutils-dev libunwind-dev libblocksruntime-dev zlib1g-dev libffi-dev \
    libboost-filesystem-dev libboost-program-options-dev libboost-system-dev \
    libprotobuf-dev protobuf-compiler \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    gcc-riscv64-linux-gnu g++-riscv64-linux-gnu binutils-riscv64-linux-gnu \
    qemu-user qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ddisasm-build /opt/teapot-frontend/ /opt/teapot-frontend/
COPY --from=aarch64-mte-sysroot / /opt/aarch64-mte-sysroot/
COPY --from=qemu-user-mte /usr/bin/qemu-aarch64-static /usr/local/bin/qemu-aarch64-mte

RUN /usr/local/bin/qemu-aarch64-mte --version && \
    strings /opt/aarch64-mte-sysroot/lib/aarch64-linux-gnu/libc.so.6 \
        /opt/aarch64-mte-sysroot/lib/ld-linux-aarch64.so.1 | \
        grep -Eq 'glibc\.mem\.tagging|mtag_enabled|memory tagging'

COPY requirements.txt /tmp/teapot-requirements.txt
COPY --from=rewriting-src / /tmp/gtirb-rewriting/
COPY --from=lra-src / /tmp/gtirb-live-register-analysis/

# Named contexts also allow the unpublished Python dependency commits to build.
# Their default stages use exactly the revisions pinned in requirements.txt.
# A GitHub source stage keeps a shallow .git without tags, from which
# setuptools-scm cannot derive gtirb-rewriting's version. Without tags, use the
# version a full clone of the pinned commit derives (v0.4.1-11-ge47b9e4).
ARG GTIRB_REWRITING_VERSION=0.4.2.dev11+ge47b9e40b
# The fork stages, the requirements.txt pins and the version above must agree, or
# the image installs other forks than `pip install -r requirements.txt` would.
# Only a stage's Git HEAD is compared, not its working tree. A stage without
# usable Git metadata (a `git archive` snapshot, or a worktree whose `.git` file
# names a host path) cannot be compared, and the build says so; a stage with a
# `.git` directory that git cannot read fails. To build another commit, either
# update its requirements.txt pin (and the version above, for a tagless
# gtirb-rewriting stage) or pass ALLOW_UNPINNED_FORKS=1.
ARG ALLOW_UNPINNED_FORKS=0
RUN for name in gtirb-rewriting gtirb-live-register-analysis; do \
        if ! commit=$(git -c safe.directory='*' -C "/tmp/$name" rev-parse HEAD 2>/tmp/fork-git.err); then \
            if [ -d "/tmp/$name/.git" ]; then \
                echo "the $name stage is a Git clone that git cannot read:" >&2; cat /tmp/fork-git.err >&2; exit 1; fi; \
            echo "note: the $name stage has no usable Git metadata ($(head -n 1 /tmp/fork-git.err)); its commit is not compared"; \
            continue; fi; \
        if [ "$ALLOW_UNPINNED_FORKS" != 1 ] \
            && ! grep -Eq "^$name @ [^#]*@$commit" /tmp/teapot-requirements.txt; then \
            echo "the $name stage is at $commit, not the requirements.txt pin" >&2; exit 1; fi; \
    done \
    && if commit=$(git -c safe.directory='*' -C /tmp/gtirb-rewriting rev-parse HEAD 2>/dev/null) \
        && [ "$ALLOW_UNPINNED_FORKS" != 1 ] \
        && ! git -c safe.directory='*' -C /tmp/gtirb-rewriting describe --tags > /dev/null 2>&1; then \
        node=${GTIRB_REWRITING_VERSION##*+g}; \
        case "$commit" in "$node"*) [ ${#node} -ge 7 ] ;; *) false ;; esac \
            || { echo "GTIRB_REWRITING_VERSION does not name gtirb-rewriting $commit" >&2; exit 1; }; fi \
    && rm -f /tmp/fork-git.err
RUN python3 -m venv /opt/venv \
    && if ! git -c safe.directory='*' -C /tmp/gtirb-rewriting describe --tags > /dev/null 2>&1; then \
        export SETUPTOOLS_SCM_PRETEND_VERSION_FOR_GTIRB_REWRITING="$GTIRB_REWRITING_VERSION"; fi \
    && sed -E '/^gtirb-(rewriting|live-register-analysis) @ /d' \
        /tmp/teapot-requirements.txt > /tmp/teapot-pypi-requirements.txt \
    && python3 -m pip install --no-cache-dir \
        -r /tmp/teapot-pypi-requirements.txt \
        /tmp/gtirb-rewriting /tmp/gtirb-live-register-analysis \
    && rm -rf /tmp/gtirb-rewriting /tmp/gtirb-live-register-analysis

# Guard against accidentally reusing an image with upstream's whole-module
# rewrite preparation. The fork pinned in requirements.txt accepts a scoped
# block set and the liveness offset table. Both dependency forks must provide
# the metadata APIs used by Teapot before an image is suitable for evaluation.
RUN python3 -c "import inspect; from gtirb_rewriting.prepare import prepare_for_rewriting; from gtirb_rewriting._auxdata_offsetmap import live_register_sets, live_register_sets_high; from gtirb_live_register_analysis.manager import LiveRegisterManager, LIVE_REGISTER_NAMES_AUXDATA, LIVE_REGISTER_SETS_AUXDATA, LIVE_REGISTER_SETS_HIGH_AUXDATA; assert 'blocks' in inspect.signature(prepare_for_rewriting).parameters, 'gtirb-rewriting lacks scoped preparation support'; assert 'preserve_liveness' in inspect.signature(LiveRegisterManager.refresh).parameters, 'gtirb-live-register-analysis lacks the explicit preservation contract'; assert callable(LiveRegisterManager.producer_vector_mask), 'gtirb-live-register-analysis lacks frontend vector masks'"

RUN python3 -c "import llvmlite.binding as llvm; llvm.initialize_all_targets(); llvm.initialize_all_asmprinters(); assert llvm.llvm_version_info[0] == 22, llvm.llvm_version_info; tm = llvm.Target.from_triple('x86_64-unknown-linux-gnu').create_target_machine(opt=3, codemodel='small'); pb = llvm.create_pass_builder(tm, llvm.create_pipeline_tuning_options(speed_level=3)); module = llvm.parse_assembly('define void @probe(ptr %p) { store i8 0, ptr %p ret void }'); pb.getModulePassManager().run(module, pb); module.verify(); print('LLVM text-DIFT APIs:', llvm.llvm_version_info)"

RUN mkdir /workspace
WORKDIR /workspace
