FROM --platform=linux/arm64 ubuntu:24.04 AS aarch64-mte-sysroot

FROM --platform=linux/amd64 debian:trixie-slim AS qemu-user-mte

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get -y install --no-install-recommends qemu-user-static && \
    rm -rf /var/lib/apt/lists/*

FROM --platform=linux/amd64 grammatech/ddisasm:latest

ENV DEBIAN_FRONTEND noninteractive
ENV ASAN_OPTIONS detect_leaks=0:verify_asan_link_order=false
ENV PYTHONPATH /workspace/gtirb-rewriting/src:/workspace/gtirb-live-register-analysis:/workspace/teapot
ENV AARCH64_MTE_SYSROOT /opt/aarch64-mte-sysroot
ENV AARCH64_MTE_QEMU /usr/local/bin/qemu-aarch64-mte

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
    binutils-dev libunwind-dev libblocksruntime-dev zlib1g-dev \
    libboost-filesystem-dev libboost-program-options-dev libboost-system-dev \
    libprotobuf-dev protobuf-compiler \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    gcc-riscv64-linux-gnu g++-riscv64-linux-gnu binutils-riscv64-linux-gnu \
    qemu-user qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

COPY --from=aarch64-mte-sysroot / /opt/aarch64-mte-sysroot/
COPY --from=qemu-user-mte /usr/bin/qemu-aarch64-static /usr/local/bin/qemu-aarch64-mte

RUN /usr/local/bin/qemu-aarch64-mte --version && \
    strings /opt/aarch64-mte-sysroot/lib/aarch64-linux-gnu/libc.so.6 \
        /opt/aarch64-mte-sysroot/lib/ld-linux-aarch64.so.1 | \
        grep -Eq 'glibc\.mem\.tagging|mtag_enabled|memory tagging'

COPY requirements.txt /tmp/teapot-requirements.txt

RUN python3 -m pip install --no-cache-dir -r /tmp/teapot-requirements.txt

# Guard against accidentally reusing an image with upstream's whole-module
# rewrite preparation. The fork pinned in requirements.txt accepts a scoped
# block set and the liveness offset table. Both dependency forks must provide
# the metadata APIs used by Teapot before an image is suitable for evaluation.
RUN python3 -c "import inspect; from gtirb_rewriting.prepare import prepare_for_rewriting; from gtirb_rewriting._auxdata_offsetmap import live_register_sets; from gtirb_live_register_analysis.manager import LiveRegisterManager, LIVE_REGISTER_NAMES_AUXDATA, LIVE_REGISTER_SETS_AUXDATA; assert 'blocks' in inspect.signature(prepare_for_rewriting).parameters, 'gtirb-rewriting lacks scoped preparation support'; assert 'preserve_liveness' in inspect.signature(LiveRegisterManager.refresh).parameters, 'gtirb-live-register-analysis lacks the explicit preservation contract'"

RUN mkdir /workspace
WORKDIR /workspace
