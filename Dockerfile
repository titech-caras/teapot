FROM grammatech/ddisasm:latest

ENV DEBIAN_FRONTEND noninteractive
ENV ASAN_OPTIONS detect_leaks=0:verify_asan_link_order=false
ENV PYTHONPATH /workspace/gtirb-live-register-analysis:/workspace/teapot

# Build this image as a reusable evaluation environment. The Teapot source
# tree and the live-register-analysis checkout are expected to be mounted at
# runtime, for example:
#
#   podman run --rm -it \
#     -v "$PWD:/workspace/teapot:Z" \
#     -v "$HOME/gtirb-live-register-analysis:/workspace/gtirb-live-register-analysis:Z" \
#     teapot-eval

RUN apt-get update && \
    apt-get -y install \
    python3 python3-pip python3-venv \
    build-essential make cmake ninja-build pkg-config file \
    gcc g++ llvm clang lld git \
    binutils-dev libunwind-dev libblocksruntime-dev zlib1g-dev \
    libboost-filesystem-dev libboost-program-options-dev libboost-system-dev \
    libcapstone-dev libprotobuf-dev protobuf-compiler \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    gcc-riscv64-linux-gnu g++-riscv64-linux-gnu binutils-riscv64-linux-gnu \
    qemu-user qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/teapot-requirements.txt

RUN python3 -m pip install --no-cache-dir -r /tmp/teapot-requirements.txt

RUN mkdir /workspace
WORKDIR /workspace
