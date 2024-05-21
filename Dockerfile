FROM ddisasm:latest

ENV DEBIAN_FRONTEND noninteractive

ADD ./* /tmp/teapot-src

RUN apt-get update && \
    apt-get -y install \
    python3 python3-pip \
    build-essential make cmake gcc llvm clang libasan8 \
    binutils-dev libunwind-dev libblocksruntime-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install -e /tmp/teapot-src

RUN mkdir /tmp/libcheckpoint_build && \
    cmake --build /tmp/teapot-src/libcheckpoint_x64 -B/tmp/libcheckpoint_build --config Release --target install

RUN make -C /tmp/teapot-src/honggfuzz install

RUN rm -rf /tmp/teapot-src

RUN mkdir /workdir
WORKDIR /workdir
