FROM grammatech/ddisasm:latest

ENV DEBIAN_FRONTEND noninteractive
ENV ASAN_OPTIONS detect_leaks=0:verify_asan_link_order=false

RUN apt-get update && \
    apt-get -y install \
    python3 python3-pip \
    build-essential make cmake gcc llvm clang git \
    binutils-dev libunwind-dev libblocksruntime-dev \
    && rm -rf /var/lib/apt/lists/*

ADD ./ /tmp/teapot
ADD ./scripts /teapot-scripts

RUN python3 -m pip install /tmp/teapot

RUN cd /tmp/teapot/libcheckpoint_x64 && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make && make install

RUN cd /tmp/teapot/honggfuzz && make && make install && \
    cp /tmp/teapot/honggfuzz/libhfuzz/libhfuzz.so /usr/local/lib

RUN rm -rf /tmp/teapot

RUN mkdir /workspace
WORKDIR /workspace
