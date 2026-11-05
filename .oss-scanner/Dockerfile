FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential autoconf automake libtool pkg-config \
      clang libdpdk-dev llvm libclang-dev libclang-rt-dev cargo rustc cbindgen bindgen \
      git python3 python3-yaml python3-scapy gdb strace \
      libpcap-dev libpcre2-dev libyaml-dev libjansson-dev zlib1g-dev \
      libcap-ng-dev libmagic-dev liblz4-dev libhyperscan-dev \
      libnetfilter-queue-dev libnetfilter-log-dev libmaxminddb-dev \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch for context.
RUN git clone https://github.com/OISF/suricata-verify

RUN ./autogen.sh \
    && CC=clang \
	CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address" \
	LDFLAGS="-fsanitize=address" \
      ./configure \
      --enable-unittests \
      --enable-nfqueue \
      --enable-nflog \
      --enable-dpdk \
      --disable-gccmarch-native \
      --disable-suricata-update

# Fetch all dependencies, including test deps (if any).
RUN cd rust && cargo fetch

# We're now going to build offline, just to ensure that the agent can also
# build offline.
ENV CARGO_NET_OFFLINE=true

RUN make -j"$(nproc)" \
    && make install install-conf \
    && suricata --build-info

RUN make check || echo "WARNING: make check FAILED"
