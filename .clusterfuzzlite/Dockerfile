FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y build-essential autoconf automake libtool make pkg-config flex bison zlib1g-dev libpcre3-dev cmake

# TODO libmagic, liblzma and other optional libraries
ADD https://github.com/PhilipHazel/pcre2/releases/download/pcre2-10.44/pcre2-10.44.tar.gz pcre2-10.44.tar.gz
ADD https://www.tcpdump.org/release/libpcap-1.10.5.tar.gz libpcap-1.10.5.tar.gz
ADD https://github.com/akheron/jansson/releases/download/v2.14/jansson-2.14.tar.gz jansson-2.14.tar.gz
RUN git clone --depth=1 https://github.com/yaml/libyaml
ADD https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz lz4-1.10.0.tar.gz
RUN git clone --depth 1 -b develop https://github.com/madler/zlib.git
RUN git clone --depth=1 https://github.com/catenacyber/fuzzpcap

ENV RUSTUP_TOOLCHAIN nightly
RUN rustup toolchain install nightly-x86_64-unknown-linux-gnu
RUN cargo install --force cbindgen

COPY . $SRC/suricata
WORKDIR $SRC/suricata
COPY ./.clusterfuzzlite/build.sh $SRC/
