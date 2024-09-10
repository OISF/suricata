FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y build-essential autoconf automake libtool make pkg-config  python flex bison zlib1g-dev libpcre3-dev cmake tshark

# TODO libmagic, liblzma and other optional libraries
ADD https://github.com/PhilipHazel/pcre2/releases/download/pcre2-10.39/pcre2-10.39.tar.gz pcre2-10.39.tar.gz
ADD https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz libpcap-1.9.1.tar.gz
ADD https://github.com/akheron/jansson/releases/download/v2.14/jansson-2.14.tar.gz jansson-2.14.tar.gz
RUN git clone --depth=1 https://github.com/yaml/libyaml
ADD https://github.com/lz4/lz4/archive/v1.9.2.tar.gz lz4-1.9.2.tar.gz
RUN git clone --depth 1 -b develop https://github.com/madler/zlib.git
RUN git clone --depth=1 https://github.com/catenacyber/fuzzpcap

ENV RUSTUP_TOOLCHAIN nightly
RUN cargo install --force cbindgen

RUN git clone --depth 1 https://github.com/OISF/libhtp.git libhtp

COPY . $SRC/suricata
WORKDIR $SRC/suricata
COPY ./.clusterfuzzlite/build.sh $SRC/
