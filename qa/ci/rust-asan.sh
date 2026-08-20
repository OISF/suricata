#!/usr/bin/env bash
#
# Build with Rust and C ASAN.

set -eux
set -o pipefail

# This script and its package list currently only target Fedora.
if [ ! -e /etc/fedora-release ]; then
    echo "ERROR: this script is only supported on Fedora" >&2
    exit 1
fi

# A cargo build target other than the default is required for Rust ASAN builds
# as we don't want proc-macros built with address sanitization.
export CARGO_BUILD_TARGET="${CARGO_BUILD_TARGET:=x86_64-unknown-linux-gnu}"

# Default to all CPUs unless already set.
: "${CPUS:=$(nproc --all)}"

CFLAGS=(
    -Wall
    -Wextra
    -Werror
    -Wno-unused-parameter
    -Wno-unused-function
    -g
    -fno-omit-frame-pointer
    -fsanitize=address
)

LDFLAGS=(
    -fsanitize=address
)

RUSTFLAGS=(
    -Zsanitizer=address
    -Cforce-frame-pointers=yes
)

export ac_cv_func_realloc_0_nonnull=yes
export ac_cv_func_malloc_0_nonnull=yes

dnf -y install \
    autoconf \
    automake \
    awk \
    cbindgen \
    curl \
    diffutils \
    file-devel \
    gcc \
    gcc-c++ \
    git \
    jq \
    jansson-devel \
    libasan \
    libtool \
    libyaml-devel \
    libnfnetlink-devel \
    libnetfilter_queue-devel \
    libnet-devel \
    libcap-ng-devel \
    libpcap-devel \
    make \
    pcre2-devel \
    pkgconfig \
    python3-yaml \
    which \
    xz-devel \
    zlib-devel

# Nightly is required for -Zsanitizer=address.
curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly --profile minimal -y
. "${HOME}/.cargo/env"

./autogen.sh

CFLAGS="${CFLAGS[@]}" LDFLAGS="${LDFLAGS[@]}" \
    ./configure --enable-warnings --enable-debug --enable-unittests --disable-shared

RUSTFLAGS="${RUSTFLAGS[@]}" make -j "${CPUS}"

# Check that the Rust is built with ASAN.
lib="rust/target/${CARGO_BUILD_TARGET}/debug/libsuricata_rust.a"
nm -C "${lib}" > rust-asan-symbols.txt
grep -q __asan_report_load1 rust-asan-symbols.txt

./src/suricata --build-info
./src/suricata -u -l .

# Only disable leak detection here, there are leaks in the Rust unit tests, to
# be investigated.
(cd rust && \
    ASAN_OPTIONS="detect_leaks=0" RUSTFLAGS="${RUSTFLAGS[@]}" \
    cargo test --workspace --all-targets)

SURICATASC=./rust/target/${CARGO_BUILD_TARGET}/debug/suricatasc \
    python3 ./suricata-verify/run.py -q --debug-failed
