#!/bin/sh
#
# Build and test on FreeBSD.

set -eux

if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "ERROR: this script is only supported on FreeBSD" >&2
    exit 1
fi

: "${DEFAULT_CFLAGS:=-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function}"
: "${CPUS:=$(sysctl -n hw.ncpu)}"

prepare()
{
    pkg install -y \
        autoconf \
        automake \
        gmake \
        jq \
        rust-cbindgen \
        jansson \
        libpcap \
        libtool \
        libyaml \
        pcre2 \
        pkgconf \
        python3 \
        py312-pyyaml \
        rust
}

run()
{
    if [ -f prep/suricata-verify.tar.gz ]; then
        tar xf prep/suricata-verify.tar.gz
    fi

    if [ ! -d suricata-verify ]; then
        echo "ERROR: suricata-verify is required" >&2
        exit 1
    fi

    ./autogen.sh
    CFLAGS="${DEFAULT_CFLAGS}" ./configure --enable-warnings --enable-unittests
    gmake -j "${CPUS}"
    ./src/suricata -u -l /tmp/
    python3 ./suricata-verify/run.py -q --debug-failed
}

if [ "$#" -eq 0 ]; then
    prepare
    run
elif [ "$#" -eq 1 ] && [ "$1" = "prepare" ]; then
    prepare
elif [ "$#" -eq 1 ] && [ "$1" = "run" ]; then
    run
else
    echo "Usage: $0 [prepare|run]" >&2
    exit 1
fi
