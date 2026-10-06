#!/bin/sh
#
# Build and test on OpenBSD.

set -eux

if [ "$(uname -s)" != "OpenBSD" ]; then
    echo "ERROR: this script is only supported on OpenBSD" >&2
    exit 1
fi

: "${DEFAULT_CFLAGS:=-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-function}"
: "${CPUS:=$(sysctl -n hw.ncpuonline)}"
# the autotools wrappers refuse to run without a version selected
: "${AUTOCONF_VERSION:=2.72}"
: "${AUTOMAKE_VERSION:=1.18}"
export AUTOCONF_VERSION AUTOMAKE_VERSION

prepare()
{
    pkg_add -I \
        "autoconf%${AUTOCONF_VERSION}" \
        "automake%${AUTOMAKE_VERSION}" \
        cbindgen \
        gmake \
        jansson \
        jq \
        libmagic \
        libtool \
        libyaml \
        lz4 \
        pcre2 \
        py3-yaml \
        python%3 \
        rust
}

run()
{
    if [ -f prep/suricata-verify.tar.gz ]; then
        tar xzf prep/suricata-verify.tar.gz
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
