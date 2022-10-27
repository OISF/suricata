#! /usr/bin/env bash
#
# Helper script for Fedora build as a non-root user.
#
# We break the build up itno parts that need to be called individually
# to avoid outputting too much data in a single step so we can see the
# output in the UI.

set -e
set -x

export PATH="$HOME/.cargo/bin:$PATH"

case "$1" in
    cbindgen)
        # Setup cbindgen.
        mkdir -p $HOME/.cargo/bin
        cp prep/cbindgen $HOME/.cargo/bin
        chmod 755 $HOME/.cargo/bin/cbindgen
        ;;
    autogen)
        ./autogen.sh
        ;;
    configure)
        ac_cv_func_realloc_0_nonnull="yes" \
            ac_cv_func_malloc_0_nonnull="yes" \
            LDFLAGS="-fsanitize=address" \
            CC="clang" \
            CFLAGS="$DEFAULT_CFLAGS -Wshadow -fsanitize=address -fno-omit-frame-pointer" \
            ./configure \
            --enable-debug \
            --enable-unittests \
            --disable-shared \
            --enable-rust-strict \
            --enable-hiredis \
            --enable-nfqueue
        ;;
    make)
        make -j2
        ;;
    unit-test)
        ASAN_OPTIONS="detect_leaks=0" ./src/suricata -u -l .
        ;;
    verify)
        python3 ./suricata-verify/run.py
        ;;
esac
