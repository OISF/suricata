#!/bin/bash

set -ev

./autogen.sh

if [[ "${NO_UNITTESTS}" != "yes" ]]; then
    ARGS="${ARGS} --enable-unittests"
fi

if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    export CFLAGS="${CFLAGS} ${EXTRA_CFLAGS}"
    if ! ./configure --enable-nfqueue --enable-hiredis ${ARGS}; then
        if [[ "${CONFIGURE_SHOULD_FAIL}" = "yes" ]]; then
           EXIT_CODE=0
        else
           EXIT_CODE=1
        fi
    fi
elif [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
    export CFLAGS="${CFLAGS} ${EXTRA_CFLAGS}"
    ./configure --enable-hiredis --enable-ipfw \
        --enable-lua --with-libpcre-includes=/usr/local/include \
        --with-libpcre-includes=/usr/local/include \
        --with-libpcre-libraries=/usr/local/lib \
        --with-libnss-includes=/usr/local/opt/nss/include/nss \
        --with-libnss-libraries=/usr/local/opt/nss/lib \
        --with-libnspr-includes=/usr/local/opt/nspr/include/nspr \
        --with-libnspr-libraries=/usr/local/opt/nspr/lib ${ARGS}
fi

if [[ "${EXIT_CODE}" ]]; then
   exit "${EXIT_CODE}"
fi

# Linux container builds have 2 cores, make use of them.
if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    j="-j 2"
fi
make ${j}

# Like "make check", but fail on first error. We redirect the output
# so Travis doesn't fail the build with a too much output error.
if [[ "${NO_UNITTESTS}" != "yes" ]]; then
    set +e # disable
    mkdir -p ./qa/log
    ./src/suricata -u -l ./qa/log --fatal-unittests > unittests.log 2>&1
    if [[ $? -ne 0 ]]; then
        echo "Unit tests failed, last 500 lines of output are:"
        tail -n 500 unittests.log
        exit 1
    fi
    set -e
fi

(cd qa/coccinelle && make check)

if [[ "$DO_DISTCHECK" == "yes" ]]; then
    make distcheck DISTCHECK_CONFIGURE_FLAGS="${ARGS}"
fi

if [[ "$DO_CHECK_SETUP_SCRIPTS" == "yes" ]]; then
    (cd scripts && ./check-setup.sh)
fi

git clone https://github.com/OISF/suricata-verify.git verify
python ./verify/run.py
