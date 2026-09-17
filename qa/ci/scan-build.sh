#!/usr/bin/env bash
#
# Build with Clang scan-build static analysis.

set -eux

# This script and its package list currently only target Ubuntu; clang-22
# and llvm-22-dev require Ubuntu 26.04 or newer.
if ! grep -qs '^ID=ubuntu' /etc/os-release; then
    echo "ERROR: this script is only supported on Ubuntu" >&2
    exit 1
fi

export CC=clang-22

apt update
apt -y install \
    libpcre2-dev \
    build-essential \
    autoconf \
    automake \
    cargo \
    cbindgen \
    clang-22 \
    clang-tools-22 \
    dpdk-dev \
    git \
    libtool \
    libpcap-dev \
    libnet1-dev \
    libyaml-0-2 \
    libyaml-dev \
    libcap-ng-dev \
    libcap-ng0 \
    libmagic-dev \
    libnetfilter-log-dev \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    libnfnetlink-dev \
    libnfnetlink0 \
    libnuma-dev \
    libhiredis-dev \
    libhyperscan-dev \
    libjansson-dev \
    libevent-dev \
    libevent-pthreads-2.1-7 \
    liblz4-dev \
    llvm-22-dev \
    make \
    python3-yaml \
    rustc \
    software-properties-common \
    zlib1g \
    zlib1g-dev

./scripts/bundle.sh
./autogen.sh

scan-build-22 ./configure --enable-warnings --enable-dpdk --enable-nfqueue --enable-nflog

# --status-bugs makes make fail if any bugs are found.
#
# disable security.insecureAPI.DeprecatedOrUnsafeBufferHandling explicitly as
# this will require significant effort to address.
# disable optin.core.EnumCastOutOfRange as it trips up capng's enum values as
# flags handling.
scan-build-22 --status-bugs --exclude "$(pwd)/rust/" \
    --exclude "$HOME/\.cargo/registry/src/" \
    -o scan-build-report/ \
    -enable-checker core.BitwiseShift \
    -enable-checker core.CallAndMessage \
    -enable-checker core.DivideZero \
    -enable-checker core.FixedAddressDereference \
    -enable-checker core.NonNullParamChecker \
    -enable-checker core.NullDereference \
    -enable-checker core.NullPointerArithm \
    -enable-checker core.StackAddressEscape \
    -enable-checker core.UndefinedBinaryOperatorResult \
    -enable-checker core.VLASize \
    -enable-checker core.uninitialized.ArraySubscript \
    -enable-checker core.uninitialized.Assign \
    -enable-checker core.uninitialized.Branch \
    -enable-checker core.uninitialized.CapturedBlockVariable \
    -enable-checker core.uninitialized.NewArraySize \
    -enable-checker core.uninitialized.UndefReturn \
    \
    -enable-checker deadcode.DeadStores \
    \
    -enable-checker nullability.NullableReturnedFromNonnull \
    -enable-checker nullability.NullablePassedToNonnull \
    -enable-checker nullability.NullableDereferenced \
    -enable-checker nullability.NullReturnedFromNonnull \
    \
    -enable-checker optin.performance.GCDAntipattern \
    -disable-checker optin.core.EnumCastOutOfRange \
    -enable-checker optin.performance.Padding \
    -enable-checker optin.portability.UnixAPI \
    -enable-checker optin.taint.GenericTaint \
    -enable-checker optin.taint.TaintedAlloc \
    -enable-checker optin.taint.TaintedDiv \
    \
    -enable-checker security.ArrayBound \
    -enable-checker security.FloatLoopCounter \
    -enable-checker security.MmapWriteExec \
    -enable-checker security.PointerSub \
    -enable-checker security.PutenvStackArray \
    -enable-checker security.SetgidSetuidOrder \
    -enable-checker security.VAList \
    -enable-checker security.cert.env.InvalidPtr \
    \
    -enable-checker security.insecureAPI.UncheckedReturn \
    -enable-checker security.insecureAPI.bcmp \
    -enable-checker security.insecureAPI.bcopy \
    -enable-checker security.insecureAPI.bzero \
    -enable-checker security.insecureAPI.decodeValueOfObjCType \
    -enable-checker security.insecureAPI.getpw \
    -enable-checker security.insecureAPI.gets \
    -enable-checker security.insecureAPI.mkstemp \
    -enable-checker security.insecureAPI.mktemp \
    -enable-checker security.insecureAPI.rand \
    -enable-checker security.insecureAPI.strcpy \
    -enable-checker security.insecureAPI.vfork \
    \
    -disable-checker security.insecureAPI.DeprecatedOrUnsafeBufferHandling \
    \
    -enable-checker unix.API \
    -enable-checker unix.BlockInCriticalSection \
    -enable-checker unix.Chroot \
    -enable-checker unix.Errno \
    -enable-checker unix.Malloc \
    -enable-checker unix.MallocSizeof \
    -enable-checker unix.MismatchedDeallocator \
    -enable-checker unix.StdCLibraryFunctions \
    -enable-checker unix.Stream \
    -enable-checker unix.Vfork \
    -enable-checker unix.cstring.BadSizeArg \
    -enable-checker unix.cstring.NotNullTerminated \
    -enable-checker unix.cstring.NullArg \
    \
    -analyzer-config optin.taint.TaintPropagation:Config="$(pwd)/qa/sb-taint-config.yaml" \
    make -j $(nproc --all)
