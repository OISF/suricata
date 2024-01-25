#! /bin/sh
#
# This is a helper script to install dependencies for building
# Suricata from source. By default it will install a set of
# dependencies suitable for users of Suricata.  Add the --developer
# option to install extra dependencies suitable for developers such as
# ASAN and documentation build tools.

set -e

for arg in $@; do
    case $arg in
	--developer)
	    DEVELOPER="yes"
	    ;;
	*)
	    echo "error: bad argument: $arg"
	    exit 1
	    ;;
    esac
done

if ! test -e /etc/os-release; then
    echo "error: unable to determine OS (no /etc/os-release)"
    exit 1
fi

. /etc/os-release

if [ "${ID}" = "" ]; then
    echo "error: no os-release id"
    exit 1
fi

install_deps_debian() {
    if [ "${VERSION_ID}" -lt "11" ]; then
	echo "error: only Debian 11 and newer supported at this time"
	exit 1
    fi

    apt update
    apt -y install \
        build-essential \
        dpdk-dev \
        libcap-ng-dev \
        libcap-ng0 \
        libjansson-dev \
        libjansson4 \
        liblua5.1-dev \
        liblz4-dev \
        liblzma-dev \
        libmagic-dev \
        libmaxminddb-dev \
        libnet1-dev \
        libnspr4-dev \
        libnuma-dev \
        libpcap-dev \
        libpcre2-dev \
        libssl-dev \
        libtool \
        libyaml-0-2 \
        libyaml-dev \
        make \
        pkg-config \
        python3 \
        python3-yaml \
        zlib1g \
        zlib1g-dev

    if [ "${DEVELOPER}" = "yes" ]; then
	echo "===> Installing extra developer packages"
	apt -y install \
	    autoconf \
	    automake \
            jq \
            sphinx-doc \
            sphinx-common \
            texlive-fonts-recommended \
            texlive-fonts-extra \
            texlive-latex-base \
            texlive-latex-extra
    fi

    # Only install Rust if not found, as it may already be installed
    # from Rustup.
    if ! rustc --version > /dev/null 2>&1; then
	apt -y install cargo rustc
    fi

    # Same for cbindgen, it may already have been installed with
    # cargo.
    if ! cbindgen --version > /dev/null 2>&1; then
	apt -y install cbindgen
    fi
}

install_deps_fedora() {
    dnf -y install \
	dpdk-devel \
	hyperscan-devel \
        diffutils \
        file-devel \
        gcc \
        gcc-c++ \
        hiredis-devel \
        jansson-devel \
        libcap-ng-devel \
        libevent-devel \
        libmaxminddb-devel \
        libnet-devel \
        libnetfilter_queue-devel \
        libnfnetlink-devel \
        libpcap-devel \
        libtool \
        libtool \
        libyaml-devel \
        lua-devel \
        lz4-devel \
        make \
        pcre2-devel \
        pkgconfig \
        python3-yaml \
        which \
        zlib-devel

    if [ "${DEVELOPER}" = "yes" ]; then
	echo "===> Installing extra developer packages"
	dnf -y install \
	    autoconf \
	    automake \
	    jq \
	    libasan \
            python3-sphinx \
            texlive-capt-of \
            texlive-cmap \
            texlive-collection-latexrecommended \
            texlive-fncychap \
            texlive-framed \
            texlive-latex \
            texlive-needspace \
            texlive-tabulary \
            texlive-titlesec \
            texlive-upquote \
            texlive-wrapfig
    fi
    
    # Only install Rust if not found, as it may already be installed
    # from Rustup.
    if ! rustc --version > /dev/null 2>&1; then
	dnf -y install cargo rustc
    fi

    # Same for cbindgen, it may already have been installed with
    # cargo.
    if ! cbindgen --version > /dev/null 2>&1; then
	dnf -y install cbindgen
    fi
}

install_deps_ubuntu() {
    if [ "${VERSION_ID}" != "22.04x" ]; then
	echo "===> WARNING: this script is for Ubuntu 22.04 and may not work"
	echo "===>          correctly on ${PRETTY_NAME}"
    fi

    apt -y update
    apt -y install \
        build-essential \
        libcap-ng-dev \
        libcap-ng0 \
        libevent-dev \
        libevent-pthreads-2.1-7 \
        libhiredis-dev \
        libjansson-dev \
        libjansson-dev \
        libmagic-dev \
        libnet1-dev \
        libnetfilter-queue-dev \
        libnetfilter-queue1 \
        libnfnetlink-dev \
        libnfnetlink0 \
        libpcap-dev \
        libpcre2-dev \
        libpython2.7 \
        libtool \
        libyaml-0-2 \
        libyaml-dev \
        make \
        python3-yaml \
        software-properties-common \
        zlib1g \
        zlib1g-dev

    # TODO:
    # - asan
    if [ "${DEVELOPER}" = "yes" ]; then
	echo "===> Installing extra developer packages"
	apt -y install \
	    autoconf \
	    automake \
	    git \
            jq \
            sphinx-common \
            sphinx-doc \
            texlive-fonts-recommended \
            texlive-fonts-extra \
            texlive-latex-base \
            texlive-latex-extra
    fi
    
    # Only install Rust if not found, as it may already be installed
    # from Rustup.
    if ! rustc --version > /dev/null 2>&1; then
	apt -y install cargo rustc
    fi

    # Same for cbindgen, it may already have been installed with
    # cargo.
    if ! cbindgen --version > /dev/null 2>&1; then
	apt -y install cbindgen
    fi
}

case "${ID}" in
    debian)
	install_deps_debian
	;;
    fedora)
	install_deps_fedora
	;;
    ubuntu)
	install_deps_ubuntu
	;;
    *)
	echo "error: ${ID} not supported by this script"
	exit 1
	;;
esac
