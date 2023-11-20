FROM mcr.microsoft.com/devcontainers/rust:1-1-bullseye as base

# Upate the base image versions
RUN sudo apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    && sudo apt install openssl -y

RUN sudo apt -y install \
    libssl-dev \
    libpcre2-dev \
    build-essential \
    autoconf \
    automake \
    curl \
    jq \
    libtool \
    libpcap-dev \
    libnet1-dev \
    libyaml-0-2 \
    libyaml-dev \
    libcap-ng-dev \
    libcap-ng0 \
    libmagic-dev \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    libnfnetlink-dev \
    libnfnetlink0 \
    libnuma-dev \
    libhiredis-dev \
    libhyperscan-dev \
    liblua5.1-dev \
    libevent-dev \
    libevent-pthreads-2.1-7 \
    libjansson-dev \
    libpython2.7 \
    make \
    parallel \
    python3-yaml \
    software-properties-common \
    zlib1g \
    zlib1g-dev \
    exuberant-ctags \
    curl \
    wget \
    dpdk-dev \
    git-core \
    pkg-config
# IDS and IPS 
RUN sudo apt-get -y install libnetfilter-queue-dev libnetfilter-queue1 \
    libnfnetlink-dev libnfnetlink0

# Clean up
 RUN sudo apt-get autoremove -y \
    && sudo apt-get clean -y \
    && sudo rm -rf /var/lib/apt/lists/*

# RUN "curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain 1.63.0 -y"

WORKDIR /usr/src