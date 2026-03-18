#!/bin/bash

# Serves for Ubuntu/Debian docs and is verified by Github Actions

# install-guide-documentation tag start: Minimal dependencies
sudo apt -y install autoconf automake build-essential cargo-1.89 \
    libjansson-dev libpcap-dev libpcre2-dev libtool \
    libyaml-dev make pkg-config zlib1g-dev
export PATH=/usr/lib/rust-1.89/bin:$PATH
# install-guide-documentation tag end: Minimal dependencies
