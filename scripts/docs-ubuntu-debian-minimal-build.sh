#!/bin/bash

# Serves for Ubuntu/Debian docs and is verified by Github Actions

# install-guide-documentation tag start: Minimal dependencies
sudo apt -y install autoconf automake build-essential cargo \
    cbindgen libjansson-dev libpcap-dev libpcre2-dev libtool \
    libyaml-dev make pkg-config rustc zlib1g-dev
# install-guide-documentation tag end: Minimal dependencies