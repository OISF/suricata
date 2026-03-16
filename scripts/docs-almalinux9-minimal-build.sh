#!/bin/bash

# Serves for RPM-based docs and is verified by Github Actions

# install-guide-documentation tag start: Minimal RPM-based dependencies
sudo dnf install -y dnf-plugins-core epel-release
sudo dnf install -y cargo gcc jansson-devel libpcap-devel \
    libyaml-devel make pcre2-devel zlib-devel
# install-guide-documentation tag end: Minimal RPM-based dependencies
