#! /usr/bin/env bash
# Check rust formatting

set -e

(
cd rust
cargo fmt --check
)
