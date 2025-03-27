#!/usr/bin/env bash

set -e

# Create temp. directory and copy in sources.
tmpdir=$(mktemp -d)
trap "rm -rf ${tmpdir}" EXIT

(cd .. && tar cf - $(git ls-files)) | (cd ${tmpdir} && tar xf -)

cd ${tmpdir}

# Do initial build.
./autogen.sh
./configure

./scripts/setup-app-layer.py --parser Echo

./scripts/setup-app-layer.py --detect Echo request

./scripts/setup-app-layer.py --logger Echo

./scripts/setup-decoder.sh Udplite

./scripts/setup-simple-detect.sh simpledetect

make distcheck

