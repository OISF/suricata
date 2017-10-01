#! /bin/sh

set -e

# Create temp. directory and copy in sources.
tmpdir=$(mktemp -d)
trap "rm -rf ${tmpdir}" EXIT

(cd .. && tar cf - $(git ls-files)) | (cd ${tmpdir} && tar xf -)

if [ -e ../libhtp ]; then
    (cd ../libhtp && git archive --format=tar --prefix=libhtp/ HEAD) | \
	(cd ${tmpdir} && tar xvf -)
else
    echo "error: this script required bundled libhtp..."
    exit 1
fi

cd ${tmpdir}

# Do initial build.
./autogen.sh
./configure

./scripts/setup-app-layer.sh Echo

./scripts/setup-app-layer-detect.sh Echo request

./scripts/setup-app-layer-logger.sh Echo

./scripts/setup-decoder.sh Udplite

./scripts/setup-simple-detect.sh simpledetect

make distcheck

