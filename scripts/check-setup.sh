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
make

./scripts/setup-app-layer.sh Echo
make

./scripts/setup-app-layer-detect.sh Echo request
make

./scripts/setup-app-layer-logger.sh Echo
make

./scripts/setup-decoder.sh Udplite
make

./scripts/setup-simple-detect.sh simpledetect
make
