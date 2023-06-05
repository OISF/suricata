#! /bin/sh

set -e

mkdir -p _generated
./evedoc.py --output _generated/eve-index.rst ../../etc/schema.json
./evedoc.py --output _generated/quic.rst --object quic ../../etc/schema.json
./evedoc.py --output _generated/pgsql.rst --object pgsql ../../etc/schema.json
