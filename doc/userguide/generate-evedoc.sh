#! /bin/sh
#
# Generate RST EVE documentation.
#
# This has been broken out of the Makefile so it can be called by
# make, and Sphinx via conf.py.

set -e

mkdir -p _generated
../../scripts/evedoc.py --output _generated/eve-index.rst ../../etc/schema.json
../../scripts/evedoc.py --output _generated/quic.rst --object quic ../../etc/schema.json
../../scripts/evedoc.py --output _generated/pgsql.rst --object pgsql ../../etc/schema.json
