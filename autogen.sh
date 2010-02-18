#!/bin/sh
# Run this to generate all the initial makefiles, etc.
autoreconf -fv --install
echo "You can now run \"./configure\" and then \"make\"."
