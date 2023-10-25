#!/bin/sh
# Run this to generate all the initial makefiles, etc.
if which libtoolize > /dev/null; then
  echo "Found libtoolize"
  libtoolize -c
elif which glibtoolize > /dev/null; then
  echo "Found glibtoolize"
  glibtoolize -c
else
  echo "Failed to find libtoolize or glibtoolize, please ensure it is installed and accessible via your PATH env variable"
  exit 1
fi;
PRODUCT_NAME=${PRODUCT_NAME:-suricata}
PRODUCT_VERSION=${PRODUCT_VERSION:-7.0.3-dev}
sed -e "s/@PRODUCT_NAME@/$PRODUCT_NAME/" -e "s/@PRODUCT_VERSION@/$PRODUCT_VERSION/"  configure.ac.in > configure.ac
autoreconf -fv --install || exit 1
if which cargo > /dev/null; then
    if [ -f rust/Cargo.lock ] ; then
        rm -f rust/Cargo.lock
    fi
fi;
echo "You can now run \"./configure\" and then \"make\"."
