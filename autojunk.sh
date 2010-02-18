#!/bin/sh
# the list of commands that need to run before we do a compile
aclocal --force -I m4
libtoolize --force --automake --copy
autoheader
automake --add-missing --copy
autoconf
cd libhtp/
autoreconf -i --force
cd ..
