#!/bin/sh
# the list of commands that need to run before we do a compile
aclocal -I m4
libtoolize --force --automake --copy
autoheader
automake --add-missing --copy
autoconf
cd htp/
autoreconf -i --force
cd ..
