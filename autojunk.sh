#!/bin/sh
# the list of commands that need to run before we do a compile
aclocal
libtoolize --force --automake --copy
autoheader
automake --add-missing --copy
autoconf

