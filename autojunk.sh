#!/bin/sh
# the list of commands that need to run before we do a compile
libtoolize --force --automake --copy
aclocal
autoheader
automake --add-missing --copy
autoconf

