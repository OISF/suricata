#!/usr/bin/env bash
#
# Script to setup a new 'simple' detect module.
# Written by Victor Julien <victor@inliniac.net>
#

set -e
#set -x

function Usage {
    echo
    echo "$(basename $0) -- script to provision a detect module. The script"
    echo "makes a copy of detect-template, sets the name and updates"
    echo "the build system."
    echo
    echo "Call from the 'src' directory, with one argument: the detect module"
    echo "name."
    echo
    echo "E.g. inside 'src': ../scripts/$(basename $0) helloworld"
    echo
}

function Done {
    echo
    echo "Detect module $NR has been set up in $FILE_C and $FILE_H"
    echo "and the build system has been updated."
    echo
    echo "The detect module should now compile cleanly. Try running 'make'."
    echo
    echo "Next steps are to edit the files to implement the actual"
    echo "detection logic of $NR."
    echo
}

# Make sure we are running from the correct directory.
set_dir() {
    if [ -e ./suricata.c ]; then
	# Do nothing.
	true
    elif [ -e ./src/suricata.c ]; then
	cd src
    else
	echo "error: this does not appear to be a suricata source directory."
	exit 1
    fi
}

if [ $# -ne "1" ]; then
    Usage
    echo "ERROR: call with one argument"
    exit 1
fi

INPUT=$1
# lowercase
LC=${INPUT,,}
#echo $LC
# UPPERCASE
UC=${LC^^}
#echo $UC
# Normal
NR=${LC^}
#echo $NR

FILE_C="detect-${LC}.c"
FILE_H="detect-${LC}.h"

set_dir

if [ ! -e detect-template2.c ] || [ ! -e detect-template2.h ]; then
    Usage
    echo "ERROR: input files detect-template.c and/or detect-template.h are missing"
    exit 1
fi
if [ -e $FILE_C ] || [ -e $FILE_H ]; then
    Usage
    echo "ERROR: file(s) $FILE_C and/or $FILE_H already exist, won't overwrite"
    exit 1
fi

FILE_C="detect-${LC}.c"
FILE_H="detect-${LC}.h"
cp detect-template2.c $FILE_C
cp detect-template2.h $FILE_H

# search and replaces
sed -i "s/TEMPLATE2/${UC}/g" $FILE_C
sed -i "s/TEMPLATE2/${UC}/g" $FILE_H
sed -i "s/Template2/${NR}/g" $FILE_C
sed -i "s/Template2/${NR}/g" $FILE_H
sed -i "s/template2/${LC}/g" $FILE_C
sed -i "s/template2/${LC}/g" $FILE_H
# add to Makefile.am
sed -i "s/detect-template2.c detect-template2.h \\\/detect-template2.c detect-template2.h \\\\\n${FILE_C} ${FILE_H} \\\/g" Makefile.am

# update enum
sed -i "s/DETECT_TEMPLATE2,/DETECT_TEMPLATE2,\\n    DETECT_${UC},/g" detect-engine-register.h

# add include to detect-engine-register.c
sed -i "s/#include \"detect-template2.h\"/#include \"detect-template2.h\"\\n#include \"${FILE_H}\"/g" detect-engine-register.c

# add reg func to detect-engine-register.c
sed -i "s/DetectTemplate2Register();/DetectTemplate2Register();\\n    Detect${NR}Register();/g" detect-engine-register.c

Done
exit 0
