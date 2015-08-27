#!/bin/bash
#
# Script to setup a new decoder.
# Written by Victor Julien <victor@inliniac.net>
#

set -e
#set -x

function Usage {
    echo
    echo "$(basename $0) -- script to provision a decoder. The script"
    echo "makes a copy of the decode-template, sets the name and updates"
    echo " the build system."
    echo
    echo "Call from the 'src' directory, with one argument: the decoder name."
    echo
    echo "E.g. inside 'src': ../scripts/$(basename $0) ipv7"
    echo
}

function Done {
    echo
    echo "Decoder $NR has been set up in $FILE_C and $FILE_H and the"
    echo "build system has been updated."
    echo
    echo "The decoder should now compile cleanly. Try running 'make'."
    echo
    echo "Next steps are to edit the files to implement the actual"
    echo "decoding of $NR."
    echo
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

FILE_C="decode-${LC}.c"
FILE_H="decode-${LC}.h"
#echo $FILE_C
#echo $FILE_H

if [ ! -e ../configure.ac ] || [ ! -e Makefile.am ]; then
    Usage
    echo "ERROR: call from src/ directory"
    exit 1
fi
if [ ! -e decode-template.c ] || [ ! -e decode-template.h ]; then
    Usage
    echo "ERROR: input files decode-template.c and/or decode-template.h are missing"
    exit 1
fi
if [ -e $FILE_C ] || [ -e $FILE_H ]; then
    Usage
    echo "ERROR: file(s) $FILE_C and/or $FILE_H already exist, won't overwrite"
    exit 1
fi

cp decode-template.c $FILE_C
cp decode-template.h $FILE_H

# search and replaces
sed -i "s/TEMPLATE/${UC}/g" $FILE_C
sed -i "s/TEMPLATE/${UC}/g" $FILE_H
sed -i "s/Template/${NR}/g" $FILE_C
sed -i "s/Template/${NR}/g" $FILE_H
sed -i "s/template/${LC}/g" $FILE_C
sed -i "s/template/${LC}/g" $FILE_H
sed -i "s/decode-template.c decode-template.h \\\/decode-template.c decode-template.h \\\\\n${FILE_C} ${FILE_H} \\\/g" Makefile.am

Done
exit 0
