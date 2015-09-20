#!/bin/bash
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
#echo $FILE_C
#echo $FILE_H

if [ ! -e ../configure.ac ] || [ ! -e Makefile.am ]; then
    Usage
    echo "ERROR: call from src/ directory"
    exit 1
fi
if [ ! -e detect-template.c ] || [ ! -e detect-template.h ]; then
    Usage
    echo "ERROR: input files detect-template.c and/or detect-template.h are missing"
    exit 1
fi
if [ -e $FILE_C ] || [ -e $FILE_H ]; then
    Usage
    echo "ERROR: file(s) $FILE_C and/or $FILE_H already exist, won't overwrite"
    exit 1
fi

cp detect-template.c $FILE_C
cp detect-template.h $FILE_H

# search and replaces
sed -i "s/TEMPLATE/${UC}/g" $FILE_C
sed -i "s/TEMPLATE/${UC}/g" $FILE_H
sed -i "s/Template/${NR}/g" $FILE_C
sed -i "s/Template/${NR}/g" $FILE_H
sed -i "s/template/${LC}/g" $FILE_C
sed -i "s/template/${LC}/g" $FILE_H
# add to Makefile.am
sed -i "s/detect-template.c detect-template.h \\\/detect-template.c detect-template.h \\\\\n${FILE_C} ${FILE_H} \\\/g" Makefile.am
# update enum
sed -i "s/DETECT_TEMPLATE,/DETECT_TEMPLATE,\\n    DETECT_${UC},/g" detect.h
# add include to detect.c
sed -i "s/#include \"detect-template.h\"/#include \"detect-template.h\"\\n#include \"${FILE_H}\"/g" detect.c
# add reg func to detect.c
sed -i "s/DetectTemplateRegister();/DetectTemplateRegister();\\n    Detect${NR}Register();/g" detect.c

Done
exit 0
