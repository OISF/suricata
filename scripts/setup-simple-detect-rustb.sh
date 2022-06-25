#!/usr/bin/env bash
#
# Script to setup a new 'simple' detect module.
# Written by Philippe Antoine
# based on previous scripts by Victor Julien
#

set -e
set -x

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

PROTOCOL=$(echo $1 | cut -f1 -d-)
KEYWORD=$(echo $1 | cut -f2 -d-)
PLC=${PROTOCOL,,}
PUC=${PLC^^}
PNR=${PLC^}
KLC=${KEYWORD,,}
KUC=${KLC^^}
KNR=${KLC^}

FILE_C="detect-${LC}.c"
FILE_H="detect-${LC}.h"

set_dir

if [ ! -e detect-snmp-usm.c ] || [ ! -e detect-snmp-usm.h ]; then
    Usage
    echo "ERROR: input files detect-snmp-usm.c and/or detect-snmp-usm.h are missing"
    exit 1
fi
if [ -e $FILE_C ] || [ -e $FILE_H ]; then
    Usage
    echo "ERROR: file(s) $FILE_C and/or $FILE_H already exist, won't overwrite"
    exit 1
fi

FILE_C="detect-${LC}.c"
FILE_H="detect-${LC}.h"
cp detect-snmp-usm.c $FILE_C
cp detect-snmp-usm.h $FILE_H

# search and replaces
sed -i -e "s/SNMP/${PUC}/g" $FILE_C
sed -i -e "s/SNMP/${PUC}/g" $FILE_H
sed -i -e "s/snmp/${PLC}/g" $FILE_C
sed -i -e "s/snmp/${PLC}/g" $FILE_H
sed -i -e "s/Snmp/${PNR}/g" $FILE_C
sed -i -e "s/Snmp/${PNR}/g" $FILE_H
sed -i -e "s/USM/${KUC}/g" $FILE_C
sed -i -e "s/USM/${KUC}/g" $FILE_H
sed -i -e "s/usm/${KLC}/g" $FILE_C
sed -i -e "s/usm/${KLC}/g" $FILE_H
sed -i -e "s/Usm/${KNR}/g" $FILE_C
sed -i -e "s/Usm/${KNR}/g" $FILE_H

# add to Makefile.am
sed -i -e "s/\tdetect-template.c \\\/\tdetect-template.c \\\\\n\t${FILE_C} \\\/g" Makefile.am
sed -i -e "s/detect-template.h \\\/detect-template.h \\\\\n\t${FILE_H} \\\/g" Makefile.am

# update enum
sed -i -e "s/DETECT_TEMPLATE,/DETECT_TEMPLATE,\\n    DETECT_AL_${PUC}_${KUC},/g" detect-engine-register.h

# add include to detect-engine-register.c
sed -i -e "s/#include \"detect-template.h\"/#include \"detect-template.h\"\\n#include \"${FILE_H}\"/g" detect-engine-register.c

# add reg func to detect-engine-register.c
sed -i -e "s/DetectTemplateRegister();/DetectTemplateRegister();\\n    Detect${PUC}${KNR}Register();/g" detect-engine-register.c

git add $FILE_C
git add $FILE_H

Done
exit 0
