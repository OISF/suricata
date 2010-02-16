#!/bin/bash

# Are we in the correct working directory?
if [ ! -f ./htp/htp.c ]
then
    echo "ERROR: Please invoke this script from the main directory (of libhtp)"
    exit
fi

# Test for the presence of svnversion
if [ -z `which svnversion` ]
then
    echo "ERROR: Unable to retrieve the revision number because 'svnversion' could not be found"
    exit
fi

if [ -z `which sed` ]
then
    echo "ERROR: Unable to retrieve the revision number because 'sed' could not be found"
    exit
fi

# Retrieve the revision number
REV=`svnversion -n`

#echo $REV

sed -e "s/\$REVISION_MISSING/$REV/" -i ./htp/htp.c

