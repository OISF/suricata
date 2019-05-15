#!/usr/bin/sh

set -e
SCANBUILD=suricata_static_analyzer 

if [ -d "$DIRECTORY" ]; then
    rm -rfv $SCANBUILD
fi

mkdir $SCANBUILD


export CC=clang
export CXX=clang++
./autogen.sh

scan-build ./configure 
scan-build -o ../suricata_static_analyzer make 
