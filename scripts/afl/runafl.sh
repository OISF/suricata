#!/bin/bash

PROTO=$1

if [ ! -d $1 ]; then
        mkdir -p $1/output
        mkdir -p $1/dump
        mkdir -p $1/input
        echo "1" > $1/input/seed.txt
else
        CRASHES=$(ls ${1}/output/crashes|wc -l)
        if [ $CRASHED -ne "0" ]; then
            DIRNAME=$(date +%s)
            mkdir "${1}/$DIRNAME"
            mv -f ${1}/output/crashes/* ${1}/$DIRNAME/
        fi
        mv -f $1/output/queue/id* $1/input/
        rm -r $1/output/
        mkdir $1/output
fi
cd $1
export ASAN_OPTIONS="detect_leaks=0 abort_on_error=1 symbolize=0"
export AFL_SKIP_CPUFREQ=1
/usr/local/bin/afl-fuzz -T ${PROTO} -t 1000 -m none -i input/ -o output/ -- ../../src/suricata --afl-${PROTO}=@@
