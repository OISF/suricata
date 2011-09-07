#!/bin/bash
#
#
if [ "$1" = "" ]; then
    echo "call with location of csv file."
    exit 1;
fi

gnuplot << EOF
set datafile separator ","
set terminal png size 1024,768
set output "$1.png"
set title "$1 ticks"
set key autotitle columnhead
set yrange [:]
set xrange [:]
set logscale y
plot "$1" using 4, for [i in $2] '' using i with $3
EOF
RESULT=$?
if [ "$RESULT" = "0" ]; then
    echo "PNG $1.png written"
fi
