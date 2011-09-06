#!/bin/bash
#
#
if [ "$1" = "" ]; then
    echo "call with location of csv file."
    exit 1;
fi

DRAW="lines"
gnuplot << EOF
set datafile separator ","
set terminal png size 1024,768
set output "$1.png"
set title "$1 ticks"
set key autotitle columnhead
set yrange [:]
set xrange [:]
set logscale y
plot "$1" using :4 with $DRAW, \
         "" using :11 with $DRAW, \
         "" using :14 with $DRAW, \
         "" using :15 with $DRAW, \
         "" using :20 with $DRAW, \
         "" using :28 with $DRAW, \
         "" using :32 with $DRAW, \
         "" using :40 with $DRAW
EOF
RESULT=$?
if [ "$RESULT" = "0" ]; then
    echo "PNG $1.png written"
fi
