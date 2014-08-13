#!/bin/bash

if [[ $# -ne 2 ]]; then
  echo "usage $0 godata pydata"
  exit
fi

GOFILE=go.data.internal
PYFILE=py.data.internal
GPFILE=plot.gp.internal
OUTFILE=bench.eps

cut -d' ' -f1,7 $1 | sed 's/s//' | python3 aggregate.py > $GOFILE
cut -d' ' -f1,7 $2 | sed 's/s//' | python3 aggregate.py > $PYFILE

cat > $GPFILE << EOF

reset
set term postscript size 3,2 eps enhanced font "Helvetica, 10"
set output "${OUTFILE}"

set size 0.6, 0.6
set xlabel "# Connections"
set ylabel "Latency (s)"

set key left top Left reverse

set style line 1 lc rgb '#0060ad' lt 1 lw 2 pt 0
set style line 2 lc rgb '#e00000' lt 1 lw 2 pt 0

plot "${GOFILE}" using 1:2:3 with yerrorbars ls 1 ti "Go", \
     "" using 1:2 with lines ls 1 notitle, \
     "${PYFILE}" using 1:2:3 with yerrorbars ls 2 ti "Python3", \
     "" using 1:2 with lines ls 2 notitle

EOF

gnuplot $GPFILE

rm $GOFILE $PYFILE $GPFILE
