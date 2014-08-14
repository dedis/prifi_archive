#!/bin/bash

if [[ $# -ne 1 ]]; then
  echo "usage $0 data"
  exit
fi

BASEFILE=baseline.data.internal
SOCKSFILE=socksonly.data.internal
GOFILE=go.data.internal
PYFILE=py.data.internal
GPFILE=plot.gp.internal

OUTFILE=pyvsgo.eps

cut -d' ' -f1,7 $1/baseline/baseline.data | sed 's/s//' | python3 aggregate.py > $BASEFILE
cut -d' ' -f1,7 $1/socksonly/socksonly.data | sed 's/s//' | python3 aggregate.py > $SOCKSFILE
cut -d' ' -f1,7 $1/go/go.data | sed 's/s//' | python3 aggregate.py > $GOFILE
cut -d' ' -f1,7 $1/python/python.data | sed 's/s//' | python3 aggregate.py > $PYFILE

cat > $GPFILE << EOF

reset
set term postscript size 3,2 eps enhanced font "Helvetica, 10"
set output "${OUTFILE}"

set size 0.6, 0.6
set xlabel "# Connections"
set ylabel "Latency (s)"

set key left top Left reverse

set style line 1 lc rgb '#000000' lt 1 lw 2 pt 0
set style line 2 lc rgb '#007700' lt 1 lw 2 pt 0
set style line 3 lc rgb '#0060ad' lt 1 lw 2 pt 0
set style line 4 lc rgb '#e00000' lt 1 lw 2 pt 0

plot "${BASEFILE}" using 1:2:3 with yerrorbars ls 1 ti "Baseline", \
     "" using 1:2 with lines ls 1 notitle, \
     "${SOCKSFILE}" using 1:2:3 with yerrorbars ls 2 ti "Socks-only", \
     "" using 1:2 with lines ls 2 notitle, \
     "${GOFILE}" using 1:2:3 with yerrorbars ls 3 ti "Go", \
     "" using 1:2 with lines ls 3 notitle, \
     "${PYFILE}" using 1:2:3 with yerrorbars ls 4 ti "Python3", \
     "" using 1:2 with lines ls 4 notitle

EOF

gnuplot $GPFILE

rm $BASEFILE $SOCKSFILE $GOFILE $PYFILE $GPFILE
