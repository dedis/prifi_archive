reset
set term postscript size 3,2 eps enhanced font "Helvetica, 10" 
set output outfile
    
set size 0.6, 0.6
set xlabel "# Clients"
set ylabel "Latency (s)"

set key left top Left reverse
set logscale xy

set style line 1 lc rgb '#0060ad' pt 1
set style line 2 lc rgb '#e00000' pt 2

plot asyncio using 1:3 with linespoints ls 1 ti "asyncio", \
     threads using 1:3 with linespoints ls 2 ti "threading"
