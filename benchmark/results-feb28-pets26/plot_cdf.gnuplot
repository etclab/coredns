#!/usr/bin/env gnuplot

load 'style.gpi'

set terminal pdfcairo enhanced font "Helvetica,12" size 6,4
set output "cdf_odoh_codoh.pdf"

set xlabel "Time (ms)"
set ylabel "CDF"
set xrange [0:5000]
set yrange [0:1]
set key right bottom
set grid

plot "cdf_codoh.dat" index 1 using 1:2 with lines lw 3 title "CODoH Wall-Clock DNS", \
     "cdf_codoh.dat" index 2 using 1:2 with lines lw 3 title "CODoH Page Load", \
     "cdf_odoh.dat" index 1 using 1:2 with lines lw 3 title "ODoH Wall-Clock DNS", \
     "cdf_odoh.dat" index 2 using 1:2 with lines lw 3 title "ODoH Page Load"
