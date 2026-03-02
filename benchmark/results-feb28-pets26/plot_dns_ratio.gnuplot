#!/usr/bin/env gnuplot

load 'style.gpi'

# set terminal pdfcairo enhanced font "Helvetica,12" size 6,4
set output "cdf_dns_ratio.pdf"

set xlabel "DNS Time / Page Load Time"
set ylabel "CDF"
set yrange [0:1]
set xrange [0:*]
set key right bottom
set grid

set format x "%.0f%%"
plot "cdf_codoh_dns_ratio.dat" using ($1*100):2 with lines lw 2 title "CODoH DNS / Page Load", \
     "cdf_odoh_dns_ratio.dat" using ($1*100):2 with lines lw 2 title "ODoH DNS / Page Load"
