#!/usr/bin/env gnuplot

load 'style.gpi'

# set terminal pdfcairo enhanced font "Helvetica,12" size 8,5
set output "per_site_codoh_vs_odoh.pdf"

set xlabel "Website Rank"
set ylabel "Time (ms)"
# set title "Per-Site CODoH vs ODoH Comparison"
set key top right
set grid

# set logscale x

# lines linestyle 1 linewidth 4 dashtype '.'
# plot "cdf_codoh_per_site.dat" using ($0):5:xtic(int($0) % 5 == 0 ? sprintf("%d", $1) : "") with lines lw 4 dt 1 lc rgb "#0072B2" title "CODoH Page Load", \
#      "cdf_codoh_per_site.dat" using ($0):3 with lines lw 2 dt 3 lc rgb "#0072B2" title "CODoH DNS", \
#      "cdf_odoh_per_site.dat" using ($0):5 with lines lw 2 dt 1 lc rgb "#D55E00" title "ODoH Page Load", \
#      "cdf_odoh_per_site.dat" using ($0):3 with lines lw 2 dt 3 lc rgb "#D55E00" title "ODoH DNS"

plot "cdf_codoh_per_site.dat" using ($0):5:xtic(int($0) % 5 == 0 ? sprintf("%d", $1) : "") with lines ls 1 lw 4 dt '.' title "CODoH Page Load", \
     "cdf_codoh_per_site.dat" using ($0):3 with lines ls 2 lw 4 dt '.-.' title "CODoH DNS", \
     "cdf_odoh_per_site.dat" using ($0):5 with lines ls 3 lw 4 dt 1 title "ODoH Page Load", \
     "cdf_odoh_per_site.dat" using ($0):3 with lines ls 4 lw 4 dt '-.-' title "ODoH DNS"

