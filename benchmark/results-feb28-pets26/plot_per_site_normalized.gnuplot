#!/usr/bin/env gnuplot

load 'style.gpi'

set terminal pngcairo enhanced font "Helvetica,12" size 800,500
set output "per_site_normalized.png"

set xlabel "Website Rank"
set ylabel "CODoH / ODoH Ratio"
set title "Per-Site CODoH Normalized by ODoH"
set key top right
set grid

# Reference line at ratio = 1 (equal performance)
set arrow from graph 0, first 1 to graph 1, first 1 nohead dt 2 lc rgb "gray40" lw 1.5

# paste combines the two files side by side:
# cols 1-6 = codoh (rank, site, dns_mean, dns_std, page_mean, page_std)
# cols 7-12 = odoh  (rank, site, dns_mean, dns_std, page_mean, page_std)
plot "< paste cdf_codoh_per_site.dat cdf_odoh_per_site.dat" \
     using ($0):($5/$11):xtic(int($0) % 5 == 0 ? sprintf("%d", $1) : "") with lines lw 2 dt 1 title "Page Load Ratio", \
     "" using ($0):($3/$9) with lines lw 2 dt 3 title "DNS Ratio"
