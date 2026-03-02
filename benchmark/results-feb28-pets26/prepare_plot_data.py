#!/usr/bin/env python3
"""Parse results_har_odoh.csv and output CDF data suitable for gnuplot."""

import argparse
import csv
import math
from collections import defaultdict

def compute_cdf(values):
    """Return sorted values and their cumulative fractions."""
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    cdf = [(i + 1) / n for i in range(n)]
    return sorted_vals, cdf


def trimmed_mean_std(values, trim_fraction=0.10):
    """Compute mean and std dev after trimming `trim_fraction` from each end.

    For example, with trim_fraction=0.10 we drop the bottom 10 % and the
    top 10 % of the sorted values, then compute mean and *sample* standard
    deviation from what remains.  If there are too few values to trim
    (e.g. only 2-3 data points), we keep them all.
    """
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    k = math.floor(trim_fraction * n)          # number to drop from each end
    if k < 1 and n >= 3:
        k = 1                                   # drop at least the min and max
    trimmed = sorted_vals[k : n - k] if k > 0 else sorted_vals
    m = len(trimmed)
    mean = sum(trimmed) / m
    if m > 1:
        variance = sum((x - mean) ** 2 for x in trimmed) / (m - 1)
        std = math.sqrt(variance)
    else:
        std = 0.0
    return mean, std

def main():
    parser = argparse.ArgumentParser(
        description="Parse a HAR benchmark CSV and output CDF data files suitable for gnuplot."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default="results_har_odoh.csv",
        help="Input CSV file with benchmark results (default: results_har_odoh.csv)",
    )
    parser.add_argument(
        "-o", "--output",
        default="cdf_odoh.dat",
        help="Output .dat file for the main CDF data (default: cdf_odoh.dat)",
    )
    args = parser.parse_args()

    input_file = args.input_file
    output_file = args.output

    total_dns = []
    wall_clock_dns = []
    page_load = []
    invalid_rows = []

    with open(input_file, newline="") as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):  # header is row 1
            t = float(row["total_dns_sum_ms"])
            w = float(row["wall_clock_dns_ms"])
            p = float(row["page_load_ms"])
            if t == 0 or w == 0 or p == 0:
                continue
            if w > p:
                invalid_rows.append(
                    (row_num, row.get("rank", "?"), row.get("site", "?"), w, p)
                )
                continue
            total_dns.append(t)
            wall_clock_dns.append(w)
            page_load.append(p)

    if invalid_rows:
        print(f"\nDropped {len(invalid_rows)} record(s) where "
              f"wall_clock_dns_ms > page_load_ms (measurement error):")
        for row_num, rank, site, w, p in invalid_rows:
            print(f"  row {row_num}: rank={rank}  site={site}  "
                  f"wall_clock_dns_ms={w:.2f}  page_load_ms={p:.2f}")

    datasets = [
        ("total_dns_sum_ms", total_dns),
        ("wall_clock_dns_ms", wall_clock_dns),
        ("page_load_ms", page_load),
    ]

    with open(output_file, "w") as out:
        for i, (label, values) in enumerate(datasets):
            sorted_vals, cdf = compute_cdf(values)
            out.write(f"# Dataset {i}: {label}\n")
            for v, c in zip(sorted_vals, cdf):
                out.write(f"{v:.4f}\t{c:.6f}\n")
            out.write("\n\n")  # two blank lines separate gnuplot datasets

    print(f"Wrote {output_file} with {len(datasets)} datasets "
          f"({len(total_dns)} points each)")

    # DNS ratio: wall_clock_dns_ms / page_load_ms (fraction of page load spent on DNS)
    dns_ratio = [w / p for w, p in zip(wall_clock_dns, page_load)]
    ratio_file = output_file.replace(".dat", "_dns_ratio.dat")
    sorted_vals, cdf = compute_cdf(dns_ratio)
    with open(ratio_file, "w") as out:
        out.write("# CDF of wall_clock_dns_ms / page_load_ms\n")
        for v, c in zip(sorted_vals, cdf):
            out.write(f"{v:.6f}\t{c:.6f}\n")

    print(f"Wrote {ratio_file} with {len(dns_ratio)} points")

    # ------------------------------------------------------------------
    # Per-site trimmed statistics (drop top & bottom 10 % of each site's
    # repeated measurements, then compute mean and std dev).
    # ------------------------------------------------------------------
    # Re-read the CSV so we can group by (rank, site).
    site_data = defaultdict(lambda: {"wall_clock_dns": [], "page_load": []})

    with open(input_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            w = float(row["wall_clock_dns_ms"])
            p = float(row["page_load_ms"])
            if w == 0 or p == 0:
                continue
            if w > p:
                continue  # already logged above
            rank = int(row["rank"])
            site = row["site"]
            key = (rank, site)
            site_data[key]["wall_clock_dns"].append(w)
            site_data[key]["page_load"].append(p)

    # Sort sites by rank (ascending).
    sorted_sites = sorted(site_data.items(), key=lambda item: item[0][0])

    stats_file = output_file.replace(".dat", "_per_site.dat")
    with open(stats_file, "w") as out:
        out.write(
            "# rank\tsite\t"
            "wall_clock_dns_mean_ms\twall_clock_dns_std_ms\t"
            "page_load_mean_ms\tpage_load_std_ms\n"
        )
        for (rank, site), metrics in sorted_sites:
            w_mean, w_std = trimmed_mean_std(metrics["wall_clock_dns"])
            p_mean, p_std = trimmed_mean_std(metrics["page_load"])
            out.write(
                f"{rank}\t{site}\t"
                f"{w_mean:.4f}\t{w_std:.4f}\t"
                f"{p_mean:.4f}\t{p_std:.4f}\n"
            )

    print(f"Wrote {stats_file} with {len(sorted_sites)} sites "
          f"(trimmed 10 % from each tail)")

if __name__ == "__main__":
    main()
