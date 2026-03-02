#!/usr/bin/env python3
"""Filter two per-site .dat files to only include sites present in both."""

import argparse
import sys


def read_dat(path):
    """Return (header_line, list_of_data_lines) where each data line is kept as-is."""
    header = None
    rows = []  # (rank, site, raw_line)
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                header = line
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            rank, site = parts[0], parts[1]
            rows.append((int(rank), site, line))
    return header, rows


def main():
    parser = argparse.ArgumentParser(
        description="Keep only sites that appear in both per-site .dat files."
    )
    parser.add_argument("file_a", help="First per-site .dat file")
    parser.add_argument("file_b", help="Second per-site .dat file")
    args = parser.parse_args()

    hdr_a, rows_a = read_dat(args.file_a)
    hdr_b, rows_b = read_dat(args.file_b)

    sites_a = {(r, s) for r, s, _ in rows_a}
    sites_b = {(r, s) for r, s, _ in rows_b}
    common = sites_a & sites_b

    dropped_a = sites_a - common
    dropped_b = sites_b - common

    if dropped_a:
        print(f"Dropped from {args.file_a}:")
        for rank, site in sorted(dropped_a):
            print(f"  rank={rank}  site={site}")
    if dropped_b:
        print(f"Dropped from {args.file_b}:")
        for rank, site in sorted(dropped_b):
            print(f"  rank={rank}  site={site}")

    for path, hdr, rows in [(args.file_a, hdr_a, rows_a),
                             (args.file_b, hdr_b, rows_b)]:
        with open(path, "w") as f:
            if hdr:
                f.write(hdr)
            for rank, site, raw in rows:
                if (rank, site) in common:
                    f.write(raw)

    print(f"\nKept {len(common)} common sites in both files.")


if __name__ == "__main__":
    main()
