#!/usr/bin/env python3
"""Parse `go test -bench` outputs from run-cache-microbench.sh and emit:

  medians.json   full per-(source, bench, N, blockSize, op) median in ns/op
  table.txt      plaintext aligned table for the paper's Table 4 (extended)
  summary.md     human-readable comparison

Inputs (raw-dir):
  coredns_plain.txt   coredns LRU + ORAMCache, plain go test
  coredns_sgx.txt     coredns LRU + ORAMCache, ego run
  pathoram_plain.txt  pathoram-go LinearScan + Access, plain go test
  pathoram_sgx.txt    pathoram-go LinearScan + Access, ego run

Missing files are tolerated (skipped columns).
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from statistics import median

CORE_RE = re.compile(
    r"^Benchmark(LRU|ORAM)Cache_(Get|Put)/N=(\d+)-\d+\s+\d+\s+([\d.]+)\s+ns/op"
)
PORAM_RE = re.compile(
    r"^Benchmark([A-Za-z]+)/blocks=(\d+)/blockSize=(\d+)/(read|write)-\d+\s+\d+\s+([\d.]+)\s+ns/op"
)


def parse_coredns(path: Path) -> dict:
    """Returns {(cache, N, op): median_ns} for cache in {LRU, ORAM}."""
    samples = defaultdict(list)
    if not path.exists():
        return {}
    for line in path.read_text().splitlines():
        m = CORE_RE.match(line)
        if m:
            cache, op = m.group(1), m.group(2)
            n = int(m.group(3))
            ns = float(m.group(4))
            samples[(cache, n, op)].append(ns)
    return {k: median(v) for k, v in samples.items()}


def parse_pathoram(path: Path) -> dict:
    """Returns {(bench, N, blockSize, op): median_ns}."""
    samples = defaultdict(list)
    if not path.exists():
        return {}
    for line in path.read_text().splitlines():
        m = PORAM_RE.match(line)
        if m:
            bench = m.group(1)
            n = int(m.group(2))
            bs = int(m.group(3))
            op = m.group(4)
            ns = float(m.group(5))
            samples[(bench, n, bs, op)].append(ns)
    return {k: median(v) for k, v in samples.items()}


def fmt_us(ns: float | None) -> str:
    """Format ns/op as microseconds with appropriate precision."""
    if ns is None:
        return "--"
    us = ns / 1000.0
    if us < 1.0:
        return f"{us:.3f}"
    if us < 10.0:
        return f"{us:.2f}"
    if us < 100.0:
        return f"{us:.1f}"
    return f"{us:.0f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--block-size", type=int, required=True)
    ap.add_argument("--n-values", required=True, help="comma-separated")
    args = ap.parse_args()

    raw = Path(args.raw_dir)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    bs = args.block_size
    n_values = [int(x) for x in args.n_values.split(",")]

    core_plain = parse_coredns(raw / "coredns_plain.txt")
    core_sgx = parse_coredns(raw / "coredns_sgx.txt")
    poram_plain = parse_pathoram(raw / "pathoram_plain.txt")
    poram_sgx = parse_pathoram(raw / "pathoram_sgx.txt")

    # --- medians.json (full dump) ---
    def keyify(d, fn):
        return [{**fn(k), "ns_per_op": v} for k, v in d.items()]

    full = {
        "block_size": bs,
        "n_values": n_values,
        "coredns_plain": keyify(core_plain, lambda k: {"cache": k[0], "N": k[1], "op": k[2]}),
        "coredns_sgx": keyify(core_sgx, lambda k: {"cache": k[0], "N": k[1], "op": k[2]}),
        "pathoram_plain": keyify(
            poram_plain, lambda k: {"bench": k[0], "N": k[1], "block_size": k[2], "op": k[3]}
        ),
        "pathoram_sgx": keyify(
            poram_sgx, lambda k: {"bench": k[0], "N": k[1], "block_size": k[2], "op": k[3]}
        ),
    }
    (out / "medians.json").write_text(json.dumps(full, indent=2, sort_keys=True))

    # --- table.txt (extended Table 4, all values in microseconds) ---
    cols = [
        ("N", lambda n: str(n)),
        ("LRU/Plain",   lambda n: fmt_us(core_plain.get(("LRU", n, "Get")))),
        ("LRU/SGX",     lambda n: fmt_us(core_sgx.get(("LRU", n, "Get")))),
        ("LScan/Plain", lambda n: fmt_us(poram_plain.get(("LinearScan", n, bs, "read")))),
        ("LScan/SGX",   lambda n: fmt_us(poram_sgx.get(("LinearScan", n, bs, "read")))),
        ("ORAM/Plain",  lambda n: fmt_us(core_plain.get(("ORAM", n, "Get")))),
        ("ORAM/SGX",    lambda n: fmt_us(core_sgx.get(("ORAM", n, "Get")))),
        ("PORAM/Plain", lambda n: fmt_us(poram_plain.get(("Access", n, bs, "read")))),
        ("PORAM/SGX",   lambda n: fmt_us(poram_sgx.get(("Access", n, bs, "read")))),
    ]
    rows = [[fn(n) for _, fn in cols] for n in n_values]
    widths = [max(len(h), max(len(r[i]) for r in rows)) for i, (h, _) in enumerate(cols)]
    headers = [h for h, _ in cols]
    sep = "  "
    txt_lines = [
        "# Cache read (Get) latency vs capacity N (microseconds)",
        f"# block_size = {bs} bytes; values are medians across trials.",
        "",
        sep.join(h.rjust(w) for h, w in zip(headers, widths)),
        sep.join("-" * w for w in widths),
    ]
    for r in rows:
        txt_lines.append(sep.join(c.rjust(w) for c, w in zip(r, widths)))
    (out / "table.txt").write_text("\n".join(txt_lines) + "\n")

    # --- summary.md (markdown for sanity-check) ---
    md = ["# Cache microbenchmark summary", ""]
    md.append(f"- block_size = {bs} B")
    md.append(f"- N sweep: {n_values}")
    md.append("- All values in **microseconds** (median of trials).")
    md.append("")
    md.append(
        "| N | LRU plain | LRU sgx | LScan plain | LScan sgx | ORAM plain | ORAM sgx | PathORAM plain | PathORAM sgx |"
    )
    md.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for n in n_values:
        cells = [
            fmt_us(core_plain.get(("LRU", n, "Get"))),
            fmt_us(core_sgx.get(("LRU", n, "Get"))),
            fmt_us(poram_plain.get(("LinearScan", n, bs, "read"))),
            fmt_us(poram_sgx.get(("LinearScan", n, bs, "read"))),
            fmt_us(core_plain.get(("ORAM", n, "Get"))),
            fmt_us(core_sgx.get(("ORAM", n, "Get"))),
            fmt_us(poram_plain.get(("Access", n, bs, "read"))),
            fmt_us(poram_sgx.get(("Access", n, bs, "read"))),
        ]
        md.append(f"| {n} | " + " | ".join(cells) + " |")
    md.append("")
    md.append("## SGX overhead")
    md.append("")
    md.append("| N | LScan SGX/Plain | ORAM SGX/Plain | PathORAM SGX/Plain |")
    md.append("|---:|---:|---:|---:|")
    for n in n_values:
        def ratio(p, s):
            return f"{s/p:.2f}x" if (p and s) else "--"
        md.append(
            f"| {n} | "
            f"{ratio(poram_plain.get(('LinearScan',n,bs,'read')), poram_sgx.get(('LinearScan',n,bs,'read')))} | "
            f"{ratio(core_plain.get(('ORAM',n,'Get')), core_sgx.get(('ORAM',n,'Get')))} | "
            f"{ratio(poram_plain.get(('Access',n,bs,'read')), poram_sgx.get(('Access',n,bs,'read')))} |"
        )
    (out / "summary.md").write_text("\n".join(md) + "\n")

    print(f"  medians.json -> {out / 'medians.json'}")
    print(f"  table.txt    -> {out / 'table.txt'}")
    print(f"  summary.md   -> {out / 'summary.md'}")
    print()
    print((out / "table.txt").read_text())


if __name__ == "__main__":
    main()
