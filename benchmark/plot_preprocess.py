#!/usr/bin/env python3
"""CODoH benchmark preprocessor: CDF computation, LaTeX tables, gnuplot scripts.

Usage: python3 plot_preprocess.py <results-dir>

Reads raw/ JSON summaries and CSVs, writes to <results-dir>/plots/:
  - *.cdf          Sorted CDF data files
  - cdf_*.gp       Gnuplot scripts per workload
  - table_*.tex    LaTeX table fragments
"""

import csv
import json
import os
import sys
from collections import OrderedDict
from pathlib import Path

# ---------------------------------------------------------------------------
# Config registry
# ---------------------------------------------------------------------------

CONFIGS = OrderedDict([
    ("doh", {
        "aliases": ["config1"],
        "num": 1,
        "label": "DoH",
        "ls": 1,
        "dt": 1,
        "color": "#4477AA",   # Tol bright blue
    }),
    ("odoh", {
        "aliases": ["config2"],
        "num": 2,
        "label": "ODoH",
        "ls": 2,
        "dt": 2,
        "color": "#EE6677",   # Tol bright red
    }),
    ("codoh-base", {
        "aliases": ["config3"],
        "num": 3,
        "label": r"CODoH (LRU, SGX)",
        "ls": 3,
        "dt": 3,
        "color": "#228833",   # Tol bright green
    }),
    ("codoh-nosgx", {
        "aliases": ["config4"],
        "num": 4,
        "label": r"CODoH (ORAM, sim)",
        "ls": 4,
        "dt": 4,
        "color": "#CCBB44",   # Tol bright yellow
    }),
    ("codoh-full", {
        "aliases": ["config5"],
        "num": 5,
        "label": r"CODoH (ORAM, SGX)",
        "ls": 5,
        "dt": 5,
        "color": "#AA3377",   # Tol bright purple
    }),
])

WORKLOADS = ["cold", "zipf", "warm"]

CDF_XRANGE = {"cold": 150, "zipf": 100, "warm": 20}

# Reverse alias map: "config1" -> "doh", etc.
_ALIAS_MAP = {}
for name, cfg in CONFIGS.items():
    for alias in cfg["aliases"]:
        _ALIAS_MAP[alias] = name


def resolve_config_name(prefix):
    """Map a filename prefix to the canonical config name."""
    if prefix in CONFIGS:
        return prefix
    return _ALIAS_MAP.get(prefix)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def discover_files(raw_dir):
    """Scan raw/ and return {(config_name, workload): {"json": path, "csv": path}}.

    Handles both canonical names (doh_cold.json) and aliases (config1_cold.json).
    """
    found = {}
    raw = Path(raw_dir)
    if not raw.is_dir():
        return found

    for f in sorted(raw.iterdir()):
        if f.is_dir():
            continue
        stem = f.stem  # e.g. "config1_cold" or "doh_cold"
        ext = f.suffix  # ".json" or ".csv"
        if ext not in (".json", ".csv"):
            continue

        # Split on last underscore to separate config prefix from workload
        parts = stem.rsplit("_", 1)
        if len(parts) != 2:
            print(f"  WARN: skipping unrecognized file: {f.name}", file=sys.stderr)
            continue
        prefix, workload = parts
        if workload not in WORKLOADS:
            print(f"  WARN: unknown workload '{workload}' in {f.name}", file=sys.stderr)
            continue

        config_name = resolve_config_name(prefix)
        if config_name is None:
            print(f"  WARN: unknown config prefix '{prefix}' in {f.name}", file=sys.stderr)
            continue

        key = (config_name, workload)
        if key not in found:
            found[key] = {}
        found[key][ext.lstrip(".")] = str(f)

    return found


def discover_sweep(raw_dir, sweep_type):
    """Discover sweep directories (sweep_oram_* or sweep_cover_*).

    Returns {param_value: {(config_name, workload): {"json": path, "csv": path}}}.
    """
    raw = Path(raw_dir)
    sweeps = {}
    prefix = f"sweep_{sweep_type}_"

    for d in sorted(raw.iterdir()):
        if not d.is_dir() or not d.name.startswith(prefix):
            continue
        param_str = d.name[len(prefix):]
        try:
            param_val = int(param_str)
        except ValueError:
            continue
        sweeps[param_val] = discover_files(str(d))

    return sweeps


# ---------------------------------------------------------------------------
# CDF computation
# ---------------------------------------------------------------------------

def compute_cdf(csv_path, output_path):
    """Read CSV, extract latency_ms, write sorted CDF file."""
    latencies = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                lat = float(row["latency_ms"])
                latencies.append(lat)
            except (ValueError, KeyError):
                continue

    if not latencies:
        print(f"  WARN: no latency data in {csv_path}", file=sys.stderr)
        return False

    latencies.sort()
    n = len(latencies)

    with open(output_path, "w") as f:
        f.write("# latency_ms cumulative_fraction\n")
        for i, lat in enumerate(latencies, 1):
            f.write(f"{lat:.3f} {i / n:.6f}\n")

    return True


# ---------------------------------------------------------------------------
# LaTeX table generation
# ---------------------------------------------------------------------------

def _fmt_lat(val):
    """Format a latency value for LaTeX."""
    if val is None:
        return "--"
    return f"{val:.1f}"


def _fmt_overhead(val, baseline):
    """Format value with overhead multiplier vs baseline."""
    if val is None or baseline is None:
        return "--"
    if baseline == 0:
        return _fmt_lat(val)
    ratio = val / baseline
    return f"{val:.1f} ({ratio:.1f}$\\times$)"


def generate_comparison_table(files, plots_dir):
    """Generate the main comparison LaTeX table."""
    # Load all JSON data
    data = {}  # (config_name, workload) -> latency_ms dict
    for (cfg, wl), paths in files.items():
        if "json" not in paths:
            continue
        with open(paths["json"]) as f:
            j = json.load(f)
        data[(cfg, wl)] = j.get("latency_ms", {})

    # Get ODoH baseline
    odoh_data = {}
    for wl in WORKLOADS:
        odoh_data[wl] = data.get(("odoh", wl), {})

    lines = []
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Latency comparison across configurations (ms).}")
    lines.append(r"\label{tab:comparison}")
    lines.append(r"\small")
    lines.append(r"\begin{tabular}{l" + " rrr" * len(WORKLOADS) + "}")
    lines.append(r"\toprule")

    # Header row 1: workload groups
    header1 = ""
    for wl in WORKLOADS:
        col_start = 2 + WORKLOADS.index(wl) * 3
        col_end = col_start + 2
        header1 += f" & \\multicolumn{{3}}{{c}}{{{wl.capitalize()}}}"
    lines.append(header1 + r" \\")

    # Cmidrules
    rules = ""
    for i, wl in enumerate(WORKLOADS):
        col_start = 2 + i * 3
        col_end = col_start + 2
        rules += f"\\cmidrule(lr){{{col_start}-{col_end}}} "
    lines.append(rules.strip() + "")

    # Header row 2: percentiles
    header2 = "Configuration"
    for _ in WORKLOADS:
        header2 += " & p50 & p95 & p99"
    lines.append(header2 + r" \\")
    lines.append(r"\midrule")

    # Data rows
    for cfg_name, cfg_info in CONFIGS.items():
        row = cfg_info["label"]
        has_data = False

        for wl in WORKLOADS:
            lat = data.get((cfg_name, wl), {})
            if not lat:
                row += " & -- & -- & --"
                continue
            has_data = True

            for pct in ["p50", "p95", "p99"]:
                val = lat.get(pct)
                baseline_val = odoh_data.get(wl, {}).get(pct)

                if cfg_info["num"] >= 3 and baseline_val is not None:
                    row += f" & {_fmt_overhead(val, baseline_val)}"
                else:
                    row += f" & {_fmt_lat(val)}"

        if has_data:
            lines.append(row + r" \\")

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    out_path = os.path.join(plots_dir, "table_comparison.tex")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Generated {out_path}")


def generate_sweep_table(sweep_data, main_data, sweep_type, param_name, main_param_val, plots_dir):
    """Generate a sweep table (ORAM or cover).

    sweep_data: {param_val: {(config, workload): {"json": path}}}
    main_data: {(config, workload): {"json": path}} for the default param value
    """
    # Collect all param values (sorted), inserting main in the right place
    all_params = sorted(set(list(sweep_data.keys()) + [main_param_val]))

    # Load latency data per (param_val, workload)
    data = {}  # (param_val, workload) -> latency_ms dict
    for param_val, files in sweep_data.items():
        for (cfg, wl), paths in files.items():
            if cfg == "codoh-full" and "json" in paths:
                with open(paths["json"]) as f:
                    j = json.load(f)
                data[(param_val, wl)] = j.get("latency_ms", {})

    # Main param value comes from main_data
    for (cfg, wl), paths in main_data.items():
        if cfg == "codoh-full" and "json" in paths:
            with open(paths["json"]) as f:
                j = json.load(f)
            data[(main_param_val, wl)] = j.get("latency_ms", {})

    if not data:
        return

    lines = []
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")

    if sweep_type == "oram":
        lines.append(r"\caption{Effect of ORAM capacity on CODoH latency (ms).}")
        lines.append(r"\label{tab:sweep-oram}")
    else:
        lines.append(r"\caption{Effect of cover count on CODoH latency (ms).}")
        lines.append(r"\label{tab:sweep-cover}")

    lines.append(r"\small")
    lines.append(r"\begin{tabular}{l" + " rrr" * len(all_params) + "}")
    lines.append(r"\toprule")

    # Header: param values
    header1 = ""
    for pv in all_params:
        col_start = 2 + all_params.index(pv) * 3
        col_end = col_start + 2
        header1 += f" & \\multicolumn{{3}}{{c}}{{{param_name}={pv}}}"
    lines.append(header1 + r" \\")

    rules = ""
    for i in range(len(all_params)):
        col_start = 2 + i * 3
        col_end = col_start + 2
        rules += f"\\cmidrule(lr){{{col_start}-{col_end}}} "
    lines.append(rules.strip())

    header2 = "Workload"
    for _ in all_params:
        header2 += " & p50 & p95 & p99"
    lines.append(header2 + r" \\")
    lines.append(r"\midrule")

    for wl in WORKLOADS:
        row = wl.capitalize()
        for pv in all_params:
            lat = data.get((pv, wl), {})
            for pct in ["p50", "p95", "p99"]:
                row += f" & {_fmt_lat(lat.get(pct))}"
        lines.append(row + r" \\")

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    out_path = os.path.join(plots_dir, f"table_sweep_{sweep_type}.tex")
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  Generated {out_path}")


# ---------------------------------------------------------------------------
# Gnuplot script generation
# ---------------------------------------------------------------------------

def generate_gnuplot_scripts(files, plots_dir, style_gpi_rel):
    """Generate one .gp file per workload."""
    for wl in WORKLOADS:
        # Collect available configs for this workload
        plot_lines = []
        for cfg_name, cfg_info in CONFIGS.items():
            cdf_file = f"{cfg_name}_{wl}.cdf"
            cdf_path = os.path.join(plots_dir, cdf_file)
            if not os.path.exists(cdf_path):
                continue
            sep = ", \\\n     " if plot_lines else ""
            line = (
                f'"{cdf_file}" using 1:2 with lines '
                f"ls {cfg_info['ls']} dt {cfg_info['dt']} lw 3 "
                f'title "{cfg_info["label"]}"'
            )
            plot_lines.append(line)

        if not plot_lines:
            print(f"  WARN: no CDF data for workload '{wl}', skipping gnuplot script", file=sys.stderr)
            continue

        xmax = CDF_XRANGE[wl]

        # Override style.gpi colors with Tol bright (more saturated/distinct)
        color_overrides = ""
        for cfg_name2, cfg_info2 in CONFIGS.items():
            color_overrides += (
                f'set style line {cfg_info2["ls"]} '
                f'linecolor rgb "{cfg_info2["color"]}"\n'
            )

        gp_content = f"""\
load "{style_gpi_rel}"
# Override with Tol bright palette
{color_overrides}set output "cdf_{wl}.eps"
set xlabel "Latency (ms)"
set ylabel "CDF"
set xrange [0:{xmax}]
set yrange [0:1]
set key bottom right

plot {", ".join(chr(92) + chr(10) + "     " + p if i > 0 else p for i, p in enumerate(plot_lines))}
"""

        gp_path = os.path.join(plots_dir, f"cdf_{wl}.gp")
        with open(gp_path, "w") as f:
            f.write(gp_content)
        print(f"  Generated {gp_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <results-dir>", file=sys.stderr)
        sys.exit(1)

    results_dir = sys.argv[1]
    raw_dir = os.path.join(results_dir, "raw")
    plots_dir = os.path.join(results_dir, "plots")

    if not os.path.isdir(raw_dir):
        print(f"ERROR: {raw_dir} not found", file=sys.stderr)
        sys.exit(1)

    os.makedirs(plots_dir, exist_ok=True)

    # 1. Discover files
    print("Discovering files...")
    files = discover_files(raw_dir)
    configs_found = sorted(set(cfg for cfg, _ in files))
    workloads_found = sorted(set(wl for _, wl in files))
    print(f"  Configs: {configs_found}")
    print(f"  Workloads: {workloads_found}")

    if not files:
        print("ERROR: no data files found in raw/", file=sys.stderr)
        sys.exit(1)

    # 2. Compute CDFs from CSVs
    print("Computing CDFs...")
    for (cfg, wl), paths in sorted(files.items()):
        if "csv" not in paths:
            continue
        cdf_out = os.path.join(plots_dir, f"{cfg}_{wl}.cdf")
        if compute_cdf(paths["csv"], cdf_out):
            print(f"  {cfg}_{wl}.cdf ({os.path.basename(paths['csv'])})")

    # 3. Generate LaTeX tables
    print("Generating LaTeX tables...")
    generate_comparison_table(files, plots_dir)

    # Sweep tables
    oram_sweeps = discover_sweep(raw_dir, "oram")
    if oram_sweeps:
        print(f"  ORAM sweep found: N={sorted(oram_sweeps.keys())}")
        generate_sweep_table(oram_sweeps, files, "oram", "N", 1024, plots_dir)

    cover_sweeps = discover_sweep(raw_dir, "cover")
    if cover_sweeps:
        print(f"  Cover sweep found: k={sorted(cover_sweeps.keys())}")
        generate_sweep_table(cover_sweeps, files, "cover", "k", 3, plots_dir)

    # 4. Generate gnuplot scripts
    print("Generating gnuplot scripts...")
    # Compute relative path from plots_dir to style.gpi
    # style.gpi is at benchmark/style.gpi; plots_dir is benchmark/results/<run>/plots/
    script_dir = os.path.dirname(os.path.abspath(__file__))
    style_gpi = os.path.join(script_dir, "style.gpi")
    style_gpi_rel = os.path.relpath(style_gpi, os.path.abspath(plots_dir))
    generate_gnuplot_scripts(files, plots_dir, style_gpi_rel)

    print("Done. Run gnuplot and epstopdf from plot.sh to finalize.")


if __name__ == "__main__":
    main()
