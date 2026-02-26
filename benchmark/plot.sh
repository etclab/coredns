#!/bin/bash
# CODoH Benchmark Plotter
#
# Usage: ./benchmark/plot.sh <results-dir>
#
# Reads raw/ JSON+CSV data, generates CDF plots (EPS+PDF) and LaTeX tables.
# Output: <results-dir>/plots/

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <results-dir>"
    echo "  e.g.: $0 benchmark/results/full-run-02"
    exit 1
fi

RESULTS_DIR="$1"
PLOTS_DIR="$RESULTS_DIR/plots"

if [[ ! -d "$RESULTS_DIR/raw" ]]; then
    echo "ERROR: $RESULTS_DIR/raw/ not found"
    exit 1
fi

# Check dependencies
for cmd in python3 gnuplot; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found. Install it first."
        exit 1
    fi
done

# Pick EPS-to-PDF converter
if command -v epstopdf &>/dev/null; then
    EPS2PDF="epstopdf"
elif command -v ps2pdf &>/dev/null; then
    EPS2PDF="ps2pdf -dEPSCrop"
else
    echo "ERROR: Neither epstopdf nor ps2pdf found. Install texlive-extra-utils or ghostscript."
    exit 1
fi

# 1. Preprocess: CDFs, tables, gnuplot scripts
echo "=== Preprocessing ==="
python3 "$SCRIPT_DIR/plot_preprocess.py" "$RESULTS_DIR"

# 2. Run gnuplot
echo ""
echo "=== Running gnuplot ==="
cd "$PLOTS_DIR"
for gp in cdf_*.gp; do
    [[ -f "$gp" ]] || continue
    echo "  gnuplot $gp"
    gnuplot "$gp"
done

# 3. Convert EPS to PDF
echo ""
echo "=== Converting EPS -> PDF ==="
for eps in *.eps; do
    [[ -f "$eps" ]] || continue
    pdf="${eps%.eps}.pdf"
    echo "  $EPS2PDF $eps -> $pdf"
    $EPS2PDF "$eps" "$pdf"
done

# 4. Summary
echo ""
echo "=== Output ==="
echo "Directory: $PLOTS_DIR/"
ls -la *.eps *.pdf *.tex 2>/dev/null || echo "  (no output files)"
