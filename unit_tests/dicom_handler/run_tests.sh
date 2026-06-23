#!/usr/bin/env bash
#
# DICOM handler detection test.
#
# Generates the corpus + dummy signature DB, then scans every file with the
# given clamscan binary and asserts:
#   - infected/*.dcm   -> exit 1 (Infected found)
#   - clean/*.dcm      -> exit 0 (OK)
#
# Each infected file hides the signature marker from a raw byte scan, so a
# detection proves the DICOM handler extracted and re-scanned the embedded
# object. Usage: run_tests.sh /path/to/clamscan
set -u

CLAMSCAN="${1:-clamscan}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== generating corpus =="
python3 "$HERE/generate_corpus.py" "$WORK" || exit 2

DB="$WORK/test.ndb"
SCAN=("$CLAMSCAN" --quiet --no-summary -d "$DB")
fail=0

scan_one() {
    # $1 = file, $2 = expected exit code (0 clean, 1 infected)
    "${SCAN[@]}" "$1" >/dev/null 2>&1
    local rc=$?
    local base
    base="$(basename "$1")"
    if [ "$rc" -eq "$2" ]; then
        printf '  PASS  %-24s (exit %d)\n' "$base" "$rc"
    else
        printf '  FAIL  %-24s (exit %d, expected %d)\n' "$base" "$rc" "$2"
        fail=1
    fi
}

echo "== infected files (expect detection) =="
for f in "$WORK"/infected/*.dcm; do
    scan_one "$f" 1
done

echo "== clean files (expect OK) =="
for f in "$WORK"/clean/*.dcm; do
    scan_one "$f" 0
done

if [ "$fail" -ne 0 ]; then
    echo "DICOM handler test: FAILED"
    exit 1
fi
echo "DICOM handler test: PASSED"
