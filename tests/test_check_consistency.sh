#!/usr/bin/env bash
# Verdict-consistency test:
#
#   pktgate_ctl --check  vs  validate_config
#
# Both tools claim to run the same parse → validate → compile pipeline
# offline. They MUST agree on every fixture, otherwise operators have two
# pre-deploy gates that disagree — exactly the "tool lies" failure mode
# from _review/TEST_AUDIT.md §"Phase 2j P0".
#
# Contract:
#   tests/fixtures/validate_config_good/*.json — both tools exit 0
#   tests/fixtures/validate_config_bad/*.json  — both tools exit non-zero
#   any disagreement = test failure with details.
#
# CMake passes the build-dir + source-dir as arguments so the script is
# directory-agnostic.
set -euo pipefail

BUILD_DIR="${1:-build}"
SRC_DIR="${2:-.}"

PKTGATE="$BUILD_DIR/pktgate_ctl"
VC="$BUILD_DIR/validate_config"

for bin in "$PKTGATE" "$VC"; do
    [ -x "$bin" ] || { echo "FAIL: $bin not built"; exit 1; }
done

run_check() {
    "$PKTGATE" --check "$1" >/dev/null 2>&1
}
run_vc() {
    "$VC" "$1" >/dev/null 2>&1
}

violations=0
checked=0

for f in "$SRC_DIR"/tests/fixtures/validate_config_good/*.json; do
    [ -f "$f" ] || continue
    checked=$((checked + 1))
    pktgate_rc=0; run_check "$f" || pktgate_rc=$?
    vc_rc=0;      run_vc    "$f" || vc_rc=$?
    if [ "$pktgate_rc" -ne 0 ] || [ "$vc_rc" -ne 0 ]; then
        printf 'DISAGREE good/%s: pktgate_ctl=%d, validate_config=%d (both must be 0)\n' \
            "$(basename "$f")" "$pktgate_rc" "$vc_rc"
        violations=$((violations + 1))
    fi
done

for f in "$SRC_DIR"/tests/fixtures/validate_config_bad/*.json; do
    [ -f "$f" ] || continue
    checked=$((checked + 1))
    pktgate_rc=0; run_check "$f" || pktgate_rc=$?
    vc_rc=0;      run_vc    "$f" || vc_rc=$?
    if [ "$pktgate_rc" -eq 0 ] || [ "$vc_rc" -eq 0 ]; then
        printf 'DISAGREE bad/%s: pktgate_ctl=%d, validate_config=%d (both must be non-zero)\n' \
            "$(basename "$f")" "$pktgate_rc" "$vc_rc"
        violations=$((violations + 1))
    fi
done

if [ "$checked" -lt 2 ]; then
    echo "FAIL: only checked $checked fixtures (expected several)"
    exit 1
fi

if [ "$violations" -gt 0 ]; then
    echo
    echo "FAIL: $violations consistency violation(s) across $checked fixtures."
    echo "If a fixture is intentionally only-rejected-by-one-tool, move it"
    echo "out of validate_config_{good,bad} into a per-tool corpus."
    exit 1
fi

echo "OK: $checked fixtures, both tools agree."
