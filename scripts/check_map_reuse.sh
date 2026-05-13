#!/usr/bin/env bash
# Fails when bpf/maps.h declares a SEC(".maps") that isn't reused into
# every XDP layer skeleton via REUSE_MAP() in src/loader/bpf_loader.cpp.
#
# Why: without reuse, each layer skeleton creates its own kernel-level map
# object with the same name, populate writes to entry's copy, the data
# plane reads from layer3's copy — silent divergence. That was exactly the
# dst_ip bug during development (commit 5642d3e). Runtime guard:
# tests/bpf/test_skeleton_invariants.cpp. Source-time guard: this script.
#
# TC-only maps live in a separate REUSE_TC_MAP block (currently stats_map
# alone) and are exempt — list them in TC_ONLY below if you add more.
#
# Usage:
#   scripts/check_map_reuse.sh [repo-root]
# Exits 0 on clean, 1 on violation.

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT"

MAPS_H="bpf/maps.h"
LOADER="src/loader/bpf_loader.cpp"

[ -f "$MAPS_H" ] || { echo "FAIL: $MAPS_H not found"; exit 1; }
[ -f "$LOADER" ] || { echo "FAIL: $LOADER not found"; exit 1; }

# Maps that are NOT shared across XDP layers (none right now — kept as
# a future-proof allow-list so the script is the single source of truth).
TC_ONLY=()

# Extract all map names declared as SEC(".maps") in maps.h.
declared=$(grep -E '^\}[[:space:]]+[a-zA-Z_0-9]+[[:space:]]+SEC\("\.maps"\)' "$MAPS_H" \
           | sed -E 's/^\}[[:space:]]+([a-zA-Z_0-9]+).*/\1/')

# Extract all REUSE_MAP() arguments from the XDP reuse lambda in bpf_loader.cpp.
# Stops at REUSE_TC_MAP block so we don't conflate the two.
reused=$(awk '
            /REUSE_TC_MAP/{exit}
            /#[[:space:]]*define[[:space:]]+REUSE_MAP/{next}
            /REUSE_MAP\(/{
                gsub(/.*REUSE_MAP\(/, "");
                gsub(/\).*/, "");
                print
            }' "$LOADER" | sort -u)

violations=0
for m in $declared; do
    skip=0
    for tc in "${TC_ONLY[@]}"; do
        if [ "$m" = "$tc" ]; then skip=1; break; fi
    done
    [ "$skip" -eq 1 ] && continue

    if ! grep -qx "$m" <<<"$reused"; then
        echo "FAIL: $m declared in $MAPS_H but never REUSE_MAP'd in $LOADER"
        violations=$((violations + 1))
    fi
done

# Reverse check: REUSE_MAP for a name no longer in maps.h
for r in $reused; do
    if ! grep -qE "\b$r\b" "$MAPS_H"; then
        echo "FAIL: $LOADER reuses $r but it is not in $MAPS_H"
        violations=$((violations + 1))
    fi
done

if [ "$violations" -gt 0 ]; then
    cat <<'EOF'

A map declared in bpf/maps.h must be wired into the XDP reuse list in
src/loader/bpf_loader.cpp::reuse_xdp_maps(). Otherwise each layer
skeleton creates its own kernel-level map with the same name and
populate/lookup silently target different objects. See
tests/bpf/test_skeleton_invariants.cpp for the runtime symptom.
EOF
    exit 1
fi

echo "OK: bpf/maps.h ↔ bpf_loader.cpp REUSE_MAP list consistent."
