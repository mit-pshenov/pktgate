#!/usr/bin/env bash
# Fails when a test file contains a "BUG", "buggy", "known:" or "quirk"
# comment in a 5-line neighbourhood of an assertion, without a tracker
# reference (TODO(name), ARCHITECTURE.md link, an issue/PR number, or a
# pytest xfail/skip marker).
#
# Motivation: prevent tests that lock in a defect as the desired contract.
# See _review/TEST_AUDIT.md §"Phase 2i" / §"Phase 2c P1" for the two
# instances that triggered this guardrail (qinq_not_parsed, ethertype hex).
#
# Usage:
#   scripts/check_test_as_contract.sh [repo-root]
# Exits 0 on clean, 1 on violation, prints offending file:line.

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT"

# Word-boundary aware to avoid false positives like "debug" or "unknown".
MARKER='(^|[^A-Za-z])(BUG|buggy|known:|quirk)([^A-Za-z]|$)'
ANCHOR='(assert\(|EXPECT_|ASSERT_|pytest\.fail|self\.assert|self\.fail)'
TRACKER='(TODO\(|ARCHITECTURE\.md|tracker:|xfail|skip\(|#[0-9]+|see issue|see PR)'

violations=0
while IFS= read -r f; do
    awk -v file="$f" -v marker="$MARKER" -v anchor="$ANCHOR" -v tracker="$TRACKER" '
        BEGIN { WIN = 5; viol = 0 }
        { lines[NR] = $0 }
        END {
            for (i = 1; i <= NR; i++) {
                if (lines[i] ~ marker) {
                    lo = i - WIN; if (lo < 1)  lo = 1
                    hi = i + WIN; if (hi > NR) hi = NR
                    has_anchor = 0; has_tracker = 0
                    for (j = lo; j <= hi; j++) {
                        if (lines[j] ~ anchor)  has_anchor  = 1
                        if (lines[j] ~ tracker) has_tracker = 1
                    }
                    if (has_anchor && !has_tracker) {
                        printf "%s:%d: %s\n", file, i, lines[i]
                        viol++
                    }
                }
            }
            exit (viol > 0) ? 1 : 0
        }' "$f" || violations=$((violations + 1))
done < <(find tests functional_tests -type f \
            \( -name '*.cpp' -o -name '*.hpp' -o -name '*.py' \) 2>/dev/null)

if [ "$violations" -gt 0 ]; then
    cat <<'EOF'

ERROR: test-as-contract anti-pattern detected (see lines above).

A test contains a "BUG", "buggy", "known:" or "quirk" comment near an
assertion without a tracker reference. Either:

  * Rewrite the assertion to expect correct behaviour, OR
  * Add one of these on a neighbouring line:
      - TODO(name-or-id)
      - link to ARCHITECTURE.md §"Known limitations"
      - pytest xfail() / skip() marker with reason
      - "tracker:" note
      - an issue/PR number (#NNN)

Background: _review/TEST_AUDIT.md §"Phase 2i" / §"Phase 2c P1".
EOF
    exit 1
fi

echo "OK: no test-as-contract anti-pattern detected."
