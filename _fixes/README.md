# Fixes — working directory

Mini-designs for non-trivial fixes from the pktgate review (`_review/99_REPORT.md`).

## When a fix needs a design here, when it doesn't

**Goes straight from `99_REPORT.md` §Recommendations to commit, no design here:**
- Single-file edits with a clearly-stated "smallest fix" in the report
- Doc-only changes
- Config / CI / build edits where the diff is obvious from the recommendation
- Anything where the "design" decision is already made (e.g. "drop CAP_SYS_ADMIN" — there's nothing to design)

Examples from the report that bypass `_fixes/`: CI shape (#1), L3 match-count guard (#2), `validate_config` wiring (#3), systemd hardening (#5), watchdog (#7), bytes counter helper (#8), CoS implement-or-reject (#9).

**Lands a mini-design here first:**
- Cross-cutting refactors touching ≥3 files in lockstep
- Anything where the "smallest fix" hides real design decisions (key shape, dispatch strategy, migration path)
- Anything that interacts with the generation-swap atomicity contract
- Changes to BPF / userspace struct layouts (the `pkt_meta` shape is load-bearing)
- Anything that breaks the existing test suite by design

Known candidates from the report: #4 IPv6-as-class (`05_ipv6_dispatch.md` planned), #10 L2 single-dispatch lookup (`10_l2_single_dispatch.md` planned).

## Mini-design file shape

Each `NN_<topic>.md` follows the same skeleton:

```
# NN — <topic>

## Motivation
<which P0/P1 from 99_REPORT.md this closes; one paragraph>

## Decision
<the load-bearing structural choice — usually a struct field, dispatch macro, key shape, or boundary contract; one paragraph>

## Alternatives considered
<2-3 paths; for each: cost, risk, why not chosen; terse>

## Implementation steps
<numbered, atomic; each one should leave the tree in a buildable state>

## Acceptance criteria
<concrete tests + observable behaviour that proves the fix works>

## Migration / rollout
<how it lands without breaking the existing test suite or in-flight generations>

## What this does not fix
<honest scope boundary; what's still open after this lands>
```

≤ 300 lines per file. Bias for terse decisions over exhaustive prose.

## Workflow

1. Pick a candidate from `99_REPORT.md` §Recommendations (or roll up several P1/P2s if they share a structural fix).
2. Decide: straight-to-commit or design first? Use the test above.
3. If design: write `NN_<topic>.md` here. Get owner sign-off. Then implement.
4. When the fix lands, mark the corresponding entry in `99_REPORT.md` with `[RESOLVED YYYY-MM-DD, ...]` inline (see the clangd entry under "Code shape / duplication" in §P2 for the format).
5. Don't delete review findings; the inline RESOLVED marker preserves history.

## Index

Currently empty. Will fill as designs land.

| File | Closes | Status |
|------|--------|--------|
| `01_ipv6_as_class.md` | P0-03, P0-04, P1 #8 | drafted 2026-05-11, owner approved |
| `02_l2_single_dispatch.md` | P1 #2, #3, #9 (plus latency win) | drafted 2026-05-11, owner approved |
