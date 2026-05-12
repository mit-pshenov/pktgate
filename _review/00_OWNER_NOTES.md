# Owner notes (post-recon, pre-Phase-1)

Captured 2026-05-11 after the Phase 0 recap. These answers shape Phase 1 scoring of findings.

## Project naming

The project is **pktgate** (not "filter" — that's just the directory name). Earlier review notes that say "filter" mean this project.

## Branch scope

`afxdp` was an experimental side branch. **Out of scope** for this review. Everything else is `main`.

## Answers to recon open questions

### 1. Logical interface names in `target_port`

Production uses **physical** interface names (eth0, eth1, …). If this contract isn't documented in CONFIG.md or ARCHITECTURE.md, that's a **bug — needs a doc fix**.

→ Phase 1 action: grep docs for the contract; if absent, raise as P2 (documentation gap).

### 2. Pinned BPF maps (bpffs) for zero-downtime restart

Out of scope right now. The `lpm_keys_[]` loss concern is a known future problem.

→ Phase 1 action: capture as an explicit TODO in `99_REPORT.md` under "Deferred — known limitations". Don't flag as a finding.

### 3. Scenarios in `scenarios/` and `scenarios_v2/`

These are **speculative gap-analysis templates**, not live configs. Their purpose is to surface what functionality is missing — they're a coverage map, not a test fixture.

→ Phase 1 action: cross-reference scenarios against actual implementation in Phase 1/2. For each scenario, note: fully covered / partially covered / not covered. This becomes input to a "what's left to build" section in the final report.

### 4. Rate-limit accuracy

Current XDP-side rate-limiter is best-effort by design. Migration to `tc-htb` / EDT is **planned but not started**.

→ Phase 1 action: verify the best-effort claim is documented in CONFIG.md or operator-facing docs. If not, P2 doc gap. The planned migration goes into the deferred-TODO list.

### 5. IPv6 fragment handling — RESOLVED during this exchange

Initially flagged as "possibly unfinished," but a grep across docs and code shows it **is by design**:
- `ARCHITECTURE.md:130` documents the drop logic with the `frag_off & 0x1FFF` check
- `CONFIG.md:165–166` explicitly states fragments are dropped at L3
- Three dedicated counters: `STAT_DROP_L3_FRAGMENT`, `STAT_DROP_L3_V6_FRAGMENT`, `STAT_DROP_L4_V6_FRAGMENT`
- Phase 16 was explicitly the IPv6 stats / fragment audit

Intentional hardening (evasion mitigation). No reassembly path planned.

→ Phase 1 action: confirm the implementation matches the doc claims. No finding expected.

## Meta-context for prioritisation

### A. Use case

Project built for a specific customer's task — but not with the means they originally wanted. For the owner, it doubles as:
1. An exercise in AI-assisted development
2. An exploration of what's possible with eBPF

→ Phase 1 implication: **there are no hard production requirements**. Don't grade against an enterprise checklist (audit logs, multi-tenant config isolation, etc. — not required). Grade against: "does it do what ARCHITECTURE says it does, correctly?"

### B. Performance

No hard pps/latency targets — but `_.txt` (the customer brief) does state the operating scenario: **line-rate L2 traffic filtering on 40 Gbps GGSN–Gi interfaces, no noticeable latency, no throughput impact**. So while there's no formal SLA in the repo, the implicit target is line-rate at 40 Gbps.

Performance measurements live in:
- `ARCHITECTURE.md §"BPF data plane benchmarks"` (line 831) — ns/pkt, Mpps per path, via BPF_PROG_TEST_RUN, 1M packets
- `README.md` line 142 — same table reproduced
- `tests/bench_compile.cpp` — control-plane compile benchmark (manual run)

→ Phase 1 framing: "here are bottlenecks observed against the implicit 40 Gbps line-rate target," not "here is what doesn't meet target X."

Note: `_.txt` says the customer wanted something different from eBPF (mentioned in part A); the XDP approach is the owner's choice for experimenting. So divergence-from-customer-wish is also out of scope as a finding.

### C. Author's suspicions

None volunteered — owner explicitly wants the review to discover issues independently rather than be steered. "Wander and find" is the directive.

### D. Backlog beyond ARCHITECTURE / scenarios

Nothing tracked outside `ARCHITECTURE.md` and `scenarios*/`. So the gap analysis = scenarios that aren't covered by code/tests. Anything not in those two places is genuinely new ground.

## Working agreement update

- Reference to "filter" in earlier files (`00_PLAN.md`, `01_recon.md`) should be read as "pktgate". Will fix on the final pass before consolidation.
- Deferred TODOs (pinned maps, EDT migration, fragment-reassembly-if-ever-needed) collect in `99_REPORT.md` under "Out of scope but known".
