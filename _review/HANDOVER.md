# Handover — pktgate

Last touched: 2026-06-10 (doc refresh; code state as of 2026-05-13).
Project on pause; main is shippable. Start here.

## 30-second status

10/10 P0, most P1, 1 NEW P0-class, LICENSE — all landed on main. Unit +
integration + BPF data-plane tests are green in CI. Functional tests are
104/104 green (full suite confirmed after every fix in this round). The
`continue-on-error` shield has been removed from the functional CI job.

The `_review/99_REPORT.md` is the canonical map. Closed findings carry
inline `[RESOLVED ...]` markers — treat those markers as the
authoritative status, not the counts in this file. One is `[PARTIAL]` —
see §performance. One emergent finding is OPEN — see §What's open.

## Post-handover round (2026-05-13)

Five commits landed after this handover was first written:

- `5642d3e` — **dst_ip / dst_ip6 are now REAL match fields** (upgrade of
  P0-01 from "validator rejection" to implementation): parallel
  `subnet_rules_dst_{0,1}` + `subnet6_rules_dst_{0,1}` LPM maps, lookup
  order src → dst → VRF → default. src+dst combo in one rule is rejected
  (composite-key L3 deferred).
- `a8aba11` — skeleton-map identity guardrails (runtime + source).
  **Catch worth knowing:** `reuse_xdp_maps()` must reuse new maps from
  the *entry* skeleton — without this, layer3 silently loads its own
  private map copies and population writes to a different map than the
  program reads from.
- `184ee76` — dst_ip combination coverage: L4 integration + LPM
  specificity + reload + property tests.
- `6f367b9` — fix `parse_config_string` crash on JSON numeric overflow.
- `baf0312` — fuzz: data-plane harness against the XDP entry program.

## Where everything lives

- **Code review artefacts:** `_review/` — 16 per-phase files, `TEST_AUDIT.md`,
  `99_REPORT.md` (executive summary + P0/P1/P2 catalogue with inline markers),
  this file (`HANDOVER.md`).
- **Mini-designs for refactor-class fixes:** `_fixes/` —
  `01_ipv6_as_class.md` (delivered in commit `5c3b4af`), `02_l2_single_dispatch.md`
  (delivered in `e1f2e98` with a perf-win caveat).
- **Customer brief:** `_.txt` at repo root.
- **Owner notes:** `_review/00_OWNER_NOTES.md` (scope, deferred items).
- **CONFIG / ARCHITECTURE docs:** `CONFIG.md`, `ARCHITECTURE.md` (kept in sync
  through this round of fixes).
- **CI:** `.github/workflows/ci.yml` — four jobs: `build-and-test` (unit +
  integration matrix), `bpf-dataplane` (sudo), `functional` (continue-on-error),
  `coverage`.

## Build and run

```bash
# Dev box needs clang-16..clang-20 + libbpf>=1.1 + nlohmann_json>=3.11 + bpftool.
# If you don't have plain `clang` symlink, CMake also accepts versioned names.
cmake -B build
cmake --build build -j$(nproc)

# Tests
ctest --test-dir build -L unit              # 16/16 fast
ctest --test-dir build -L integration       # 4/4 fast
sudo ctest --test-dir build -L bpf          # 1 test (65 internal cases)
sudo bash functional_tests/run.sh           # 104 pytest cases, ~6 min, 2 flaky

# Pre-deploy gate
build/validate_config <file.json>           # parse + validate + compile
```

If `cmake -B build` fails on `clang-16 not found`, blow away `build/` and
re-run with `CC=clang-19 CXX=clang++-19` (or whichever you have).

## What's open

**OPEN emergent finding (2026-05-13): rate-limit reload drops everything.**
Configure `rate-limit bandwidth=100Kbps`, send 500-packet burst (TCP/8888),
~41 pass (partial drop, expected). `reload_config({bandwidth: "1Mbps"})`,
wait 1s for inotify, send another burst — **captured = 0**. The post-reload
generation drops the entire flow the pre-reload generation passed fine.
P1#7-shaped: `rate_state_map` is the only non-double-buffered map
(`bpf/maps.h:217-224`, single PERCPU_HASH, not generation-keyed); commit
`a0d2f8e` GC'd stale entries but did NOT add an on-reload clean. Where to
start: `functional_tests/test_zz_rate_limit.py::test_reload_changes_effective_rate`
(xfail strict=False, reproduces deterministically on the dev box); check
whether `src/pipeline/generation_manager.cpp` reload path ever calls
`bpf_map_delete_elem` against `rate_state_map` — if not, that's the smoking
gun for the stale-bucket hypothesis. If future work touches `rate_state_map`,
`GenerationManager`, or the inotify reload path, run
`sudo bash functional_tests/run.sh test_zz_rate_limit.py` — xfail flipping
to XPASS is the green light to remove the marker.

Tracked entries in `99_REPORT.md` that DIDN'T get `[RESOLVED]`:

**P1 (priority):**
- **#5 generation rollback is broken/dead** — only fires under test mocks. Either
  pre-populate `prog_array_0`/`default_action_0` or delete `rollback()`.
- **#20 full-packet mirror has no truncation / PII boundary** — Gi-link carries
  subscriber HTTP, IMSI/IMEI in VoLTE SIP, unencrypted DNS. **Architectural
  fix needed** (AF_XDP socket or userspace mirror daemon) — `bpf_clone_redirect`
  in TC has no native truncation and `bpf_skb_change_tail` mutates the
  original packet. Defer to a dedicated design round.
- **#21 no per-rule observability** — Prometheus exposes global counters only;
  per-rule pps/bps still aggregated by (layer, reason). Customer brief asked
  for per-rule. Needs cardinality design (per-rule labels can blow up Prom
  ingestion on configs with thousands of rules).
- **#21 no per-rule observability** — Prometheus exposes global counters only.
  Per-rule pps/bps still aggregated by (layer, reason). The customer brief
  asked for per-rule.
- **#22 ARCHITECTURE.md drift** — map count, L2 lookup count, stat count.
  Partially updated in this round; do another sweep.

**P2:** large catalogue in `99_REPORT.md` §"P2"; nothing operationally severe.

**Tasks created during this round:**
- `#13` functional test isolation — RESOLVED 2026-05-12. Capture helpers
  pinned to ingress direction; full suite 104/104 over three runs.

## Performance (P1#2)

`_fixes/02_l2_single_dispatch.md` shipped the structural collapse from
5 per-field L2 maps to 1 composite. P1#3 and P1#9 closed. But the
latency win the design predicted (≥30% on no-match path) did NOT
materialise: `bench_l2_no_match_fallthrough_1M` measures ~590 ns/pkt
post-refactor vs ~294 ns/pkt pre-refactor.

The bench runs `layer2_prog` standalone; the iterator does
`MAX_L2_MASKS=8` ARRAY lookups (each cheap), but for active masks it
also runs `build_l2_key()` (memset + conditional memcpy chains) and a
HASH lookup. The verifier doesn't seem to optimise the unrolled loop
as well as the design assumed.

Suggested investigation path:
1. `bpftool prog dump xlated/jited id <layer2_prog_id>` to see how the
   verifier-emitted instruction stream looks.
2. Compare to a hand-rolled version with `bpf_loop` instead of
   `#pragma unroll` (kernel ≥5.17).
3. Consider caching `build_l2_key()` output across iterations — only the
   `filter_mask` changes; everything else stays.
4. If the verifier insists on re-deriving fields each iteration, fall back
   to per-mask sub-maps (1 ARRAY → N HASH lookups via direct keys instead
   of one composite-key HASH).

Plan-B from the original mini-design ("keep 5 maps, just fix
filter_mask + primary selection") is on the table if option (3) or (4)
doesn't help.

## Functional flake (#13) — RESOLVED 2026-05-12

**Root cause.** Capture helpers in `conftest.py` used `tcpdump -i <iface>
'<bpf>'` without pinning direction, so kernel-emitted egress from
`ns_filter` (IPv6 NS for DAD, RS, MLD reports) was being captured on the
filter veth and treated as "the packet under test made it through XDP".
Broad filters like `'ip6'` made this far more likely; narrower ones like
`'tcp port 80'` could still hit `not got_packets` flakes intermittently.

**Fix.** Added `-Q in` to every capture command (`capture_on_filter`,
`capture_count`, `capture_tos` in `conftest.py`, and `capture_on_mirror`
in `test_zz_mirror_redirect.py`). This restricts the capture to ingress
frames — the only direction relevant to "did XDP forward this?". Frames
the kernel originates inside the filter namespace are egress and are now
invisible to the tests.

**Verification.** Three back-to-back `sudo bash functional_tests/run.sh`
runs of the full suite: 104/104 green each time.

**Diagnostic that pinpointed it.** Repeating each scenario 5× with
`tcpdump -e -vv` showed the captures were `ICMP6, router solicitation`
from the filter-side link-local fe80::… address, not the packet sent by
scapy. Both fragment-TCP and fragment-UDP packets were correctly dropped
by BPF; the test's "got something" boolean was responding to ND/RS
background noise.

## Memory pointers

User-private agent memory for this project was consolidated into the
repo on 2026-06-10: durable context now lives in `CLAUDE.md` at the
repo root (use case, testing discipline, sibling project), and review
state lives in this file. The `~/.claude/projects/-home-user-filter/memory/`
slot was emptied on purpose.

## Recent commits to context

```
baf0312 fuzz: data-plane harness against the XDP entry program
6f367b9 fix: parse_config_string crash on JSON numeric overflow
184ee76 dst_ip combination coverage: L4 integration + LPM specificity + reload + property
a8aba11 Skeleton-map identity guardrails (runtime + source)
5642d3e L3: real dst_ip / dst_ip6 support with parallel LPM maps
1a6fef4 functional: pktgate fixture to module scope (#13 partial)
4e77d2b Refresh ci.yml functional-job comment after #10/#11/#4 (#12)
e1f2e98 L2 single-dispatch refactor: composite key + active masks (#10 / P1#2/#3/#9)
b4d5077 Reject CoS in validator until VLAN PCP rewrite lands (P0-09)
4379c91 Add per-stat byte counters and bps Prometheus series (P0-08)
f50f5a5 Add Type=notify + WatchdogSec, document fail-safe contract (P0-07)
5548047 Systemd hardening and supply-chain pins (P0-06, P1#16/#17/#18, LICENSE)
9659cee Reject wrong-layer match fields in validator (P0-05, P1#11)
5c3b4af IPv6 as a class: family stamp + fail-closed walkers (P0-03/P0-04/P1#8)
e6fe7d8 Wire validate_config into build, compile, CI fixtures (P0-02)
0624e31 Reject empty L3 match and dst_ip/dst_ip6 (P0-01)
5625f1a Apply default_behavior at L2 on no-match (new P0-class)
7d265e6 Wire bpf-dataplane and functional CI jobs (P0-10)
```

## Anti-checklist (don't do these)

- Don't touch the generation-swap contract without reading
  `10_generation_manager.md` — it's the load-bearing atomicity in the data
  plane.
- `dst_ip` / `dst_ip6` are real match fields since `5642d3e` (parallel
  destination LPM maps). The historical hazard — compiler silently
  expanding them into `0.0.0.0/0` — is closed; what remains rejected is
  src+dst combo in a single rule (composite-key L3 deferred).
- Don't add new capture helpers without `-Q in` (or an explicit
  ingress-only equivalent). The `ns_filter` kernel emits a steady
  drip of ND/RS/MLD traffic that any direction-agnostic capture will
  occasionally see; that was the entire #13 flake.
- Don't run `scripts/install.sh` without reading it — it does real
  systemd enable / iface modification.

## When in doubt

1. Read `_review/99_REPORT.md`'s executive summary.
2. Grep the report for the area you're touching — most P1s and P2s have
   one-line summaries that point to phase files for deep reads.
3. The mini-designs in `_fixes/` document the WHY for non-trivial moves.
4. If a test is failing, run it in isolation first
   (`sudo bash functional_tests/run.sh path::Class::test`) before
   assuming code regression.
