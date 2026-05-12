# 08 — Checkpoint after Phase 2 (partial)

Session 2026-05-11. Snapshot for the next reviewer (likely a fresh Claude session) to pick up cleanly.

## What's done

| Phase | File | Subject | Status |
|-------|------|---------|--------|
| 0 — Recon | `01_recon.md` | Project map, scope, hot zones | ✅ |
| 1 — Architecture | `02_architecture.md` | Doc-vs-impl, invariants, perf envelope, scenario coverage | ✅ |
| 2a — Compiler | `03_rule_compiler.md` | `src/compiler/rule_compiler.cpp` | ✅ |
| 2b — Layer 3 BPF | `04_layer3.md` | `bpf/layer3.bpf.c` | ✅ |
| 2c — Layer 2 BPF | `06_layer2.md` | `bpf/layer2.bpf.c` | ✅ |
| 2d — Layer 4 BPF | `05_layer4.md` | `bpf/layer4.bpf.c` | ✅ |
| 2e — Entry BPF | `07_entry.md` | `bpf/entry.bpf.c` | ✅ |
| 2f — TC ingress | `09_tc_ingress.md` | `bpf/tc_ingress.bpf.c` | ✅ |
| 2g — Generation mgr | `10_generation_manager.md` | `src/pipeline/generation_manager.cpp` | ✅ |
| 2h — Loader | `11_bpf_loader.md` | `src/loader/bpf_loader.cpp` | ✅ |
| 2i — Config | `12_config_parser_validator.md` | `src/config/{parser,validator}.cpp` | ✅ |
| 2j — Tool | `13_validate_config_tool.md` | `tools/validate_config.cpp` | ✅ |

**Phase 2 is now closed. All 10 sub-modules reviewed.**

Also: `00_OWNER_NOTES.md` (customer brief context, scope decisions), `TEST_AUDIT.md` (running ledger of "why didn't the tests catch this").

## What's not yet done

### Phase 2 remaining modules

| ID | Subject | Why review |
|----|---------|-----------|
| 2f | `bpf/tc_ingress.bpf.c` | CoS (Phase 1 P0) still has not been confirmed at the TC side beyond Phase 2d's drive-by; also IPv6 DSCP rewrite (Phase 2d) needs verifying |
| 2g | `src/pipeline/generation_manager.cpp` | Rate_state_map lifecycle (Phase 2d P1), rollback shadow-clear (Phase 1 P1), prog_array atomicity (Phase 2b open) |
| 2h | `src/loader/bpf_loader.cpp` | `stats_map` reuse_fd between XDP and TC (Phase 1 open), already-attached-XDP behaviour |
| 2i | `src/config/{parser,validator}.cpp` | Untrusted input boundary, fuzz surface; **first place to fix the L3 wildcard P0 (add a "must have match field" guard)** |
| 2j | `tools/validate_config.cpp` | Does it exercise `compile_rules`? If not, it lies about what it validates |

### After Phase 2

| Phase | Subject |
|-------|---------|
| 3 | Cross-cutting (perf envelope across modules, security, observability, build, supply chain) |
| Tests | Dedicated tests-phase using `TEST_AUDIT.md` as input — for each entry: which test should have caught it, does it exist, is it strengthenable. **High priority given the meta-finding that the test suite has happy-path coverage only and one test (`test_l2_qinq_not_parsed`) cements a defect AS contract.** |
| 4 | Consolidated `99_REPORT.md` with P0/P1/P2 graded, low-hanging fruit, recommendations |
| 5 (post-review) | Save `project` memory note pointing here, so future sessions don't restart from zero (per owner agreement) |

## Findings inventory (as of checkpoint)

### P0 — blocks correct operation under stated envelope

1. **No bps counter** — customer brief explicitly asks; `stats_map` packets-only. `02_architecture.md §7`.
2. **CoS / VLAN PCP rewrite advertised but unimplemented** — `tc_ingress.bpf.c` does IPv4 DSCP only. `02_architecture.md §7`; confirmed from L4 side in `05_layer4.md §6`. Needs final TC-side confirm in Phase 2f.
3. **No fail-safe / watchdog** — customer brief asks; systemd unit has only `Restart=on-failure`. `02_architecture.md §7`.
4. **`dst_ip` / `dst_ip6` accepted by parser, silently becomes catch-all `0.0.0.0/0` LPM entry** — one typo in operator config drops all IPv4. `03_rule_compiler.md §7` + data-plane confirm in `04_layer3.md §7`.
5. **IPv6 ext-header chain ≥ 5 deep bypasses all L4 rules and rate-limit** — security-grade carrier-Gi evasion. `05_layer4.md §7`.
6. **IPv6 ACT_TAG silently corrupts the packet** — TC ingress hard-codes IPv4 byte offsets, no IP-family gate; an IPv6 packet matching a tag rule gets TC/FL nibbles mangled and source-address bytes overwritten by `bpf_l3_csum_replace`. Carrier-Gi packet corruption. `09_tc_ingress.md`.
7. **Wrong-layer match fields silently accepted by validator** — operator writes `dst_port` in an L3 rule (or `src_mac` in an L4 rule); validator passes; compiler silently drops the field; operator's mental model diverges from runtime. Same class as the dst_ip P0 but wider. `12_config_parser_validator.md`.
8. **`validate_config` tool is the pre-deploy gate per docs, but doesn't compile rules** — returns `OK` on configs that will trigger the dst_ip catch-all P0. Worst form of operator-facing safety lie. Plus: the tool isn't in `CMakeLists.txt`, so fresh builds don't produce it. `13_validate_config_tool.md`.
9. **IPv6 as a class — three bugs share one root cause** — no IP-family gate at action sites + shallow ext-header walks that fail-open. Structural fix: `ip_family` byte in `pkt_meta`, mandatory v4/v6 dispatch macro, ext-walker fails-closed at depth bound. `14_cross_cutting.md §1`.
10. **systemd unit over-grants CAP_SYS_ADMIN** — `pktgate.service:43-44`. XDP+TC on kernels ≥5.8 needs only CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON. CAP_SYS_ADMIN is the most attacker-valuable capability on the system. `14_cross_cutting.md §2`.

### P1 — significant debt

6. **`data_meta` XDP→TC contract is driver-dependent and unstated** — `02_architecture.md §7`; confirmed `07_entry.md`.
7. **ARCHITECTURE.md drift** — map count 21 vs 25, L2 lookups 4 vs 5, stat count 30 vs 40; silent feature expansion (TCP flags, IPv6, L2 compound). `02_architecture.md §7`.
8. **Generation rollback doesn't clear demoted shadow** — `02_architecture.md §7`. Phase 2g to confirm.
9. **IPv6 fragment-drop bypassable via Hop-by-Hop → Fragment chain on L3-terminal ALLOW rules** — security-relevant. Promoted to P1 by owner. `04_layer3.md §7`.
10. **L2 compound rules: primary key by lexical order** — usability footgun; two rules sharing primary field collide. `03_rule_compiler.md §7`.
11. **No compile-time enforcement of per-map size limits** (4096/16384/8/64) — overflow detected only at deploy. `03_rule_compiler.md §7`.
12. **Rate-limit divisor uses `libbpf_num_possible_cpus`** — configured 10 Gbps → ~9.77 Mbps on stock `NR_CPUS=8192` kernels. `03_rule_compiler.md §7` (userspace), `05_layer4.md §1` (math validated).
13. **L2 BPF does 5 sequential hash lookups, not 1** — Phase 1's 100-125 ns estimate is correct, contradicting Phase 2a's "1 lookup, latency-neutral" optimistic model. Phase 2a needs this correction propagated. **Pipeline budget violated on VLAN-tagged no-match traffic on a single core.** `06_layer2.md §13`.
14. **L2 compound rules `{src_mac, dst_mac}` silently drop one MAC** — `filter_mask` (`common.h:103-105`) has no SRCMAC/DSTMAC bits. `06_layer2.md §7`.
15. **QinQ (0x88a8) not parsed; `test_l2_qinq_not_parsed` cements the defect AS CONTRACT** — carrier-Gi-critical (S-Tag/C-Tag traffic invisible). The test is the **most damaging variant** of the test-audit meta-finding. `06_layer2.md §6`; `TEST_AUDIT.md`.
16. **`rate_state_map` shared across generations, never GC'd** — rate changes silently don't apply (stable IDs) or leak entries → silent rate-limit disable. `05_layer4.md §7`.
17. **`STAT_TC_NOOP` conflates "driver stripped data_meta" with "no work today"** — diagnostic ambiguity exactly on the Phase 1 P1 §7 driver-dependency invariant. `09_tc_ingress.md`.
18. **`ACT_MIRROR` with `mirror_ifindex == 0` is silently skipped, no counter** — operator-visible silent failure. `09_tc_ingress.md`.
19. **`config-schema.json` is not wired into the validator** — pure documentation, despite CONFIG.md claiming enforcement. Also lacks `minProperties: 1` on L3 rule, so it wouldn't catch the dst_ip P0 even if wired. `12_config_parser_validator.md`.
20. **No file-size guard on config load** — adversary with config-path write access OOMs the daemon via huge JSON. inotify-driven reload reads whatever's on disk. `12_config_parser_validator.md`.
21. **CI runs only `unit` and `integration` ctest labels** — `bpf_dataplane` and the entire `functional_tests/*.py` suite run nowhere automatically. **Every Phase-2 P0 passed CI green.** The single most damning finding. Fix CI shape before fixing more bugs. `14_cross_cutting.md §5`.
22. **`NoNewPrivileges=no`** in `pktgate.service` — anti-hardening for a daemon that should never need to escalate. `14_cross_cutting.md §2`.
23. **No `SystemCallFilter=`, no seccomp** in systemd unit — large attack surface for a privileged daemon. `14_cross_cutting.md §2`.
24. **`libbpf >= 1.1` floor only, no upper bound and no exact pin** — supply-chain reproducibility hazard. Same for `nlohmann_json >= 3.11` and clang. `14_cross_cutting.md §5`.

### P2 — many; consolidated in 99_REPORT later

A non-exhaustive bullet:
- Stat naming inconsistencies (`STAT_PASS_L3` dual-fire on mirror-terminal; `STAT_DROP_L4_NOT_IPV4` misnomer; `STAT_DROP_L2_NO_MATCH` conflates causes; `STAT_DROP_NO_META` overloaded)
- Code duplication between v4/v6 handlers in `layer3.bpf.c` (~70 lines)
- BPF_ANY comment in `layer4.bpf.c:26` misrepresents a non-existent race
- No port wildcard / non-TCP-UDP silently goes to default
- `tcp_flags` on UDP rules silently never matches
- `pkt_meta.redirect_ifindex` is dead across L2/L3/L4
- Entry doesn't pre-compute `eth_proto` / `l3_off` into `pkt_meta` (savings ~3-6 ns/packet across pipeline)
- Endianness rules per-comment, not central table
- BPF benchmarks oversell `PROG_TEST_RUN` numbers; no TRex/IXIA validation
- Tail-call asymmetry in `layer3.bpf.c` matched-rule vs no-rule paths
- Generic catch in compiler swallows rule_id context for L2/L3 errors

## Corrections needed when consolidating

- **Phase 2a (`03_rule_compiler.md`)** Q3 latency claim is wrong (BPF reads all 5 L2 maps). The latency table in `03_rule_compiler.md §Latency impact summary` overstates L2 efficiency.
- **Recon (`01_recon.md`)** "O(n²) collision checks" was wrong — refuted in Phase 2a §Q5. Drop from final report.
- "Filter" → "pktgate" in `00_PLAN.md` (one-time substitution; cosmetic).

## Latency picture (as of checkpoint)

Per-packet cost, common-success path (rule matches, ALLOW, has_next_layer):

| Layer | Cost (ns) | Notes |
|-------|-----------|-------|
| entry | 40-65 | Bulk is structural (adjust_meta + tail_call). |
| L2 (untagged no-match → L3) | 65-100 | 3 lookups: src_mac/dst_mac/ethertype. |
| L2 (VLAN-tagged no-match → L3) | 110-160 | 5 lookups. Carrier-Gi-typical case. |
| L2 (first-lookup match) | 40-60 | Single hit on src_mac. |
| L3 (IPv4, rule-hit, ALLOW, tail-call) | 50-80 | LPM dominates. |
| L3 (IPv6, rule-hit, ALLOW, tail-call) | 55-100 | LPM depth + 16-byte memcpy. |
| L4 (IPv4 TCP, rule-allow) | 45-55 | Hash lookup + small action work. |
| L4 (rate-limit pass/drop) | 80-100 | `ktime_get_ns` cost. |

**Cumulative pipeline numbers:**
- Untagged, rule-match path: ~200-300 ns (entry+L2 match+L3+L4).
- VLAN-tagged no-match through pipeline: ~270-410 ns. **Above the 205 ns/pkt budget at 40 Gbps / 1024 B avg.**
- Worst with adversarial IPv6 ext headers: bypass means L4 rules don't apply, so latency isn't the concern there — correctness is.

**40 Gbps line-rate on a single core is not achievable for VLAN-tagged traffic with the current L2 design.** Multi-core RSS distribution (8+ cores) reaches it on the average path, but the L2 redesign (single-dispatch lookup) is the biggest single saving available — ~50-100 ns/packet.

## Test-audit meta-pattern (recap)

Three damning entries so far:
1. **dst_ip P0** — six different test files plausibly should have caught it; none did. Pure happy-path coverage.
2. **IPv6 ext-header bypasses** (×2: L3 fragment-behind, L4 chain-≥5) — adversarial coverage absent everywhere ext headers are touched.
3. **QinQ `test_l2_qinq_not_parsed`** — test actively asserts the bug AS CONTRACT. False confidence times two.

The tests-phase should treat this not as "add missing tests" but as "the test suite culture rewards happy-path-only checking, and this needs structural intervention". `_.txt` lists TRex/IXIA validation as expected — none of this exists today.

## Pickup instructions for the next session

1. Read this file first (`08_CHECKPOINT.md`).
2. Read `00_OWNER_NOTES.md` for scope and prioritisation rules.
3. Continue with **Phase 2f (`bpf/tc_ingress.bpf.c`)** next — closes the CoS P0 and IPv6 DSCP rewrite story.
4. Then 2g (`src/pipeline/generation_manager.cpp`) — closes rate_state_map P1 and rollback P1 from Phase 1.
5. Then 2h, 2i, 2j in order.
6. After Phase 2 is closed, Phase 3 (cross-cutting), then tests-phase using `TEST_AUDIT.md`.
7. Final consolidation to `99_REPORT.md`. Apply the corrections in "Corrections needed when consolidating" above.
8. Save project memory note per owner agreement once `99_REPORT.md` is committed.
