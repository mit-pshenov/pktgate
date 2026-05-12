# 02 — Architecture review (Phase 1)

Critical audit of pktgate's architecture **as designed and documented** vs (a) implementation, (b) the customer brief's implicit envelope (40 Gbps L2 line-rate, no noticeable latency on GGSN–Gi), and (c) what a competent reviewer expects from this design space.

Source documents read in full: `ARCHITECTURE.md`, `CONFIG.md`, `TEST_PLAN.md`, `README.md`, `_.txt`, `_review/00_PLAN.md`, `_review/00_OWNER_NOTES.md`, `_review/01_recon.md`. Sampled code: `bpf/common.h`, `bpf/maps.h`, `bpf/entry.bpf.c`, `bpf/layer2.bpf.c`, `bpf/layer3.bpf.c`, `bpf/layer4.bpf.c` (entry only), `bpf/tc_ingress.bpf.c`, `src/main.cpp`, `src/pipeline/generation_manager.cpp` (selected), `src/compiler/rule_compiler.cpp` (L2 portion), `src/config/config_validator.cpp` (port portion), `systemd/pktgate.service`.

---

## 1. Architecture as stated

pktgate is an XDP+TC hybrid packet filter driven by a JSON config. The data plane is five BPF programs:

- **entry XDP** reads the active generation from `gen_config`, allocates per-packet metadata in the XDP `data_meta` area, and tail-calls into Layer 2 via the per-generation `prog_array`.
- **L2 XDP** does five hash lookups in fixed order (src_mac → dst_mac → ethertype → vlan_id → pcp), first match wins; supports compound rules (one primary lookup + secondary checks via a filter mask).
- **L3 XDP** parses IP, drops non-first fragments (IPv4) and Fragment-Header packets (IPv6), does an LPM lookup on source address (separate v4/v6 tries), falls back to a VRF-by-ifindex hash.
- **L4 XDP** matches `(protocol, dst_port)` with optional TCP-flag mask, executes terminal actions (allow/drop/rate-limit) and "tag" by stamping DSCP into `pkt_meta` for TC to apply.
- **TC ingress** consumes `pkt_meta.action_flags` and performs the skb-only deferred work: `bpf_clone_redirect` for mirror, DSCP rewrite + IP checksum fixup for tag.

Configuration is double-buffered. Two parallel sets of maps (generations 0/1) and two `prog_array`s coexist; the entry program branches on a single `gen_config[0]` value. Commit is a single atomic map update followed by a 100 ms `usleep` drain. Rollback is the reverse update. LPM tries can't be iterated by BPF, so `GenerationManager` keeps an in-memory list of inserted LPM keys per generation for shadow-clear.

The control plane is C++23: `ConfigParser` → `ConfigValidator` → `ObjectCompiler` (object groups → byte-level keys) → `RuleCompiler` (pipeline → BPF map entries, port-group expansion, key-collision detection) → `GenerationManager.prepare()/commit()` → `PipelineBuilder` orchestrates. Hot reload is via inotify on the config directory (atomic-rename safe) plus SIGHUP, with 150 ms debounce; reload failures don't perturb the active generation. SIGUSR1 dumps `stats_map` (per-CPU array, 40 enum slots).

Architecture also lists 21 BPF maps, claims O(1) per-packet hash lookups, documents an LPM-iteration workaround, and explicitly states the XDP→TC hand-off uses `data_meta` rather than a per-CPU side map.

---

## 2. As stated vs. as implemented

### Implemented-but-undeclared (silent expansion)

- **Five L2 lookup types, not four.** `ARCHITECTURE.md §3.2` and §4 list four L2 maps (`l2_src_mac`, `l2_dst_mac`, `l2_ethertype`, `l2_vlan`). Code in `bpf/maps.h:98-112` adds `l2_pcp_0/1`, and `bpf/layer2.bpf.c:187-196` performs the PCP lookup as the 5th step. CONFIG.md exposes `pcp` as a match field. The arch maps table is stale.
- **L2 compound rules with secondary filter mask.** Architecture §3.2 implies "first match wins" on a single field. The actual model (`bpf/common.h:101-118` `filter_mask`, `bpf/layer2.bpf.c:18-35` `l2_filters_match`, `src/compiler/rule_compiler.cpp:130-202` primary-selection logic) compiles AND-of-fields into a primary lookup + per-rule secondary checks. CONFIG.md documents this at length; ARCHITECTURE.md doesn't mention it.
- **TCP flags filter.** `struct l4_rule.tcp_flags_set / tcp_flags_unset` (`bpf/common.h:151-160`) and `bpf/layer4.bpf.c:191-197` are not mentioned anywhere in ARCHITECTURE.md. CONFIG.md §"TCP Flags" documents it. Layer-4 description in `§3.4` of the arch doc still lists only port matching and DSCP/CoS.
- **IPv6 dual-stack at L3 and L4.** Arch §3.3 and the maps table describe only IPv4 LPM, `lpm_v4_key`, IPv4 fragment drop. Code has `subnet6_rules_0/1` LPM tries (`bpf/maps.h:134-148`), `lpm_v6_key` (`bpf/common.h:65-74`), `bpf/layer3.bpf.c:188-235` IPv6 path with Fragment-Header detection (nexthdr 44), bounded extension-header skip loop in `layer4.bpf.c:137-179`. Architecture has only one passing mention in the phase table (§11, phase 13). Maps table omits the v6 maps. Stat enum has dedicated `STAT_PASS_L3_V6` etc., implemented and read, but the maps table doesn't capture v6 maps either.
- **Default-action maps.** `default_action_0/1` (`bpf/maps.h:184-196`) are listed in the table but not described in §3 (Data Plane) or §5 (generation swap algorithm). The doc treats default behaviour as a thing the validator checks, never as a runtime map read.
- **Prometheus exporter.** `src/metrics/prometheus_exporter.hpp` (293 LOC per recon) is implemented (verified by `--metrics-port` flag in `src/main.cpp:128-140,209-219`) and tested. `ARCHITECTURE.md §6` tree listing omits the `metrics/` directory entirely. README.md and the customer brief both list Prometheus, so it's user-visible.
- **`tools/validate_config`.** Referenced from CONFIG.md (`./build/validate_config config.json`) and present at `tools/validate_config.cpp`, but ARCHITECTURE.md §6 file tree doesn't list `tools/`.
- **`config-schema.json`.** Listed at repo root, referenced from CONFIG.md as the schema, never mentioned in ARCHITECTURE.md.
- **TC ingress maps duplication.** `tc_ingress.bpf.c:26-31` redeclares `stats_map` locally rather than including `maps.h`. The architecture doesn't discuss whether TC and XDP share `stats_map` by name resolution at load time or by symbolic reuse. This is a real loader contract (the loader must `bpf_map__reuse_fd` the TC program's `stats_map` to the XDP one) and it is unstated; if it's not done correctly the per-CPU counters split across two maps and stats become unreadable. (Defer to Phase 2 to confirm `bpf_loader.cpp` does this.)
- **Stat counter count drift.** Architecture says "40 per-CPU counters" in §4 (consistent with `STAT__MAX=40`) but §8 also says "30 per-CPU counters" in the phase-8 row of §11. The enum has been grown across phases without one of the tallies being updated.
- **Total map count.** Arch §4 declares "21 maps (2 shared + 9×2 double-buffered + 1 rate_state)". `grep "SEC(\".maps\")" bpf/maps.h` counts **25** maps (plus the TC duplicate of `stats_map`). The doc undercounts by 4: the missing items are `subnet6_rules_0/1`, `l2_pcp_0/1`, `default_action_0/1`, with stats counted as shared but mis-grouped.

### Declared-but-missing (or thin)

- **`ARCHITECTURE.md §3.5` action table** lists CoS via `bpf_skb_set_tunnel_key` or VLAN PCP rewrite. CONFIG.md exposes `cos` in `tag` `action_params`. `bpf/tc_ingress.bpf.c` implements **only DSCP rewrite (the IPv4 TOS path)** — no CoS, no VLAN PCP rewrite, no IPv6 traffic-class rewrite. Arch §10 Q6 even concedes "VLAN PCP (CoS) rewrite is not implemented", but §3.5 and CONFIG.md still advertise it as a working action parameter. Either the action param must be rejected by the validator or the doc/CONFIG must say "cos accepted, not enforced".
- **`STAT_PASS_L3` double-increment.** Architecture says each return path increments exactly one stat. In `bpf/layer3.bpf.c` `handle_l3_action`, the ALLOW path increments `STAT_PASS_L3` (line 110) only when there's no next_layer. But the `get_default_action` path also increments `STAT_PASS_L3` (line 36). For an IPv4 packet that hits a subnet rule with `has_next_layer=1` → tail call to L4 → L4 passes, the packet is counted in `STAT_PASS_L4`, not L3 — fine. But if the rule action is MIRROR with `has_next_layer=0`, both `STAT_MIRROR` and `STAT_PASS_L3` are incremented — that's an architectural double-count the doc doesn't acknowledge. (Minor; Phase 2 to confirm intent.)
- **L3 destination-IP match.** CONFIG.md `dst_ip` and `dst_ip6` are documented match fields. `bpf/layer3.bpf.c` performs LPM lookup on `iph->saddr` / `ip6h->saddr` only — no `dst_ip` lookup is visible in the code I sampled. Either the validator/compiler rejects `dst_ip`, or there's an unimplemented match field exposed by CONFIG.md. (`grep dst_ip src/compiler/` in Phase 2 will resolve; this is a likely doc-vs-implementation lie.) ❗ flagged as MUST-RESOLVE in §8.
- **VRF "any-direction" matching.** Arch §3.3 says VRF can be read from `skb->mark or ifindex`. Implementation only checks `ctx->ingress_ifindex`. The `or skb->mark` path doesn't exist in XDP (no skb). This is a Russian-language statement in the arch doc that doesn't match reality.
- **Generation swap "rcu_barrier()"** is mentioned in §5 step 5 as an alternative to `usleep(100ms)`. Implementation uses unconditional `usleep(100000)` (`generation_manager.cpp:306`). The doc presents both as options but never says which is in force; an operator reading it can't tell that a fixed 100 ms is the only path.
- **`bpf_map_get_next_key` workaround on rollback.** Arch §10 Q9 covers the LPM iteration limit for shadow-clear; it does not cover what happens to the in-memory `lpm_keys_[shadow]` list on a `rollback()`. Reading `generation_manager.cpp:310-322`, rollback only flips `gen_config[0]` — it does **not** clear the now-shadow generation's LPM tracking list nor its maps. The next `prepare()` will call `clear_shadow_maps()` and iterate the list, but if rollback happens after a partial `prepare()` (which is the only sensible reason to call rollback), the list is whatever was inserted up to the failure. The invariant "shadow is empty on entry to prepare" is unstated, and the rollback path doesn't restore it.

### Where there's no gap

- The "atomic single-write swap on `gen_config[0]`" claim matches the BPF code exactly (`entry.bpf.c:18-52`).
- The XDP→TC hand-off via `data_meta` is implemented as described (`entry.bpf.c:29-46`, `layer3.bpf.c:86-91` for mirror flag, `tc_ingress.bpf.c:42-66` for read-back); the variable-cache-before-helper trick is even documented in TC code comments.
- The inotify-on-directory + 150 ms debounce + non-empty-file check pattern is implemented as documented (`src/main.cpp:65-93,247-260`).
- IPv4-fragment drop, IPv6-Fragment-Header drop, IPv6-extension-header bounded skip: code matches docs (`layer3.bpf.c:198-202,249-254`; `layer4.bpf.c:152-176`). Owner notes (§5) already confirmed this is intentional hardening.
- `port out of range 0-65535` is checked both in `config_parser.cpp:98-100` and `config_validator.cpp:135-137`. The TEST_PLAN.md "known finding" about port > 65535 passing may be stale — verify in Phase 2 by chasing the path through port-group entries vs literal ports.

---

## 3. Module-boundary invariants

### Userspace ↔ BPF struct layout

- **Invariant**: `struct lpm_v4_key`, `lpm_v6_key`, `mac_key`, `l2_rule`, `l3_rule`, `l4_rule`, `pkt_meta`, `rate_state` must be byte-identical between BPF and C++.
- **Protected**: `bpf/common.h` is included from both sides; `_Static_assert` / `static_assert` on the two LPM keys; `tests/test_byte_layout.cpp` (31 tests) checks offsets. Good.
- **Unstated but relied on**: endianness conventions are documented in field comments ("network byte order"/"host byte order") but there's no central table. `ethertype_key.ethertype` is NBO, `vlan_key.vlan_id` is host, `port_key.port` is host, `l4_match_key.dst_port` is host, `lpm_v4_key.addr` is NBO, `iph->saddr` is NBO — easy to mix up when a new layer is added. A field-by-field endianness table in ARCHITECTURE.md would prevent the next bug. Findings tier: P2.

### Generation swap atomicity, drain, rollback

- **Invariant 1 (atomicity)**: A single `bpf_map_update_elem(gen_config, 0, &new_gen)` switches the read of the entry program. Held.
- **Invariant 2 (drain)**: Any in-flight packet on the old generation completes before old maps are mutated. The architecture's claim is "XDP runs with preemption disabled, so 100 ms is conservative" (`generation_manager.cpp:300-306`). On a real 40 Gbps NIC with 8-16 RX queues, a packet can be paused mid-pipeline by an NMI, but the XDP path itself is bounded by ~1M instructions. 100 ms is safe in practice. However, **`commit()` doesn't actually wait for anything** — it just sleeps. If a kthread is descheduled (extreme load, debugger), correctness is degraded. The architecture papers over this with "very conservative"; under a true 40 Gbps offered load with NAPI batching, 100 ms × N reloads/sec is wall-clock latency the operator pays. Not a correctness issue, just a stated invariant that's weaker than it sounds.
- **Invariant 3 (rollback)**: A failed `prepare()` leaves the system as it was. Held for the active generation; **not** held for the shadow generation's contents — see §2 last bullet. Rolling back after some shadow maps were populated leaves cruft. Next `prepare()` clears via `lpm_keys_[shadow]`, so it self-heals on next reload — but if the daemon crashes between rollback and the next reload, the next process won't recreate maps (no pinned bpffs use yet per owner notes), so this is benign **today**.

### Config reload vs in-flight packets

- **Invariant**: Reload errors don't perturb traffic. Confirmed in `do_reload()` (`src/main.cpp:31-62`) — every failure path returns without touching active maps.
- **Unstated**: What if reload **succeeds at compile** but **fails partway through `prepare()`** (e.g., third L4 map update returns EINVAL)? Code calls `clear_shadow_maps(gen)` and returns the error. Active is intact. Good. But if `clear_shadow_maps` itself partially fails, the shadow is in a hybrid state. The doc doesn't promise atomicity of `clear_shadow_maps`. Phase 2 should check.

### Metadata flow XDP → TC

- **Invariant**: The `data_meta` area's first 20 bytes contain a `pkt_meta` written by the entry program and never re-adjusted. TC reads it via `skb->data_meta`.
- **Protected**: `bpf_xdp_adjust_meta(-sizeof(pkt_meta))` once at entry; layer programs only read. Bounds checks `(meta+1) > data` everywhere.
- **Unstated and load-bearing**: The kernel preserves XDP `data_meta` across the XDP→TC transition **only when the driver/queue supports it**. Generic XDP and most native paths do; AF_XDP and some offloaded drivers may not. The architecture asserts it but never names the driver constraint. On the GGSN–Gi 40 Gbps NICs (likely Mellanox CX-5/CX-6, Intel E810), this is fine, but the architecture doesn't claim native vs generic XDP, doesn't pin to NIC queues, doesn't acknowledge that the L2 path bypasses certain offloads (RSS, hardware filters). Operator deploying on a NIC without `data_meta` preservation has no diagnostic. Finding tier: P1.

---

## 4. Concept-level gaps

Things a competent reviewer expects in this design space, weighted against the project's stated envelope (40 Gbps L2 line-rate filter on Gi).

- **No NIC queue / CPU affinity story.** XDP performance is dominated by RX-queue → CPU pinning, RSS hash steering for rate-limit-friendly distribution, and IRQ affinity. The architecture has zero on this — the bench numbers are BPF_PROG_TEST_RUN single-core. For 40 Gbps you need multi-queue; with per-CPU rate buckets *and* an unpredictable RSS distribution, per-rule aggregate rate-limit will be off (already acknowledged in §10 Q3 as "approximate"), but the broader queue-affinity story is missing.
- **No XDP_TX path.** Mirror and redirect use `bpf_redirect`/`bpf_clone_redirect` (different code paths, different cost). XDP_TX (bounce back out the same interface) isn't discussed — relevant if pktgate is to act as an inline DDoS scrubber (a stated scenario).
- **No native vs generic XDP statement.** README says "BpfLoader::attach() automatically detects native vs SKB XDP". The architecture doesn't commit to one. Generic XDP is 5–10× slower; on Gi interfaces the operator must know native is required, and what drivers support it.
- **No degraded-mode / failsafe.** The customer brief explicitly asks for "hot-standby or bypass mode in case of failure". The architecture has nothing. systemd `Restart=on-failure` (`pktgate.service:17-19`) is the entire story. No `WatchdogSec`, no `sd_notify`, no fail-open behavior on XDP-program-load failure (the daemon exits and traffic stops). For a Gi-side inline filter this is the difference between a momentary blip and an outage.
- **No upgrade path.** What happens on `pktgate_ctl` SIGTERM? `loader.detach_tc(); loader.detach()` (`main.cpp:278-279`) — XDP is removed, packets are forwarded normally by the host stack. That's actually a sensible default for a Gi filter (fail-open), but it isn't documented anywhere as a contract. And there's no "drain the new generation and hand off to a new daemon" story.
- **No statement of what "line-rate" means here.** Bench numbers are 76–165 ns per packet in `BPF_PROG_TEST_RUN`. The architecture never says "we target 4.88 Mpps at 1024-byte average" or "we deliberately do not target 64-byte line-rate"; an operator reading ARCHITECTURE.md sees "13.2 Mpps" with no envelope. See §5.
- **No bandwidth/throughput counters.** Per-rule counters in `stats_map` are packet counts only — no byte counters. Customer brief explicitly asks for "per-rule counters (pps/bps/drops)". `pps` is computable, `drops` is per-stat, but **`bps` is not measurable** because no byte counter is incremented anywhere. Implicit gap.
- **No sFlow / IPFIX export.** Customer brief lists "sFlow export". Not implemented. Owner-notes B explicitly says "no hard requirements"; still worth flagging as a brief-vs-implementation delta.
- **No corrupted-shadow-state recovery.** If the kernel rejects one map update partway through `prepare()`, the shadow LPM trie may have a subset of entries. `clear_shadow_maps` then iterates `lpm_keys_[gen]` — but that list was built incrementally as keys were inserted, so it should be consistent. **Unless** the failure is in batch_update partway through a batch (libbpf batch API can succeed on some items and fail on the next). Phase 2 should verify whether the in-memory list is updated per-item or per-batch.
- **No upgrade-with-config-change path.** Generation swap handles config reload, but doesn't handle BPF binary upgrade (new layer logic). Phase 11 in §11 marks "hardening done"; phase 13 added IPv6 — these required full rebuild + restart. For a stated zero-downtime story, this is a limitation that should be named.
- **No statement on capture privacy at TC.** Mirror via `bpf_clone_redirect` to an arbitrary ifindex is full-packet capture. On a multi-tenant Gi link this is a privacy / lawful-intercept concern. The architecture doesn't discuss what tenant boundary mirror crosses.

---

## 5. Performance envelope

### Customer brief numbers

40 Gbps line-rate. Two extremes:
- **64-byte Ethernet frames** (worst-case PPS, e.g., SYN flood): 40e9 / (64 + 20 inter-frame overhead) bits = **59.5 Mpps**. Per-packet budget: **16.8 ns**.
- **1024-byte average frames** (mixed Gi traffic, realistic Internet payload mix tilts to ~700–900 B average): 40e9 / (1024 × 8) = **~4.88 Mpps**. Per-packet budget: **~205 ns**.
- **1500-byte MTU**: 40e9 / 12176 = **~3.29 Mpps**. Per-packet budget: **~304 ns**.

Latency budget per brief: ≤ 500 µs **per packet**. XDP adds tens of ns, well inside.

### Published numbers

`ARCHITECTURE.md §831` and `README.md:142` table:

| Path                     | ns/pkt | Mpps  |
|--------------------------|--------|-------|
| L2 MAC drop              | 76     | ~13.2 |
| L4 TCP:80 allow          | 90     | ~11.1 |
| Full pipeline (L3 + L4)  | 165    | ~6.1  |

### Cross-check

- **64-byte line-rate**: at 76 ns/pkt the best path delivers 13.2 Mpps — 4.5× short of 59.5 Mpps. Not achievable on a single core. A 16-core 40 Gbps NIC with even per-core distribution would need ~3.72 Mpps/core; at 165 ns/pkt (full pipeline) you get 6.06 Mpps/core, which **is** enough — **if** the bench is honest. See next paragraph.
- **1024-byte average**: 4.88 Mpps. At 165 ns (full pipeline) one core can do 6.1 Mpps; 1 core suffices for the average, 8 cores for headroom and bursts. Plausible.
- **1500-byte MTU**: trivial. 3.29 Mpps fits in one core's full-pipeline budget with headroom.

### What the benchmarks don't measure

This is the meaningful caveat:

1. **`BPF_PROG_TEST_RUN` bypasses the driver, the NIC ring, NAPI, RPS, RX/TX softirq cost, page-pool churn, and cache eviction.** It's a synthetic best-case that measures the BPF program executor and nothing else. Real XDP under load is 1.5–3× the test-run number on identical hardware in our experience.
2. **No multi-core scaling test.** All numbers are single-thread `BPF_PROG_TEST_RUN`. Per-CPU map contention is by definition zero in that harness. The `rate_state_map` is `PERCPU_HASH`, so reads scale linearly, but the `stats_map` is a `PERCPU_ARRAY` whose aggregation cost lives in userspace — fine.
3. **No realistic-mix benchmark.** Only 3 paths are measured. Worst case for the design is "5 L2 hash misses + LPM trie miss + L4 hash miss + default action" — that's 9 lookups, none of which are in the table. A pessimistic estimate: 5 × (hash lookup ~25 ns) + 1 × (LPM miss ~60 ns) + 1 × (hash miss ~25 ns) ≈ 210 ns; close to the 165 ns full-pipeline number but worse, and not benchmarked.
4. **No cache-cold benchmark.** 1M packets in a tight loop runs entirely from L1/L2; production at 40 Gbps with thousands of distinct flows misses caches frequently.
5. **No NIC-attached benchmark.** No mention of TRex/IXIA or even of `xdp-bench`. Customer brief explicitly lists TRex/IXIA as the validation tool in step 6. None is in the repo or CI. The owner has acknowledged no hard target; still, the published numbers shouldn't be presented as "13.2 Mpps line-rate" without the caveat.
6. **No latency distribution.** Brief says ≤ 500 µs per packet. The bench reports average ns/pkt. p99/p999 latency under contention is not measured. The 100 ms `usleep` in commit doesn't add per-packet latency (config reload is rare), but verifier-stalled lookups, percpu allocation, and TC clone-redirect path are unmeasured.
7. **TC ingress cost.** The deferred-actions path (mirror, tag) adds an entire second BPF program execution per packet — not in the bench table.
8. **Statistics overhead.** Architecture notes "~8-10% overhead vs without statistics" but doesn't quantify per-counter cost. With 40 stat slots and `STAT_INC` on every return path, a long pipeline can hit `stats_map` 4-6 times per packet.

### Bottom line for §5

The published numbers **do not contradict** 40 Gbps line-rate at 1024-byte average **provided** you have 4-8 cores with RSS spreading evenly, native XDP, and no cache thrash. They **cannot support** 64-byte line-rate from these benchmarks. The architecture doesn't have to claim 64-byte; the customer brief talks about real Gi traffic which is far from 64 B. The honest framing is: "we benchmarked the BPF executor in isolation; line-rate-class validation needs TRex on bare metal with a multi-queue NIC". That framing is absent from ARCHITECTURE.md.

---

## 6. Scenario coverage cross-reference

Classification: **C** = covered (implementation + corresponding test), **P** = partial (some pieces work, gaps clear), **N** = not covered (declared template only).

### `scenarios/` (10 — "today's pktgate can do these 1:1" per owner notes)

| #  | File                              | Status | Notes |
|----|-----------------------------------|--------|-------|
| 01 | 01_ddos_protection.json           | **C** | allow/drop/rate-limit on L3/L4; functional test `test_zz_rate_limit.py` covers token bucket |
| 02 | 02_vlan_segmentation.json         | **C** | L2 vlan_id + L3 src_ip; both implemented (`layer2.bpf.c:179-184`) and tested (`test_l2_mac.py`, validator §39-51) |
| 03 | 03_traffic_mirroring.json         | **C** | mirror via TC `bpf_clone_redirect`; `test_zz_mirror_redirect.py` (10 tests) |
| 04 | 04_compliance_pci_dss.json        | **C** | MAC allow-list + L4 port + mirror; all building blocks present |
| 05 | 05_api_rate_limiting.json         | **P** | rate-limit + tag works; **rate_key (per-source rate)** required by realistic API tiers is not supported — global per-rule only |
| 06 | 06_vrf_routing_multitenancy.json  | **C** | VRF by ingress_ifindex (`layer3.bpf.c:272`) and redirect implemented |
| 07 | 07_ipv6_dual_stack_migration.json | **C** | L2 ethertype + IPv6 LPM + L4 IPv6 ext-headers all present |
| 08 | 08_iot_ot_isolation.json          | **C** | MAC + subnet micro-segmentation, mostly L3+L4 |
| 09 | 09_datacenter_qos.json            | **P** | DSCP via tag works (IPv4 only). **CoS (VLAN PCP rewrite) not implemented** despite being advertised in CONFIG.md — see §2 above |
| 10 | 10_port_scan_detection.json       | **C** | MAC filter + L3 drop-list + L4 mirror to IDS |

**Summary**: 8/10 fully covered; 2/10 partial (CoS unimplemented in #09, no per-source rate-limit in #05).

### `scenarios_v2/` (10 — "wishlist beyond current functionality")

Owner-notes confirm these are gap-analysis templates. Most depend on match fields and actions pktgate doesn't have.

| #  | File                                    | Status | Missing |
|----|-----------------------------------------|--------|---------|
| 01 | 01_carrier_ddos_mitigation.json         | **N** | tcp_flags works; missing: src_port, pkt_len, ttl, ip_lists, rate_key:src_ip, src_geo |
| 02 | 02_soc_incident_response.json           | **N** | `log`, `schedule` (time-bounded rules) — not in design |
| 03 | 03_pci_dss_cde_isolation.json           | **P** | tcp_flags works; `log` (per-rule event log) missing |
| 04 | 04_zero_trust_east_west.json            | **P** | core src_ip/dst_ip + dst_port works; `log` action missing |
| 05 | 05_iot_purdue_model.json                | **P** | MAC + subnet + L4 work; `log` missing |
| 06 | 06_dns_security.json                    | **N** | dns_query parsing not implemented; rate_key not implemented |
| 07 | 07_encrypted_traffic_control.json       | **N** | SNI/JA3 — deep L7, not in design space |
| 08 | 08_threat_intel_feed.json               | **N** | ip_lists (bulk external feed), src_geo, label/counter — not in design |
| 09 | 09_flowspec_compatible.json             | **P** | tcp_flags + redirect + tag work; src_port, pkt_len, icmp_type, RFC 8955 component set largely absent |
| 10 | 10_observability_sampling.json          | **N** | `sample` (1:N packet sampling), `label` (per-rule Prometheus labels), `counter` (explicit) — not in design |

**Summary**: 0 fully covered, 5 partial (core works, observability/log primitives missing), 5 not covered (require new match fields or L7).

The pattern matches scenarios_v2/README.md's own gap analysis. The single largest concrete capability gap is **per-rule `log` action** (mentioned by 6 of 10 v2 scenarios) — currently the only audit trail is the `stats_map` aggregate.

---

## 7. Architectural findings (graded)

```
- [P0] No bps counter, no per-flow byte stats
  Where: bpf/maps.h:200-205 (stats_map), bpf/{entry,layer2,layer3,layer4}.bpf.c (all STAT_INC sites)
  What: stats_map records packet counts only. There is no byte counter anywhere in the data plane. The customer brief (`_.txt:27`) explicitly requires "per-rule counters (pps/bps/drops)". README.md repeats this. CONFIG.md lists Prometheus metrics including pps. Implementing bps would require an extra map and a STAT_ADD(stat, len) per return path.
  Why it matters: For a Gi-side filter where the operational question is "how much bandwidth is rule X passing/dropping", packet counts at variable MTU are not enough. With the bench showing ~6 Mpps at 165 ns/pkt, the question "is this rule eating 5 Gbps of egress?" is unanswerable.
  Suggested action: Add `STAT_ADD_BYTES(key, pkt_len)` helper, paired counter array, expose as `pktgate_bytes_total{...}` in Prometheus.

- [P0] CoS / VLAN PCP rewrite is advertised but unimplemented
  Where: ARCHITECTURE.md §3.5 row "tag"; CONFIG.md "Actions" table param `cos`; bpf/tc_ingress.bpf.c has no VLAN rewrite path
  What: CONFIG.md exposes `"cos": 0-7` as a `tag` action param. Architecture §3.5 lists "VLAN PCP rewrite" as a tag mechanism. tc_ingress.bpf.c only does IPv4 DSCP. §10 Q6 admits this but the user-facing docs don't.
  Why it matters: Operator configs CoS, validator accepts it, deploy succeeds, packets emerge with the original PCP. Silent semantic failure on a documented feature.
  Suggested action: Either implement `bpf_skb_vlan_push/pop` in TC (the §10 Q6 deferral) and remove the warning, or reject `cos` in the validator with "not yet supported".

- [P0] No fail-open / fail-safe behaviour on data-plane failure
  Where: src/main.cpp:170-204 (load+attach paths), systemd/pktgate.service:17-19
  What: If BPF load/attach fails, daemon exits → no filter, but also no signal to the operator beyond `systemctl status`. If the daemon crashes mid-run, XDP program stays attached (kernel keeps it) — traffic continues to be filtered by the *frozen* generation. There's no `WatchdogSec=`, no `sd_notify(READY=1)`, no per-rule failure mode (e.g., a watchdog map that the userspace pings).
  Why it matters: Customer brief explicitly lists "Failover: hot-standby or bypass mode in case of failure" and "watchdog monitoring of worker health". Neither exists. On the Gi link this distinguishes a 3-second recovery from a 30-minute one.
  Suggested action: (1) Add `WatchdogSec=30` in the unit file and call `sd_notify("WATCHDOG=1")` from the main loop. (2) Document the contract: crash → XDP frozen at last good config; intentional stop → XDP detached → packets pass.

- [P1] data_meta XDP→TC contract is unstated and driver-dependent
  Where: ARCHITECTURE.md §2 and §5 ("Metadata сохраняется при XDP_PASS → TC ingress transition"), bpf/tc_ingress.bpf.c:42-66
  What: The design relies on the kernel preserving the XDP-set metadata area across the XDP-to-TC handoff. This works on most native-XDP-capable drivers (mlx5, ice, i40e) but is silently broken on some (offloaded XDP, certain virtio-net configurations). The architecture asserts the invariant without naming the driver constraint.
  Why it matters: Deployed on the wrong NIC, the TC program reads garbage metadata, mirror/tag silently fail; the only counter that fires is `STAT_TC_NOOP`. Hard to diagnose.
  Suggested action: Document required driver capabilities. Add a startup self-test that sends a sentinel packet through `BPF_PROG_TEST_RUN` on the live program and verifies pkt_meta arrives at TC.

- [P1] Architecture map count, L2 lookup count, stat count are all stale
  Where: ARCHITECTURE.md §4 (21 maps), §3.2 (4 L2 maps), §11 phase 8 ("30 per-CPU counters")
  What: Actual map count is 25 (counted in maps.h). Actual L2 lookups are 5 (incl. PCP). Actual stat slots are 40 (STAT__MAX=40). Three independent counts are wrong in the central design doc.
  Why it matters: For a doc whose purpose is "internal design for developers", drift this big means the next change will be done by reading source not docs — and the next reader will have to do exactly what this review did.
  Suggested action: Refresh §3.2, §3.5, §4, §8.1 tables; add a "last updated against commit X" marker.

- [P1] L2 compound rules, TCP flags, IPv6 dual-stack: silent expansion vs ARCHITECTURE.md
  Where: ARCHITECTURE.md §3.2-§3.4 vs bpf/layer{2,3,4}.bpf.c
  What: Three significant features — L2 secondary filter mask, L4 TCP-flag bitmasks, IPv6 data-plane paths — were added without updating the architecture doc beyond a one-line entry in the phase-completion table.
  Why it matters: Code-doc drift compounds; "we updated CONFIG.md but not ARCHITECTURE.md" is a self-correcting policy if caught early and a project-killer if not.
  Suggested action: Treat ARCHITECTURE.md and code as one PR for non-trivial changes. Backfill §3.x and the maps table.

- [P1] Generation rollback doesn't clear the (now-shadow) generation
  Where: src/pipeline/generation_manager.cpp:310-322
  What: `rollback()` only flips `gen_config[0]` back. It does not clear the maps or the `lpm_keys_[gen]` list of the generation it just demoted to shadow. Re-using rollback right after a partial `prepare()` leaves the shadow in a hybrid state. The next `prepare()` does call `clear_shadow_maps`, so self-healing on next reload — but the invariant "shadow is empty on entry to prepare" isn't preserved across a rollback alone.
  Why it matters: Confused state if a sequence of failed prepares + rollbacks is hit. With no pinned maps (today's situation per owner notes), bounded — the next successful deploy clears. Becomes more dangerous if bpffs pinning is later added.
  Suggested action: Have `rollback()` schedule a shadow-clear (or just call `clear_shadow_maps(new_shadow)` defensively). Document the invariant.

- [P0] `dst_ip` / `dst_ip6` are accepted by the parser but completely ignored — silent semantic disaster
  Where: CONFIG.md:158,160,239,241 (documented match fields); src/config/config_model.hpp:37,39 (model has the fields); src/config/config_parser.cpp:32-34 (parser populates them); src/config/config_validator.cpp (no mention); src/compiler/rule_compiler.cpp (no mention — only `src_ip` and `src_ip6` are compiled at lines 219,232); bpf/layer3.bpf.c (LPM only on saddr, daddr never read)
  What: The end-to-end path for dst_ip is: parsed into the model, then dropped on the floor. Validator does not reject it. Compiler does not emit anything for it. BPF data plane has no daddr lookup at all. A rule like `{"match": {"dst_ip": "192.168.0.0/16"}, "action": "drop"}` is silently turned into "no match fields" (rule_compiler.cpp:144 fallback `continue; // no match fields — validator should have caught this`). A rule combining `src_ip` AND `dst_ip` becomes "match on src_ip only" — the dst restriction vanishes.
  Why it matters: This is the worst class of filter bug — the operator's intent is parsed, accepted, deployed, and then disagrees with packet behaviour. On a Gi-side filter this could mean either (a) the operator thinks they're blocking egress to a destination range and aren't, or (b) a rule that should match a narrow (src,dst) pair instead matches all packets from that src. It sits exactly on the trust boundary CONFIG.md establishes with the operator.
  Suggested action: Pick one, fast: (1) implement — add `subnet_dst_v4/v6` LPM tries, compile dst_ip there, add the second lookup in layer3.bpf.c (cost: one extra LPM lookup per packet at L3 — ~30-60 ns each); or (2) remove the field — reject `dst_ip`/`dst_ip6` in the validator with a clear error, strip from CONFIG.md, document as "not supported". Either is acceptable; the current state is not.
  Latency note: option (1) doubles the L3 LPM cost on packets that hit a rule with both src and dst constraints. For packets without dst_ip in any rule, cost is one map lookup miss (~25-50 ns).

- [P2] No NIC queue / CPU affinity discussion, no native-vs-generic-XDP statement
  Where: ARCHITECTURE.md (entire doc) — absence
  What: For a Gi 40 Gbps inline filter, queue affinity and native XDP are the difference between line-rate and "10x slower than promised". Nothing in the architecture commits to a position.
  Why it matters: Operator handing this to ops has no operational deployment guide. The README "BpfLoader::attach() auto-detects native vs SKB XDP" is a footgun if the driver silently falls back to generic.
  Suggested action: Add an "Operational requirements" section: native XDP only, multi-queue NIC required, RSS recommended, IRQ pinning expected. Fail loudly if generic XDP is selected.

- [P2] Endianness rules are per-field comments, not a central table
  Where: bpf/common.h scattered comments
  What: Network vs host byte order is documented at the field level. There's no single table. Easy to make a mistake when adding a new match field. (See `parse_ethertype` returning host order but stored as NBO in keys via htons — works because the convention is followed; one mismatched htons would break L2 silently.)
  Suggested action: Add an "Endianness reference" table to ARCHITECTURE.md.

- [P2] BPF benchmarks aren't honest about what they measure
  Where: ARCHITECTURE.md §"BPF data plane benchmarks", README.md:142
  What: BPF_PROG_TEST_RUN is a synthetic harness; the ns/pkt numbers are best-case. The doc presents them as Mpps without the caveat. No NIC-attached or TRex measurement exists.
  Why it matters: A reader sees "13.2 Mpps" and concludes line-rate is proven. It isn't.
  Suggested action: Add a "Caveat: PROG_TEST_RUN measurements only; real line-rate validation requires TRex/IXIA on bare metal" note to the table.

- [P2] STAT_PASS_L3 incremented both on rule-allow and on default-action paths
  Where: bpf/layer3.bpf.c:36 and :110
  What: For a MIRROR action with no next layer, both STAT_MIRROR and STAT_PASS_L3 fire. For a packet that hits subnet → L4 → L4 default action, only L4 counters fire (correct). The L3 double-count for the mirror-terminal case is minor but inconsistent with the implied "exactly-one stat per packet" model.
  Suggested action: Phase 2 to decide if this is intentional (likely is) and document the rule.
```

---

## 8. Open issues to defer to Phase 2

- **RESOLVED (between Phase 1 and Phase 2): `dst_ip` / `dst_ip6` are unimplemented.** Confirmed by grep across `src/config/{model,parser,validator}.{hpp,cpp}`, `src/compiler/rule_compiler.cpp`, `bpf/layer3.bpf.c`. The parser populates the model fields; nothing downstream reads them. Promoted to P0 in §7. Phase 2 should still verify the empty-match fallback path in `rule_compiler.cpp:144` (does it actually `continue` past such rules, or silently emit a match-everything rule?).
- `tc_ingress.bpf.c` declares its own `stats_map`. Verify in Phase 2 that `BpfLoader` does `bpf_map__reuse_fd()` so XDP and TC share one map. If not, stats are split and the Prometheus exporter under-reports.
- The TEST_PLAN.md "known finding: port > 65535 passes validation" appears contradicted by the parser/validator both checking the bound. Phase 2 should reproduce the failing case (likely path: port_group with a string-encoded value, or port_group expansion not re-validated post-expansion).
- `clear_shadow_maps()` per-step error behaviour: does a partial failure leave the shadow in a hybrid state? Phase 2 to confirm.
- Rate-limit `do_rate_limit` has a `BPF_ANY` initialise-or-overwrite race on the per-CPU map. The kernel handles `PERCPU_HASH` element creation, but the comment in the code mentions "race" — Phase 2 should confirm tokens aren't reset to full bucket on a fast-path collision.
- Loader behaviour when XDP is already attached (e.g., daemon restart without `detach`). Doc says "automatic detection"; check if there's a stale-program-handover story.
- Object compiler / MAC group / port group expansion limits: limits in CONFIG.md (4096 per layer) — does the expansion path reject or truncate? Phase 2 to check `rule_compiler.cpp`.

---

## 9. Update to project memory

Phase 1 architecture review found that pktgate's documented design is faithful in its load-bearing skeleton — generation swap, double-buffered maps, XDP→TC hand-off via `data_meta`, inotify-with-debounce hot reload, fragment-drop hardening — but the ARCHITECTURE.md doc has drifted from the implementation along several axes. The L2 lookup is now five-way (PCP added), the data plane is fully IPv6-dual-stacked, TCP-flag filtering is implemented, L2 compound rules with a secondary filter mask exist, and the metrics/Prometheus and tools/validate_config modules are present — none reflected in ARCHITECTURE.md beyond one-liners in the phase-completion table. The map count, L2 lookup count, and stat-slot count are all stale. The principal real-correctness gaps are: (1) `cos` action parameter is advertised but the TC program implements only DSCP, so a user-visible feature silently fails; (2) no byte counters, despite the customer brief asking for bps; (3) no fail-safe/watchdog story, despite the brief asking for bypass/hot-standby; (4) the XDP→TC `data_meta` invariant is driver-dependent but never named; (5) generation rollback leaves the demoted shadow uncleared, self-healing only on the next successful deploy. The published BPF_PROG_TEST_RUN benchmarks (13.2 Mpps single-thread L2 drop, 6.1 Mpps full pipeline) leave enough headroom for 40 Gbps at realistic Gi packet sizes (≥1000 B average) on a single core, but cannot support 64-byte line-rate and are not honest about what `BPF_PROG_TEST_RUN` measures versus a NIC-attached real workload. Scenario coverage: 8/10 of `scenarios/` fully covered (CoS and per-source rate-limit are the partials); 0/10 of `scenarios_v2/` fully covered, by design — they were authored as a gap-analysis map, and the gaps they surface (per-rule `log`, `sample`, `label`, `rate_key`, `ip_lists`, `src_port`, `pkt_len`) form a coherent v2 roadmap.
