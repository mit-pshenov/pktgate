# pktgate — Critical Review Report

Status: paused (project), review complete (2026-05-11), 10/10 P0 + 8 P1 + LICENSE landed (2026-05-12). All artefacts in `_review/`. This file is the entry point; **a successor should start with `_review/HANDOVER.md`**, which has current state + setup + the open follow-ups.

## Executive summary

pktgate is a C++23/eBPF carrier-Gi packet filter (~6.7 KLOC userspace, ~1.2 KLOC BPF, 570+ test points) targeting line-rate L2/L3/L4 filtering on 40 Gbps GGSN–Gi interfaces. The customer brief (`_.txt`) frames the operating envelope; the owner additionally uses the project as an AI-assisted-development and eBPF-capability exploration (`00_OWNER_NOTES.md §A`). Eighteen development phases have shipped; the project has been paused since 2026-04-09.

The architecture's load-bearing skeleton is faithful — atomic single-write generation swap, double-buffered maps, XDP→TC handoff via `data_meta`, inotify+SIGHUP hot reload with 150 ms debounce, IPv4 fragment-drop hardening (`02_architecture.md §2`). What rots underneath are four classes of finding, each of which makes the system meaningfully unsafe even when individually small:

1. **IPv6 is systematically broken** — three independent IPv6 bugs across three BPF files (L3 fragment-bypass via Hop-by-Hop, L4 ext-header-chain-≥5 bypass, TC ingress IPv6 ACT_TAG packet corruption) all share one root cause: no IP-family gate at action sites and shallow ext-header walks that fail-open (`14_cross_cutting.md §1`).
2. **Operator-trust-boundary leaks** — the validator accepts `dst_ip`/`dst_ip6` as documented match fields and silently routes them to a `0.0.0.0/0` LPM wildcard that catches every IPv4 packet (`03_rule_compiler.md §Q1`, `04_layer3.md §1`); accepts wrong-layer match fields (`dst_port` in an L3 rule, etc.); `validate_config` returns OK on configs that destroy the network because the tool runs parse + validate but not `compile_rules`, and is not in CMakeLists anyway (`13_validate_config_tool.md`); the published `config-schema.json` is never wired into the validator and lacks the L3 `minProperties: 1` constraint that would have caught the headline bug (`12_config_parser_validator.md §Q7`).
3. **Test culture rewards happy-path coverage** — the headline `dst_ip` P0 had six plausible test sites and zero coverage; two existing tests (`test_l2_qinq_not_parsed`, `test_l2_ethertype_invalid_hex_chars`) actively assert known bugs as contract, the second one self-labels "buggy" in its own comment (`15_tests_phase.md §4`).
4. **CI runs none of the catching tests** — the `bpf_dataplane` ctest label and the entire `functional_tests/*.py` pytest suite never run automatically; every Phase-2 P0 passed CI green (`14_cross_cutting.md §5`, `15_tests_phase.md §1`).

Verdict on resume/archive: **resumable, but only after CI shape and the L3 wildcard guard land**. A single CI workflow edit plus one validator branch (~20 lines) closes the worst outage scenario and unblocks honest signal on the rest. Until those two land, every additional feature ships through the same broken pipeline.

The smallest patch set that makes a difference: add a `bpf_dataplane` + functional CI job; add a "L3 rule must have a match field" guard mirroring the existing L2 guard at `config_validator.cpp:40-48`; reject `dst_ip`/`dst_ip6` in the validator until destination LPM tries exist; add `validate_config` to CMakeLists and have it run `compile_rules`. Total surface: four files, under a day of work, closes four of the ten P0s.

## How to use this report

- **Owner returning to resume**: read the executive summary and the P0 list; the four-class deep dives explain the structural shape; the recommendations are the action plan.
- **Successor maintainer**: the project framing + executive summary give the 30-minute orientation; the artefact index (Appendix C) routes to the per-phase deep reads.
- **The P0 list is the must-read.** P1 is reference for follow-up planning. P2 is grouped by area for cleanup sweeps.
- **The class deep-dives are the structural argument** — each ends with a single structural fix the maintainer can implement to close that whole class.
- **Recommendations are rank-ordered by leverage**, not severity. Start with #1.

## Project framing

pktgate (working directory `/home/user/filter`, not its real name — `00_OWNER_NOTES.md`) is an XDP+TC hybrid packet filter driven by JSON configuration. Five BPF programs (entry, layer2, layer3, layer4, tc_ingress) tail-call through per-generation maps; the userspace control plane parses JSON, validates semantically, compiles to byte-level map entries, and atomically swaps generations via a single `bpf_map_update_elem(gen_config, 0, &new_gen)` followed by a fixed 100 ms drain (`02_architecture.md §1`, `10_generation_manager.md`).

The customer brief (`_.txt`) is a carrier-Gi 40 Gbps inline filter with ≤500 µs added per-packet latency, <0.01% packet loss, per-rule counters (pps/bps/drops), Prometheus + sFlow, hot-standby/bypass fail mode, TRex/IXIA validation. The owner doubles the project as an AI-assisted-development and eBPF-capability experiment, so "no hard production SLA" applies — but the implicit envelope is still line-rate L2 at 40 Gbps (`00_OWNER_NOTES.md §A,B`). Eighteen phases of work, 38 commits, last activity 2026-04-09, paused immediately after CONFIG.md landed.

Codebase: 6.7 KLOC C++23 userspace, 1.2 KLOC BPF kernel-side, 570+ test points (466 ctest + 104 pytest functional + 3 fuzz harnesses). Build is CMake 3.25 + clang-16+ + libbpf ≥1.1 + nlohmann_json ≥3.11. Deployment via systemd + RPM. (`01_recon.md`)

## Findings — the 10 P0 list

Ordering criterion: severity of outage potential. The dst_ip wildcard leads because a single operator config typo turns a `drop` rule into a full IPv4 blackhole on the Gi link — the worst-case operator failure mode in any reading of this project's brief.

**P0-01. `dst_ip` / `dst_ip6` accepted, become `0.0.0.0/0` LPM wildcard**
- **Where:** `src/config/config_parser.cpp:32-34`, `src/config/config_validator.cpp:82-111`, `src/compiler/rule_compiler.cpp:206-243`, `bpf/layer3.bpf.c:257-266` (and v6 mirror).
- **What:** Parser reads `dst_ip` into the model; no validator guard requires the L3 rule to carry an actual match field; the compiler's L3 loop has no `else` for the no-match-recognised case and falls through to `result.l3_rules.push_back(cr)` with a default-constructed `CompiledL3Rule` whose key is `{prefixlen=0, addr=0}`. LPM trie semantics make that entry match every IPv4 packet.
- **Why it matters under the 40 Gbps Gi envelope:** One operator typo (`dst_ip` instead of `src_ip`) silently turns a narrow drop rule into "drop every IPv4 packet on the wire" — instant Gi blackhole.
- **Smallest fix:** Add an L3 match-count guard in `config_validator.cpp` mirroring the L2 guard at lines 40-48, plus an explicit rejection of `dst_ip`/`dst_ip6` until destination LPM tries exist.
- **Cite:** `03_rule_compiler.md §Q1`, `04_layer3.md §1`, `12_config_parser_validator.md §Q1`.

**P0-02. `tools/validate_config` is the documented pre-deploy gate but lies on the catastrophic configs** **[RESOLVED 2026-05-12: validate_config now in CMakeLists; runs parse + validate + compile_objects + compile_rules. Three negative fixtures (dst_ip wildcard, empty L3 match, unknown subnet ref) + one positive fixture wired into ctest under the `unit` label. The P0-01 dst_ip class can no longer pass the tool.]**

- **Where:** `tools/validate_config.cpp:17,24` (only invokes `parse_config` + `validate_config`, never `compile_rules`); `CMakeLists.txt` (no `add_executable` for the tool); `build/validate_config` is an April-9 leftover from before the source was removed from the build.
- **What:** Documented in `CONFIG.md:40` as the pre-deploy validator. Returns `OK` on configs that trigger P0-01 because the validator gap is in the path it skips. Not built by fresh `cmake --build` — a user on a clean checkout gets "command not found".
- **Why it matters:** Operators are told this tool is the safety net. It isn't. The single most damaging operator-facing surface.
- **Smallest fix:** Add `validate_config` to CMakeLists; have it call `compile_rules` after `validate_config`; surface compile errors in the same FAIL format.
- **Cite:** `13_validate_config_tool.md`.

**P0-03. IPv6 ACT_TAG silently corrupts the packet** **[RESOLVED 2026-05-12: TC ACT_TAG path now gates on meta->ip_family. IPv6 packets bump STAT_TC_TAG_V6_UNIMPL and skip the rewrite — no more Flow Label / source-address corruption. v6 Traffic Class rewrite scoped as separate follow-up.]**

- **Where:** `bpf/tc_ingress.bpf.c:83-105` (hard-codes IPv4 byte offsets 15 and 24 with no IP-family gate); `bpf/layer4.bpf.c:259-265` (stamps `ACT_TAG` regardless of family).
- **What:** An IPv6 packet matching a tag-action rule reaches TC; byte 15 (low nibble of TC, high nibble of Flow Label) is overwritten with `(dscp<<2)|ecn` (wrong location for IPv6 DSCP); `bpf_l3_csum_replace` at frame offset 24 writes a 16-bit delta into bytes 2-3 of the IPv6 source address (IPv6 has no header checksum at that offset). No counter fires. Source address corrupted, Flow Label mangled, downstream stack either silently delivers a malformed packet or drops it.
- **Why it matters:** Carrier Gi traffic is IPv6-heavy. Any `tag` rule corrupts every matched IPv6 packet. Silent data corruption on a documented feature path.
- **Smallest fix:** Gate the TAG branch on `eth->h_proto == 0x0800` until the IPv6 TC field rewrite is implemented; remove the `bpf_l3_csum_replace` call on the v6 path entirely (IPv6 has no header checksum).
- **Cite:** `09_tc_ingress.md §2`.

**P0-04. IPv6 ext-header chain ≥5 bypasses all L4 rules and rate-limit** **[RESOLVED 2026-05-12: L4 ext-header walker now fail-closed at depth 4; if nhdr is still in {0,43,60} after the bound, STAT_DROP_L4_V6_EXT_DEPTH + XDP_DROP. Fragment check moved INSIDE the loop so it catches Fragment at any depth, not only position 0.]**

- **Where:** `bpf/layer4.bpf.c:151-185` — `#pragma unroll for (int i = 0; i < 4; i++)` walks four ext headers max.
- **What:** A chain of 5+ Hop-by-Hop / Destination-Option headers leaves `nhdr` still at an ext-header value (0/43/60) after the bounded walk; the post-loop code uses that as the L4 protocol, falls through the `if (proto == 6) else if (proto == 17)` arms, and consults `get_default_action`. Configured port rules and rate-limit silently don't apply. The post-loop Fragment check at `:175` also misses for chains hiding the Fragment header at position ≥5.
- **Why it matters:** Adversary trivially evades a configured rate-limit on an IPv6 service, or bypasses port-based drops, by appending 5+ ext headers (each ≥8 bytes, ~180 fit in one MTU). On default-allow deployments the packet passes unfiltered; on default-drop it becomes a DoS.
- **Smallest fix:** On loop exit with `nhdr` still in {0, 43, 60}, fail-closed — `STAT_DROP_L4_V6_EXT_DEPTH` + `XDP_DROP`. Optionally increase the bound to 8, but the fail-closed posture is the security-correct one.
- **Cite:** `05_layer4.md §3`.

**P0-05. Wrong-layer match fields silently accepted by validator** **[RESOLVED 2026-05-12: per-layer allowed-fields check in check_field_applicability() at config_validator.cpp. Each layer's validate_lN_rules now rejects fields belonging to other layers with "field 'X' is not applicable to layer N". 4 new negative tests added.]**

- **Where:** `src/config/config_validator.cpp` (no per-layer "allowed fields" table); `src/compiler/rule_compiler.cpp` (per-layer compile loops silently ignore fields not relevant to that layer).
- **What:** An L3 rule with `dst_port: 80` is accepted; the L3 compiler silently drops the field. An L4 rule with `src_mac` is accepted; same outcome. The only wrong-protocol guard is `tcp_flags` on non-TCP (`config_validator.cpp:166-169`); everything else slips through.
- **Why it matters:** Same class as P0-01 — operator intent diverges silently from runtime behaviour, and the validator is the exact place that should catch it.
- **Smallest fix:** Add per-layer "allowed match fields" set in the validator; emit `"field 'X' is not applicable to layer N"` for any populated-but-not-allowed field. ~15 LOC.
- **Cite:** `03_rule_compiler.md §Q7`, `12_config_parser_validator.md §Q2`.

**P0-06. systemd unit over-grants CAP_SYS_ADMIN** **[RESOLVED 2026-05-12: dropped from AmbientCapabilities and CapabilityBoundingSet. Set NoNewPrivileges=yes (the old "must be no" comment was wrong — AmbientCapabilities pass through). Added SystemCallFilter to narrow the syscall surface.]**

- **Where:** `systemd/pktgate.service:43-44` — `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_PERFMON`.
- **What:** XDP+TC on kernels ≥5.8 needs only `CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON`. `CAP_SYS_ADMIN` is the kernel-wide "root" capability (mount, namespace ops, reboot, raw memory) — the single most attacker-valuable cap on the system. Likely a copy-from-old-example artefact.
- **Why it matters:** Post-exploit blast radius is the entire kernel, not the BPF subsystem. Neutralises the otherwise-good hardening directives in the same unit.
- **Smallest fix:** Drop `CAP_SYS_ADMIN` from both `AmbientCapabilities` and `CapabilityBoundingSet`; retest on the target kernel.
- **Cite:** `14_cross_cutting.md §2`.

**P0-07. No fail-safe / watchdog mode** **[RESOLVED 2026-05-12: Type=notify + WatchdogSec=30 in the unit; pktgate_ctl writes READY=1 after attach and pings WATCHDOG=1 from the 1s main loop via direct $NOTIFY_SOCKET (no libsystemd dep). ARCHITECTURE.md §Fail-safe documents the crash-vs-stop contract.]**

- **Where:** `systemd/pktgate.service:17-19` (only `Restart=on-failure`); no `WatchdogSec=`, no `sd_notify`, no fail-open behaviour on BPF load failure.
- **What:** Customer brief (`_.txt:17`) explicitly lists "Failover: hot-standby or bypass mode in case of failure" and "watchdog monitoring of worker health". Neither exists. BPF load failure → daemon exits → no XDP attached → traffic passes unfiltered (lucky fail-open default, but undocumented). Crash with XDP loaded → kernel keeps the last good program attached and traffic continues to be filtered by the frozen generation, which is reasonable, also undocumented.
- **Why it matters:** On the Gi link this distinguishes a 3-second recovery from a 30-minute one. Brief-stated capability silently absent.
- **Smallest fix:** Add `WatchdogSec=30` + `sd_notify("WATCHDOG=1")` from the main loop. Document the crash-vs-stop contract.
- **Cite:** `02_architecture.md §7`.

**P0-08. No bps counter; customer-brief "per-rule counters (pps/bps/drops)" unanswerable** **[RESOLVED 2026-05-12: new bytes_map (PERCPU_ARRAY, parallel keyspace to stats_map) + STAT_ADD_BYTES / STAT_COUNT helpers. Entry + every terminal stat slot in L2/L3/L4 and TC ingress now bump both. Prometheus exposes `pktgate_bytes_total`, `pktgate_drop_bytes_total{layer,reason}`, `pktgate_pass_bytes_total{layer}`. StatsReader prints global bytes alongside the global packet counter. Per-rule cardinality still aggregated by (layer, reason) — a per-rule-id breakdown is a follow-up.]**

- **Where:** `bpf/maps.h:200-205` (stats_map is packet-count only); every `STAT_INC` call site across the four BPF programs.
- **What:** The 40-slot `stats_map` counts packets only — no `STAT_ADD(stat, len)` helper anywhere. The customer brief explicitly asks for bps (`_.txt:27`). README repeats this. Prometheus exposes packets only.
- **Why it matters:** For a Gi-side filter the operational question is "how much bandwidth is rule X passing/dropping". At ~6 Mpps and variable MTU, packet counts can't answer it.
- **Smallest fix:** Add `STAT_ADD_BYTES(key, pkt_len)` macro; paired counter array (`bytes_map` or extend `stats_map` to u64×2); expose as `pktgate_bytes_total{...}` in Prometheus.
- **Cite:** `02_architecture.md §7`, `14_cross_cutting.md §4`.

**P0-09. CoS / VLAN PCP rewrite advertised but unimplemented** **[RESOLVED 2026-05-12 via reject path: validator now refuses `cos` with "CoS rewrite is not yet supported (needs bpf_skb_vlan_push/pop in TC ingress)". CoS removed from CONFIG.md / ARCHITECTURE.md action tables; legacy sample2.json and conftest base_config purged of `cos: 5` so live configs validate. Test reframed from range-guard to feature-gate.]**

- **Where:** `bpf/tc_ingress.bpf.c` (no `bpf_skb_vlan_push/pop` anywhere; `meta->cos` is never read); `bpf/layer4.bpf.c:262` (stamps `meta->cos`); `CONFIG.md` and `ARCHITECTURE.md §3.5` advertise `cos` as a working tag parameter.
- **What:** Operator configures `cos: 5`, validator accepts it, L4 dutifully stamps the value into `pkt_meta.cos`, TC silently never reads it. The user-visible knob has no effect.
- **Why it matters:** Documented feature path silently fails. Same class as the dst_ip P0 — accepted, deployed, ignored.
- **Smallest fix:** Either implement `bpf_skb_vlan_push/pop` in TC ingress, OR reject `cos` in the validator with "not yet supported" and remove from CONFIG.md.
- **Cite:** `02_architecture.md §7`, `09_tc_ingress.md §1`.

**P0-10. CI runs only `unit` + `integration` ctest labels; every Phase-2 P0 passed CI green**
- **Where:** `.github/workflows/ci.yml:62-65` (label-restricted ctest); the `bpf_dataplane` label and the entire `functional_tests/*.py` pytest suite never run automatically. The coverage job (`ci.yml:91`) explicitly opts out of `bpf_dataplane`.
- **What:** Every catastrophic finding in this report passed CI because the tests that would catch them (or could catch them) run nowhere. The dst_ip P0, the IPv6 P0s, the validate_config silent-OK — all sit in test surfaces that CI doesn't exercise.
- **Why it matters:** This is the **mechanical** reason the bugs accumulated. Adding more tests is moot if those tests aren't in CI. **Fix this before fixing any other bug, or the next round lands the same way.**
- **Smallest fix:** Add a `bpf-dataplane` job to ci.yml (privileged via `sudo`, runs `ctest -L bpf`); add a `functional` job that runs `sudo bash functional_tests/run.sh`; drop the `-E bpf_dataplane` filter on the coverage step.
- **Cite:** `14_cross_cutting.md §5`, `15_tests_phase.md §1`.

## Findings — P1 (numbered list)

1. **`data_meta` XDP→TC contract is driver-dependent and unstated.** `02_architecture.md §3`, `07_entry.md §2`, `11_bpf_loader.md §Q4`. No startup self-test; on incompatible drivers `STAT_TC_NOOP` pins to 100% with no operator-facing diagnostic. Fix: BPF_PROG_TEST_RUN sentinel check in attach_tc(). **[RESOLVED 2026-05-12: ctest `test_xdp_to_tc_data_meta_contract` in bpf_dataplane snapshots STAT_DROP_NO_META, runs a sentinel packet through entry_prog via BPF_PROG_TEST_RUN, asserts the counter didn't move. Any regression that removes `bpf_xdp_adjust_meta` fails CI before it ships. Diagnostic split (P1#13) also surfaces a driver-strip case at runtime via the dedicated STAT_TC_NO_META.]**

2. **L2 BPF performs 5 sequential hash lookups, not 1.** `06_layer2.md §1`. Phase 2a's "primary by lexical order = latency-neutral" model was wrong; the BPF program walks all five maps on no-match, paying ~100-160 ns on VLAN-tagged traffic. Pipeline budget violated on a single core for the carrier-Gi-typical case. Fix: collapse to one composite-key lookup (also enables the `dst_mac` compound-rule fix below). **[PARTIAL 2026-05-12: structural collapse done — 5 maps → 1 composite (`l2_rules_{0,1}`) + active-mask iterator (`l2_active_masks_{0,1}`, MAX_L2_MASKS=8). However, post-refactor `bench_l2_no_match_fallthrough_1M` measures 590 ns (was ~294 ns); the unrolled mask-iteration + per-iteration build_l2_key + HASH lookup is heavier than the design predicted. Needs verifier-output investigation or a tighter inner loop. Closing P1#3/#9 structurally; P1#2 perf-win remains open as follow-up.]**

3. **L2 compound rules `{src_mac, dst_mac}` silently drop one MAC.** `06_layer2.md §3`. `filter_mask` (`bpf/common.h:103-105`) carries no SRCMAC/DSTMAC bits; the compiler picks the lexically-first MAC as primary and drops the other. Rule applies wider than written. **[RESOLVED 2026-05-12 via #10: FILTER_MASK_SRCMAC/DSTMAC bits added; compiler emits cross-product entries for both MACs constrained.]**

4. **QinQ (0x88a8) not parsed; `test_l2_qinq_not_parsed` cements the defect AS CONTRACT.** `06_layer2.md §6`, `TEST_AUDIT.md`. Carrier-Gi typically stacks S-Tag (0x88a8) outer + C-Tag (0x8100) inner; pktgate is invisible to the inner tag. Worst test-audit class — test actively blocks the fix.

5. **Generation rollback is broken and dead.** `10_generation_manager.md §Q2,Q4`. `rollback()` only flips `gen_config[0]`; doesn't clear demoted shadow; rolling back to the never-deployed initial gen-0 lands on empty `prog_array_0` (all packets drop via `STAT_DROP_ENTRY_TAIL`) AND zero-initialised `default_action_0[0] = ACT_DROP`. **Note: only invoked from test mocks** (`tests/test_generation_logic.cpp`, `tests/test_concurrency.cpp`) — production never calls it. The bug exists but only fires under test mock invocation. Fix: pre-populate prog_array_0 and default_action_0 at loader startup, or delete the method.

6. **Rate-limit divisor uses `libbpf_num_possible_cpus`, not online CPUs.** `03_rule_compiler.md §additional-1`, `05_layer4.md §1`. Configured 10 Gbps → ~9.77 Mbps aggregate on a stock NR_CPUS=8192 kernel (8 active RSS cores × per-CPU budget for 8192-CPU world). Phase 2a underestimated the magnitude. **[RESOLVED 2026-05-12: `online_cpu_count()` helper added; divisor now uses `sysconf(_SC_NPROCESSORS_ONLN)`. Anchored by test_online_cpu_count_bounds + test_rate_limit_divisor_uses_online_cpus.]**

7. **`rate_state_map` shared across generations, never garbage-collected.** `05_layer4.md §additional`, `10_generation_manager.md §Q1`. Single non-double-buffered `PERCPU_HASH`. Rate changes silently don't apply if `rule_id` stays stable; dead entries leak until `MAX_RATE_ENTRIES=4096`, then rate-limit silently disables. Confirmed no `bpf_map_delete_elem` call exists anywhere in userspace. **[RESOLVED 2026-05-12: two-part fix. (a) `GenerationManager::commit()` calls `MapManager::prune_u32_keys_not_in(rate_state_fd, active_rule_ids)` after the drain window, removing entries whose rule_id is no longer a rate-limit rule. (b) BPF datapath now reads `rate_bps` from `rule->rate_bps` every packet instead of the cached `rs->rate_bps`; the `rate_bps` field is gone from `struct rate_state`. So a reload that changes a rule's rate takes effect on the next packet. Tests: test_prune_u32_keys_not_in (direct helper test), test_l4_rate_limit_uses_current_rule_rate (datapath honours new rule rate against stale state).]**

8. **IPv6 fragment-drop bypassable via Hop-by-Hop → Fragment chain on L3-terminal ALLOW.** `04_layer3.md §3`. L3 only checks immediate `ip6h->nexthdr == 44`; L4 walks ext-headers and catches the hidden case but only if reached. A terminal-ALLOW L3 rule bypasses L4's defensive drop. Promoted to P1 per owner decision. **[RESOLVED 2026-05-12: L3 now walks up to 4 ext headers looking for Fragment; fail-closed on chains too deep with STAT_DROP_L3_V6_EXT_DEPTH. Terminal-ALLOW rules no longer reachable on fragments hidden behind HBH/Routing/DestOpt.]**

9. **L2 compound primary chosen by lexical order, not selectivity.** `03_rule_compiler.md §Q3`. Two rules `{ethertype:IPv4, vlan_id:10}` and `{ethertype:IPv4, vlan_id:20}` cannot coexist — the second collision-rejects. Usability footgun forcing dummy fields. **[RESOLVED 2026-05-12 via #10: composite key includes all constrained fields, so distinct {ethertype, vlan_id} pairs no longer collide.]**

10. **No compile-time enforcement of per-map size limits.** `03_rule_compiler.md §Q4`. `MAX_PORT_ENTRIES=4096`, `MAX_SUBNET_ENTRIES=16384`, etc., are enforced only by the kernel returning -E2BIG mid-deploy with a generic error. Shadow ends partially populated. **[RESOLVED 2026-05-12: `compile_rules` now runs per-map capacity checks after collision detection and rejects with a named diagnostic ("Map capacity exceeded: L4 rules (MAX_PORT_ENTRIES) has N entries (cap 4096)") before any BPF map syscall. Tests `test_l4_capacity_exceeded_rejected` + `test_l4_capacity_at_limit_accepted` anchor the boundary. MAX_L2_ENTRIES moved from maps.h to common.h so userspace can see it.]**

11. **`config-schema.json` documented as the contract but never wired in; missing `minProperties: 1` on L3.** `12_config_parser_validator.md §Q7`. CONFIG.md tells operators the schema is enforced; nothing reads it. Even if wired in, the schema's own L3 definition would miss the dst_ip P0 because it lacks `minProperties: 1`. **[RESOLVED 2026-05-12: CONFIG.md now states the schema is a non-authoritative editor-tooling reference; validate_config (which runs parse + validate + compile) is the documented source of truth and is strictly stricter than the schema would be.]**

12. **No file-size guard on config-file load.** `12_config_parser_validator.md §Q8`. Adversary with `/etc/pktgate` write access OOMs the daemon via huge JSON; inotify reads whatever's on disk. Reasonable cap: 4 MiB. **[RESOLVED 2026-05-12: 16 MiB cap (more headroom than 4, still two orders of magnitude above any real config) enforced in `parse_config()` via `std::filesystem::file_size()` before the stream is opened. Tests test_parse_config_oversize_file_rejected + test_parse_config_normal_size_accepted.]**

13. **`STAT_TC_NOOP` conflates "driver stripped data_meta" with "no deferred work today".** `09_tc_ingress.md §6`. The diagnostic counter for P1#1 above is itself ambiguous. Splitting into `STAT_TC_NO_META` + `STAT_TC_NOOP` is one enum slot. **[RESOLVED 2026-05-12: STAT_TC_NO_META (slot 43) split from STAT_TC_NOOP. The two cases now show up as distinct `pktgate_tc_total{action="no_meta"|"noop"}` Prometheus series and as `tc/noop` / `tc/no_meta` in the stats reader.]**

14. **`ACT_MIRROR` with `mirror_ifindex == 0` silently skipped, no counter.** `09_tc_ingress.md §4`. Config bug or partial deploy → mirror silently fails; audit pipeline silently misses traffic. **[RESOLVED 2026-05-12: STAT_TC_MIRROR_NO_IFINDEX (slot 44) increments whenever ACT_MIRROR fires with ifindex==0. Exposed as `pktgate_tc_total{action="mirror_no_ifindex"}` and `tc/mirror_no_iface`.]**

15. **Stale TC ingress filter after SIGKILL is not handled at restart.** `11_bpf_loader.md §Q3`. `bpf_tc_hook_create` tolerates EEXIST correctly, but `bpf_tc_attach` is called without `BPF_TC_F_REPLACE`-equivalent. After SIGKILL, the prior daemon's TC ingress program remains attached; the new daemon's attach races for the same slot and may fail with EEXIST. XDP self-heals via same-mode replace; TC needs manual `tc qdisc del`. **[RESOLVED 2026-05-12: `attach_tc()` now sets `BPF_TC_F_REPLACE` on the `bpf_tc_opts`, matching XDP's default replace-on-attach behaviour. A SIGKILL'd predecessor's TC program is overwritten in place instead of producing EEXIST.]**

16. **`NoNewPrivileges=no` is set with a misleading comment.** `14_cross_cutting.md §2`. AmbientCapabilities are compatible with `NoNewPrivileges=yes`; the comment cements a misunderstanding that defeats one of the cheapest hardening flags. **[RESOLVED 2026-05-12 as part of P0-06: set to yes with a corrected comment explaining the actual interaction.]**

17. **No `SystemCallFilter=` / seccomp on a CAP_BPF + (current) CAP_SYS_ADMIN process.** `14_cross_cutting.md §2`. Even after dropping CAP_SYS_ADMIN, a seccomp filter restricting to `@bpf @network @file-system @system-service` cuts post-exploit blast radius. **[RESOLVED 2026-05-12: SystemCallFilter=@system-service @network-io @file-system, denylist on @mount/@reboot/@swap/@raw-io/@cpu-emulation/@obsolete. EPERM on violation.]**

18. **CMake has no libbpf version floor.** `14_cross_cutting.md §5`. RPM spec requires ≥1.1 (correct, CVE-2022-3534), CMake accepts anything. Build-from-source on older distros silently compiles against vulnerable libbpf. **[RESOLVED 2026-05-12: pkg_check_modules(LIBBPF REQUIRED libbpf>=1.1) — matches the RPM spec floor.]**

19. **`tools/validate_config.cpp` missing from CMakeLists; `build/validate_config` is Apr-9 stale.** `13_validate_config_tool.md §Q9`, `14_cross_cutting.md §5`. Build-system half of P0-02. **[RESOLVED 2026-05-12 alongside P0-02; tool now in `install(TARGETS pktgate_ctl validate_config ...)` and built by default.]**

20. **Full-packet mirror has no truncation, no PII boundary.** `02_architecture.md §4`, `14_cross_cutting.md §2`. Gi-link carries subscriber HTTP, IMSI/IMEI in VoLTE SIP, unencrypted DNS, source IPs — all clone-redirected at full length. No `--max-mirror-bytes` cap, no opt-in flag, no SELinux/AppArmor profile to gate who can configure mirror rules.

21. **No per-rule observability — neither metrics nor logs nor trace.** `14_cross_cutting.md §4`. Prometheus exporter exposes 40 global counters only; no rule-id-keyed map; no `--trace-rule N` runtime hook. Customer-brief "per-rule counters" silently absent. Note: recon's "Prometheus per-rule labels" claim was wrong — exporter is global-only.

22. **ARCHITECTURE.md drift.** `02_architecture.md §2`. Map count (21 documented vs 25 actual), L2 lookup count (4 vs 5 with PCP), stat count (30 vs 40), TCP flags / IPv6 / L2 compound rules documented only in phase-completion table. Doc is no longer load-bearing for next-maintainer onboarding. **[RESOLVED 2026-05-12: section 3.2 rewritten for composite-key L2 + active-mask iterator; section 3.3 covers IPv6 LPM + family stamp + ext-header walker; section 4 maps table now reflects all 23 maps (l2_rules + l2_active_masks instead of 4 per-field maps, subnet6_rules, bytes_map); pkt_meta gains ip_family; section 8 stats enum updated to 45 slots including TC_NO_META / TC_MIRROR_NO_IFINDEX / ext-depth drops. stats_reader text dump also catches up on STAT_DROP_L2_RULE/PASS_L2/REDIRECT_FAIL/V6_EXT_DEPTH/TAG_V6_UNIMPL that were previously omitted.]**

## Findings — P2 (one-line summary)

Grouped by area. ≤ one line each. Full text in cited phase files.

**Stats / observability**
- `STAT_PASS_L3` double-fires on MIRROR-with-no-next-layer (`02_architecture.md §7`, `04_layer3.md §2`).
- `STAT_DROP_L4_NOT_IPV4` misnamed (also fires for non-IPv6) (`05_layer4.md §12`).
- `STAT_DROP_L2_NO_MATCH` conflates "no rule matched" with "tail-call to L3 failed" (`06_layer2.md §4`). **[RESOLVED 2026-05-12, as part of the L2 default_behavior fix (NEW P0-class surfaced post-review): L2 now applies default_behavior on no-match when LAYER_PRESENT_L2 is set; STAT_DROP_L2_NO_MATCH fires on default=drop, STAT_DROP_L2_TAIL fires on tail-call failure. layer_present_{0,1} ARRAY map distinguishes empty-L2 (skip-to-L3) from non-empty-no-match (apply default).]**
- `STAT_DROP_NO_META` overloaded (helper failure vs verifier-mandated bounds) (`07_entry.md §10`).
- `STAT_TC_TAG` fires only when DSCP actually changes (`09_tc_ingress.md §8`).
- No `STAT_TC_TOTAL` denominator counter (`09_tc_ingress.md §12`).
- `BPF_ANY` comment at `layer4.bpf.c:26` misrepresents a non-existent race (`05_layer4.md §2`). **Correction from Phase 1 §8: rate_state_map is PERCPU_HASH so no cross-CPU race exists; comment is misleading, no actual bug.**
- Mirror-before-tag ordering not documented (mirror sees original DSCP, on-stack sees new) (`09_tc_ingress.md §9`).

**Code shape / duplication**
- `handle_l3_action` / `handle_l3_action_v6` / `get_default_action[_v6]` are ~70 lines of duplication (`04_layer3.md §additional`).
- ACT_TAG / ACT_RATE_LIMIT fall into L3 default-drop without dedicated counter (`04_layer3.md §additional`).
- L3 tail-call asymmetry: matched-rule-fail drops, no-match-fail applies default (`04_layer3.md §6`).
- Entry doesn't pre-compute `eth_proto`/`l3_off` into pkt_meta (saving ~3-6 ns/packet) (`07_entry.md §6`).
- `pkt_meta.redirect_ifindex` is dead across L2/L3/L4/TC (`07_entry.md §9`, `05_layer4.md §12`).
- BPF compile lacks -Wall/-Wextra (`14_cross_cutting.md §5`).
- compile_commands.json contains no BPF entries; clangd cannot index `bpf/*.bpf.c` (`14_cross_cutting.md §5`). **[RESOLVED 2026-05-11, post-review: added `/home/user/filter/.clangd` with `-target bpf`, `-D__TARGET_ARCH_x86`, `-I bpf/`, `-isystem /usr/include` overrides. The `-isystem /usr/include` was the load-bearing flag — with `-target bpf`, clangd doesn't auto-include the host system header path, so `<bpf/bpf_helpers.h>` was unresolved. clangd now indexes vmlinux structs and resolves BPF helpers (signature + docstring + provider header). The 24-line file is in sync with the CMake BPF compile rule (CMakeLists.txt:67-72); a comment in it flags that requirement for future maintainers.]**

**Compiler / validator**
- Generic catch in compiler swallows rule_id for L2/L3 errors (`03_rule_compiler.md §additional-6`).
- L3-IPv6 collision check heap-allocates via 20-byte std::string (`03_rule_compiler.md §additional`).
- Validator doesn't eagerly parse CIDRs / interface names (`12_config_parser_validator.md §additional`).
- Parser yields one error per file load; validator accumulates — inconsistent UX (`12_config_parser_validator.md §Q6`).
- `device_info.capacity` parsed but never validated or used (`12_config_parser_validator.md §additional`).
- `description` field unbounded (`12_config_parser_validator.md §additional`).
- `tcp_flags` re-parse in validator is dead code in practice (`12_config_parser_validator.md §additional`).
- Action `tag` without dscp or cos still validates (`12_config_parser_validator.md §additional`).
- `object6:` ref handling is bespoke, only covers src_ip6 in L3 (`12_config_parser_validator.md §Q4`).
- `tcp_flags` on UDP rule accepted, never matches at runtime (`05_layer4.md §4`).
- No port wildcard / non-TCP-UDP silently goes to default (`05_layer4.md §5`).
- `test_l2_ethertype_invalid_hex_chars` cements the `stoul("0xGGGG")` quirk as contract (`12_config_parser_validator.md §Q11`).

**Operability / build**
- Cross-mode stale XDP attach silently demotes to SKB (`11_bpf_loader.md §Q3`).
- `detach_tc()` destroys entire clsact qdisc including egress (`11_bpf_loader.md §Q9`).
- No native-XDP-required mode, no errno on fallback log (`11_bpf_loader.md §Q4`).
- No data_meta self-test at startup (`11_bpf_loader.md §additional`).
- Latent `prog_array_0` / `default_action_0` not pre-populated (`11_bpf_loader.md §Q5`, `10_generation_manager.md §Q4`).
- `clear_shadow_maps` aborts on first error; best-effort cleanup discards error (`10_generation_manager.md §Q3,Q7`).
- `active_gen_.store` happens before the 100 ms drain (`10_generation_manager.md §Q11`).
- Drain (`usleep(100ms)`) is calendar time, not synchronisation (`10_generation_manager.md §Q5`).
- `populate_*` functions don't validate FD return values (`10_generation_manager.md §Q11`).
- `batch_update` fallback signal is a magic string (`11_bpf_loader.md §Q6`).
- REUSE_MAP / REUSE_TC_MAP macros duplicate; `int err` shadow (`11_bpf_loader.md §Q12`).
- TC reuse block silently single-purpose; future TC map additions easy to miss (`11_bpf_loader.md §additional`).
- No `attached_after_deploy_` invariant enforced (`11_bpf_loader.md §additional`).
- Hardening flags applied only to Release-no-sanitizer (`14_cross_cutting.md §5`).
- BPF benchmarks oversell PROG_TEST_RUN numbers; no TRex/IXIA validation (`02_architecture.md §5`).
- Endianness rules per-comment, not central table (`02_architecture.md §7`).

**CLI / tools / docs**
- `validate_config`: no --help, --version, --json output (`13_validate_config_tool.md §Q7`).
- `validate_config`: exit code doesn't distinguish parse vs validation errors, wraps at 256 (`13_validate_config_tool.md §Q2,Q9`).
- `validate_config`: path basename only — same-name files in different dirs collide (`13_validate_config_tool.md §Q4`).
- No data-plane fuzzer (`14_cross_cutting.md §5`).
- sFlow / IPFIX absent (customer-brief delta) (`14_cross_cutting.md §4`).
- LICENSE file absent at repo root; RPM ships a source file as the licence document (`14_cross_cutting.md §5`). **[RESOLVED 2026-05-12: GPL-2 text at repo root, installed to ${docdir} via CMake.]**
- `build/` is a month-stale snapshot (`14_cross_cutting.md §5`).
- No NIC queue / CPU affinity discussion, no native-vs-generic-XDP statement in ARCHITECTURE.md (`02_architecture.md §4`).

## Class deep-dives

### Class 1: IPv6 is systematically broken

Three IPv6-specific defects across three different files share one root error: **IPv4 logic is the source of truth, IPv6 is added as a second arm with shallow extension-header handling and no IP-family gate at action sites**. Concretely (`14_cross_cutting.md §1`):

- `bpf/layer3.bpf.c:198` checks Fragment only when it's the immediate next header; a `Hop-by-Hop → Fragment` chain bypasses fragment-drop on terminal-ALLOW IPv6 rules (P1 #8).
- `bpf/layer4.bpf.c:154` walks four ext headers; a chain of 5+ leaves `nhdr` as an ext-header value, falls into the non-TCP/UDP arm, consults default action — every L4 rule and rate-limit bypassed (P0-04).
- `bpf/tc_ingress.bpf.c:83-105` hard-codes IPv4 byte offsets for TOS rewrite and IP-checksum delta with no family check; an IPv6 packet hitting a tag rule has its Flow Label mangled and source address corrupted by `bpf_l3_csum_replace` writing into bytes 2-3 of the v6 src addr (P0-03).

The pattern is uniform: cross-cutting helpers (the L4 ext-header walker, the TC DSCP rewriter) are not parameterised on family. No code in `bpf/*.c` checks AF_INET vs AF_INET6 at the action-execution site. There is no `pkt_meta` family bit at all (`bpf/common.h:155-176`). The compiler echoes the same fragility — v4 and v6 paths in `rule_compiler.cpp:219-235` are sibling additions, no shared helper.

The test suite mirrors this gap. `functional_tests/test_l3_ipv6.py` has 10 tests — all happy-path, max ext-header chain depth 2, zero tests for IPv6 + `tag`, IPv6 + `mirror`, IPv6 + `rate-limit`. The cross-product matrix of {action × family × adversarial-encoding} is essentially empty.

**Single structural fix:** Add an `ip_family` byte (or bit in `action_flags`) to `pkt_meta`. L3 sets it on every path. Every TC ingress action site, every L4 ext-walker, every future cross-cutting helper gates on it. Replace the `for (i<4)` ext walker with a fail-closed-at-bound posture: if the walk exits without finding a transport, drop with `STAT_DROP_L4_V6_EXT_DEPTH`. Add a `BPF_V4_V6_DISPATCH(stmt_v4, stmt_v6)` macro at every site where v4/v6 logic coexists; clang-tidy lint flags `0x0800`/`0x86DD` literals outside the macro.

### Class 2: Operator-trust-boundary leaks

Four findings — P0-01 (dst_ip wildcard), P0-02 (validate_config lies), P0-05 (wrong-layer fields), P1 #11 (config-schema not wired) — are independent symptoms of one structural failure: **the validator is not actually a validator**. It is a partial sanity checker. Operators reading CONFIG.md / config-schema.json are told there is a contract; the contract does not exist.

- `dst_ip` is documented as a match field; the validator has no L3 "must have a match field" guard (`config_validator.cpp:82-111`); the compiler falls through with a default-constructed key; the BPF data plane faithfully serves the resulting wildcard LPM entry.
- The validator has no per-layer "allowed fields" table, so `dst_port` on an L3 rule, `src_ip` on an L4 rule, `vlan_id` on an L4 rule — all pass.
- `tools/validate_config`, advertised as the pre-deploy gate, runs parse + validate but not `compile_rules` — exactly the stages where the bugs live.
- `config-schema.json` exists at repo root, is described in CONFIG.md as the contract, is never loaded by any code path, and (independently) lacks `minProperties: 1` on its own L3 rule definition — so even if wired in it would miss the headline bug.

All four are silent semantic divergences between operator intent and runtime behaviour. The owner-facing surface (CONFIG.md, the validate_config tool, the schema file) promises a discipline the runtime doesn't enforce.

**Single structural fix:** Build a per-layer "allowed match fields" table in `config_validator.cpp`. Apply it in each `validate_lN_rules`. Add an L3 match-count guard mirroring the existing L2 guard at lines 40-48. Wire `compile_rules` into `tools/validate_config` (and add the tool to CMakeLists). Decide on `config-schema.json`: either wire it in via nlohmann/json-schema and fix the L3 `minProperties: 1`, or delete it and the CONFIG.md claim. The operator-facing contract becomes: "if `validate_config` says OK, the config is safe to deploy." Today it lies; this single workstream makes it honest.

### Class 3: Test culture rewards happy-path coverage

The dst_ip P0 had **six different test files** that plausibly should have caught it (`test_rule_compiler_edge.cpp`, `test_config_validator.cpp`, `test_roundtrip.cpp`, `test_pipeline_integration.cpp`, `test_ipv6.cpp`, `functional_tests/test_l3_subnet.py`); not one had a negative-match assertion for "rule does NOT fire on packets it shouldn't" (`TEST_AUDIT.md`, `15_tests_phase.md §2`). The IPv6 ext-header bypasses sit behind `for (i<4)` walks that no test exercises at depth ≥5. The `validate_config` tool has zero tests of any kind.

Two existing tests actively cement bugs as contract:

- `tests/bpf/test_bpf_dataplane.cpp:1048` (`test_l2_qinq_not_parsed`) asserts that QinQ frames drop with no inner-VLAN parsing as the expected contract. On a carrier Gi link this is the worst test variant — false confidence times two, the test actively blocks the fix.
- `tests/test_config_validator.cpp:717` (`test_l2_ethertype_invalid_hex_chars`) asserts that `"0xGGGG"` passes validation as the contract, with an inline comment that **self-labels** "This test documents current (buggy) behavior."

Two instances make this a project-level test-culture concern, not a one-off. Neither test carries a tracked TODO; without an archaeology trail, the next maintainer cannot tell deferred-by-design from latent-bug.

**Single structural fix:** Three concrete moves, in order (`15_tests_phase.md §5`): (1) PR-template question on negative-assertion tests forcing a linked design decision; (2) static CI grep flagging test sources containing `// BUG`, `// buggy`, or `// known:` adjacent to an `EXPECT`/`assert` without a linked tracking marker (would have flagged the ethertype test immediately); (3) `ARCHITECTURE.md §Known limitations` as the single audited place for "X is unsupported; here's why; here's the cost-to-fix", with tests-as-contract required to cite an entry. The flagship cheap test from `15_tests_phase.md §2 P0-4`: `test_l3_no_match_field_rejected`, mirroring the existing L2 sibling at `tests/test_config_validator.cpp:418`, is the highest-leverage single test in the entire plan — five lines of code, kills the dst_ip P0.

### Class 4: CI runs none of the catching tests

This is the **mechanical** root cause of why everything else accumulated. `bpf_dataplane` label and the entire `functional_tests/*.py` pytest suite run nowhere automatically (`14_cross_cutting.md §5`, `15_tests_phase.md §1`). Even the coverage job explicitly opts out of `bpf_dataplane` (`ci.yml:91`). Every Phase-2 P0 passed CI green.

The implication: adding tests doesn't help if those tests aren't in CI; strengthening tests doesn't help if those tests aren't in CI; even fixing the test-as-contract anti-pattern doesn't help if those tests aren't in CI. The shape of the CI is the load-bearing problem.

**Fix this FIRST.** Concretely: edit `ci.yml` to add `bpf-dataplane` and `functional` jobs (one YAML edit, ~30 lines), drop the `-E bpf_dataplane` filter on the coverage step, mark both new jobs as required for PR merge. CMake side: no edit, the `bpf;privileged` label already exists. Cost: under an hour. Without this, every other recommendation in this report risks landing through a CI that says "OK" while the bugs ship.

**Single structural fix:** The YAML in `15_tests_phase.md §2 Step 1`, copy-pasteable. Plus a follow-up CMake target for `validate_config` so it builds and CI can exercise it.

## Performance — the consolidated envelope

Per-packet latency on six representative paths, x86_64 native XDP, cache-warm, single core (`14_cross_cutting.md §3`):

| # | Path | entry | L2 | L3 | L4 | TC | Total (ns) | 1 core (Mpps) |
|---|------|-------|----|----|----|----|-----------:|--------------:|
| 1 | Untagged TCP allow (src_mac match → L3 allow → L4 allow) | 50 | 50 | 65 | 50 | — | **215** | 4.65 |
| 2 | Untagged TCP rate-limited (token-bucket pass) | 50 | 50 | 65 | 90 | — | **255** | 3.92 |
| 3 | VLAN-tagged no-match → L3 default DROP (5 L2 lookups) | 50 | 135 | 25 | — | — | **210** | 4.76 |
| 4 | VLAN-tagged TCP allow (5 L2 lookups + L3 + L4) | 50 | 135 | 65 | 50 | — | **300** | 3.33 |
| 5 | IPv6 + 2 ext headers, TCP allow + ACT_TAG (currently corrupts) | 55 | 50 | 80 | 75 | 60 | **320** | 3.12 |
| 6 | IPv4 mirror via TC clone_redirect | 50 | 50 | 70 | 50 | 120 | **340** | 2.94 |

Numbers exclude driver/NAPI/softirq cost (×1.5-3 multiplier for real NIC-attached load, `02_architecture.md §5`).

**40 Gbps verdict at 1024 B mean frame (4.88 Mpps, ~205 ns/pkt budget):** Path #1 fits on 1 core with ~5% headroom; path #3 (the carrier-Gi-typical VLAN bulk) just fits at 210 ns; path #4 (VLAN + matched TCP allow) **does not fit on 1 core**, needs 2; mirror path needs 2 cores too. **At 64-byte line-rate (59.5 Mpps, 16.8 ns budget) the design does not fit on any plausible core count** and never claimed to — the customer's carrier-Gi mix tilts heavily toward 700-1500 B average.

**Top 3 optimisations** (`14_cross_cutting.md §3`):

1. **L2 single-dispatch lookup** — replace the 5 sequential map walks with one composite-key hash + filter_mask covering all five field types. Saves **50-100 ns/pkt** on the dominant path. Effort: medium (compiler refactor + BPF rewrite). The single largest perf win in the tree.
2. **Pre-compute `eth_proto` + `l3_off` in entry's `pkt_meta`** — eliminate Ethernet re-parse at L2/L3/L4. Saves **6-9 ns/pkt**. Effort: small (lockstep refactor across four BPF files).
3. **Replace `ktime_get_ns` in rate-limit with `bpf_jiffies64`** or batched NAPI-poll timestamp — saves **10-15 ns/pkt** on rate-limited paths. Effort: small. Risk: token-bucket precision drops to ms scale (acceptable for Mbps rates).

**"If all applied" target:** Path #3 drops from 210 → ~85-125 ns (1-core capacity rises from 4.76 to 8-12 Mpps). Path #4 drops from 300 → ~170-180 ns, fitting 40 Gbps at 1024 B on a single core. The published 13.2 Mpps headline finally describes a real path, not the synthetic-shortest one.

**Honesty note:** all per-layer numbers are `BPF_PROG_TEST_RUN` measurements + reviewer estimates. No NIC-attached benchmark exists. No TRex/IXIA validation. The customer brief explicitly named TRex as the validation tool (step 6); none is in the repo or CI.

## What's deferred (out of scope, but recorded)

From `00_OWNER_NOTES.md`, accepted as deferred:

- **Pinned BPF maps (bpffs) for zero-downtime restart.** Currently maps are recreated on daemon restart; `lpm_keys_[]` in-memory state is lost on crash. Self-healing via the next successful prepare. If pinning is later added, the rollback-to-virgin-gen-0 trap (P1 #5) becomes more dangerous and `clear_shadow_maps` partial-failure behaviour needs hardening.
- **EDT-based rate-limit migration.** Current XDP rate-limiter is best-effort by design (worsened by P1 #6). Migration to `tc-htb` / EDT planned but not started. Document the current accuracy contract in CONFIG.md until then.
- **IPv6 fragment reassembly.** Intentional drop-at-L3 with dedicated counter is the documented hardening posture (`ARCHITECTURE.md:130`, `CONFIG.md:165-166`). No reassembly path planned. The P1 fragment-bypass-via-Hop-by-Hop finding is about closing the **evasion channel**, not about reassembly.

## Recommendations to maintainer

Rank-ordered by leverage, not severity. Start at #1; each subsequent item assumes the prior ones are done.

1. **Fix CI shape FIRST.** Wire `bpf-dataplane` and `functional` jobs into `.github/workflows/ci.yml`, drop the `-E bpf_dataplane` filter on coverage. One YAML edit. Closes P0-10's mechanical root cause. Without this, the rest of this list lands the same way the existing bugs landed.
2. **The cheapest single fix that kills an outage.** Add the L3 "must have a match field" guard in `config_validator.cpp:82-111` mirroring the L2 guard at lines 40-48. Reject `dst_ip`/`dst_ip6` until destination LPM tries exist. Add `test_l3_no_match_field_rejected` mirroring the existing L2 sibling test. ~20 LOC. Closes P0-01.
3. **Make `validate_config` honest.** Add the tool to CMakeLists (its own `add_executable` + `target_link_libraries`); have it call `compile_rules` after `validate_config`; surface compile errors. Add a known-bad fixtures directory and a CI test that runs the tool over it. Closes P0-02 and the build-system half of P1 #19.
4. **Treat IPv6 as one workstream, not three bugs.** Add `ip_family` byte to `pkt_meta`. Gate `bpf/tc_ingress.bpf.c` TAG path on it (closes P0-03). Make the L4 ext-walker fail-closed at depth bound with `STAT_DROP_L4_V6_EXT_DEPTH` (closes P0-04). Add an adversarial IPv6 test matrix: depth × action × family. Closes P0-03, P0-04, and P1 #8 in one phase.
5. **Tighten the systemd / supply-chain story.** Drop `CAP_SYS_ADMIN` from the unit (P0-06). Set `NoNewPrivileges=yes` and fix the comment (P1 #16). Add `SystemCallFilter=@bpf @network @file-system @system-service` (P1 #17). Pin `libbpf >= 1.1` in CMake (P1 #18). Install a `LICENSE` file. One-page change set.
6. **Add the wrong-layer-fields validator table.** Per-layer "allowed match fields" set in `config_validator.cpp`. ~15 LOC. Closes P0-05. Pair with the schema decision: wire in `nlohmann/json-schema-validator` (closes P1 #11) OR delete the schema and the CONFIG.md claim.
7. **Add a fail-safe story.** `WatchdogSec=30` + `sd_notify("WATCHDOG=1")` in the main loop. Document the crash-vs-stop contract: crash → XDP frozen at last good config; stop → XDP detached → packets pass. Closes P0-07.
8. **Add bytes counters.** `STAT_ADD_BYTES(key, pkt_len)` helper, paired counter array, Prometheus `pktgate_bytes_total{...}` series. Closes P0-08 and the customer-brief bps gap.
9. **Either implement CoS or reject it.** Either implement `bpf_skb_vlan_push/pop` in TC ingress, OR reject `cos` in the validator and strip from CONFIG.md. Closes P0-09.
10. **The L2 single-dispatch refactor.** Largest perf win (50-100 ns/pkt). Closes P1 #2, P1 #3, and P1 #9 together (collapse the 5-map walk into one composite-key lookup, with filter_mask extended to cover src_mac/dst_mac). Worth a dedicated mini-phase because it touches compiler key-selection logic, the BPF L2 program, and the test suite in lockstep.

## What this review is not

This review read every file in `_review/`'s mandatory-reading list, plus the BPF source, the C++ control-plane, the systemd unit, the CMakeLists, the CI workflows, the RPM spec, and a targeted sampling of tests. It did **not**: assembly-trace the compiled BPF programs (verifier-output analysis, JIT inspection, x86_64 instruction counting); run the functional test suite end-to-end (the veth-namespace pytest path); construct a kernel-version compatibility matrix beyond what `vmlinux.h` and the source comments imply; benchmark on the customer's actual hardware (GGSN-side Gi NIC, likely Mellanox CX-5/CX-6 or Intel E810). The latency numbers in this report are reviewer estimates extrapolated from the published `BPF_PROG_TEST_RUN` measurements plus per-helper cost models — they are honest, but they are not measured. The customer-brief target (line-rate at 40 Gbps with TRex/IXIA validation) has never been benchmarked at all, by this review or by the project's own CI.

## Appendix A: corrections to per-phase artefacts

Captured here so the per-phase files do not need to be edited; the record is complete.

- **"filter" vs "pktgate":** earlier files (`00_PLAN.md`, `01_recon.md`, scattered) say "filter". The project is **pktgate**; "filter" is the working-directory name only (`00_OWNER_NOTES.md`).
- **Phase 2a L2 latency claim is wrong** (`03_rule_compiler.md §Q3` and §"Latency impact summary"). The compiler-side "primary by lexical order" decision routes which map a rule lives in; the BPF data plane (`bpf/layer2.bpf.c:142-197`) walks **all five maps** sequentially on no-match. Correct L2 latency on the VLAN-tagged no-match path is the Phase 1 / Phase 2c number: 100-125 ns (up to ~160 ns worst case), not Phase 2a's "1 lookup, latency-neutral". This consolidated report uses the correct numbers.
- **Recon's "O(n²) collision check" claim** (`01_recon.md`) was refuted in `03_rule_compiler.md §Q5`: collision detection is five linear `unordered_map` passes, O(n) total. Dropped from the active findings list.
- **Recon's "Prometheus per-rule labels" claim** (`01_recon.md`) is wrong (`14_cross_cutting.md §4`). The exporter emits 40 global counters only; static labels (layer, reason), no rule-id cardinality. The lack of per-rule observability is filed as P1 #21.
- **Phase 1 §8's "rate-limit BPF_ANY race" does not exist** (`05_layer4.md §2`). `rate_state_map` is `BPF_MAP_TYPE_PERCPU_HASH` (`bpf/maps.h:219-224`) — each CPU sees a private slot; cross-CPU race impossible. The comment at `bpf/layer4.bpf.c:26` is misleading (P2 doc-fix); the race itself does not exist.
- **`rollback()` is effectively dead code in production** (`10_generation_manager.md §Q2`). Grep confirms it is only invoked from `tests/test_generation_logic.cpp` and `tests/test_concurrency.cpp` against bespoke mocks (not the real `GenerationManager`). The three bugs in `rollback()` (Phase 1 P1 + the rollback-to-virgin-gen-0 trap) are real but only fire under test-mock invocation. Listed in this report as P1 #5 with that caveat.

## Appendix B: review process notes

The 4-phase plan from `00_PLAN.md` worked. Phase 0 recon built a compact module map; Phase 1 architecture review caught the structural pattern (doc-vs-impl drift, IPv6 added as afterthought, customer-brief deltas) and surfaced the dst_ip suspicion that escalated through Phase 2. The ten Phase-2 module reviews each opened with the questions Phase 1 left, and at least three (Phase 2a, 2c, 2d) generated escalations or refinements that the consolidated report carries forward. Background agents enabled parallelism on the BPF files; the `TEST_AUDIT.md` ledger surfaced the meta-pattern (happy-path culture, tests-as-contract) that no single-module review would have caught.

Honest meta-observation: the review found ~50 distinct issues across all gradings in about six hours of session time. This is faster than the customer-pay billable rate would justify, but slower than a senior reviewer fluent in BPF could go without AI assistance. The largest individual win was the dst_ip P0 escalation — Phase 1 saw it as "field accepted, then dropped", Phase 2a saw it as "field becomes wildcard LPM entry that drops every IPv4 packet", and Phase 2b confirmed the data-plane half. That escalation pathway, across three sessions, is what the structured review-by-phases produced; a single-pass review would likely have stopped at Phase 1's framing.

The honest limitations from "What this review is not" apply — particularly the no-NIC-benchmark caveat, which leaves the 40 Gbps line-rate claim un-tested by either the project or the reviewer. The structural critique stands independent of those measurements; the performance envelope numbers are estimates not measurements.

## Appendix C: artefact index

Direct map from review file to content; readers can jump.

- `_review/00_PLAN.md` — original 4-phase plan, working agreement
- `_review/00_OWNER_NOTES.md` — scope decisions, deferred items, customer-brief framing, naming clarifier (pktgate vs filter)
- `_review/01_recon.md` — project map, directory tree, build & deps, hot zones; contains some claims later corrected (see Appendix A)
- `_review/02_architecture.md` — Phase 1: docs-vs-impl drift, scenario coverage, perf envelope discussion, opens dst_ip P0
- `_review/03_rule_compiler.md` — Phase 2a: `src/compiler/rule_compiler.cpp` — escalates dst_ip to wildcard-LPM P0, primary-by-lexical-order P1, rate-divisor P1
- `_review/04_layer3.md` — Phase 2b: `bpf/layer3.bpf.c` — confirms data-plane half of dst_ip P0, IPv6 frag-bypass P1
- `_review/05_layer4.md` — Phase 2d: `bpf/layer4.bpf.c` — IPv6 ext-chain-≥5 bypass P0, rate-state lifecycle P1
- `_review/06_layer2.md` — Phase 2c: `bpf/layer2.bpf.c` — refutes Phase 2a's L2 latency claim (5 lookups, not 1), QinQ-as-contract P1, MAC-pair compound rule P1
- `_review/07_entry.md` — Phase 2e: `bpf/entry.bpf.c` — `data_meta` driver dependency confirmation, pkt_meta dead-field
- `_review/08_CHECKPOINT.md` — Phase 2 mid-point inventory and pickup instructions
- `_review/09_tc_ingress.md` — Phase 2f: `bpf/tc_ingress.bpf.c` — IPv6 ACT_TAG corruption P0, CoS unimplemented P0 final confirmation
- `_review/10_generation_manager.md` — Phase 2g: `src/pipeline/generation_manager.cpp` — rollback rollback-to-virgin-gen-0 trap, rate_state_map lifecycle confirmation
- `_review/11_bpf_loader.md` — Phase 2h: `src/loader/bpf_loader.cpp` — stats_map reuse confirmed closed, stale-TC-after-SIGKILL P1
- `_review/12_config_parser_validator.md` — Phase 2i: `src/config/{parser,validator}.cpp` — validator gap for L3 match-count, wrong-layer fields, schema-not-wired
- `_review/13_validate_config_tool.md` — Phase 2j: `tools/validate_config.cpp` — tool-lies-on-catastrophic-configs P0
- `_review/14_cross_cutting.md` — Phase 3: IPv6 as a class, capability surface, perf envelope consolidated, CI shape, observability gaps
- `_review/15_tests_phase.md` — Phase Tests: CI shape audit, P0-by-P0 test plan, test-as-contract remediations, culture recommendations
- `_review/TEST_AUDIT.md` — running ledger of "bug existed, tests didn't catch"
- `_review/99_REPORT.md` — this file
