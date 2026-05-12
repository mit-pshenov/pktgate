# 05 — bpf/layer4.bpf.c (Phase 2d)

## What this program does

L4 is the terminal XDP program in the per-packet tail-call chain (entry → L2 → L3 → L4). It re-parses Ethernet from scratch (`layer4.bpf.c:105-109`), branches on `eth->h_proto` into an IPv4 or IPv6 path, parses the IP header (including IPv4 options via `iph->ihl * 4` and an unrolled IPv6 ext-header walk, max 4 iterations), reads the transport header for TCP/UDP, and looks up `(protocol, dst_port)` in the per-generation hash `l4_rules_{0,1}`. On match it runs a per-rule action: `ALLOW`/`DROP` are terminal; `TAG` stamps `dscp`+`cos`+`ACT_TAG` bit into the `pkt_meta` area read by `tc_ingress`; `RATE_LIMIT` runs a per-CPU token-bucket and yields PASS or DROP. On miss (no rule, or non-TCP/UDP transport) it consults `default_action_{0,1}` via `get_default_action`.

Inputs from L3: the `pkt_meta` struct in `data_meta` (generation, action_flags accumulated upstream, mirror_ifindex possibly set by L2/L3, etc.). Outputs: XDP verdict (`XDP_PASS`/`XDP_DROP`), and side-effects on `pkt_meta` (set DSCP/CoS/ACT_TAG bit). L4 never sets `mirror_ifindex` or `redirect_ifindex` — `l4_rule` (`bpf/common.h:151-160`) has no such fields; only L2/L3 stamp mirror.

The file has no `_v6` duplication — both families share the rule lookup, action switch, and rate-limit logic. The only duplication is between the v4 and v6 *parse* arms, which is structurally unavoidable.

## Per-question findings

### 1. Rate-limit token-bucket math correctness

`do_rate_limit` (`layer4.bpf.c:20-78`):

- **First-packet init** (line 25-34): on map-miss, build `struct rate_state init = {.tokens = rule->rate_bps / 8, ...}` and `bpf_map_update_elem(rate_state_map, &rid, &init, BPF_ANY)`, then PASS. Initial token count = `rate_bps / 8` = 1-second burst worth of bytes (the field name is `rate_bps` but it is consumed as bytes throughout — see Q1.consumption below). **First packet is always free** regardless of length — it passes before any consumption.
- **Refill per call** (line 38-58): `now - last_refill` → ns; clamped to ≤ 1e9 ns (line 52-53) so any long quiescent period only refills 1 second's worth. Refill formula: `refill = (elapsed_ns/1000) * (rate_bytes_per_sec/1000) / 1e6` — three integer divisions to keep intermediate products within u64. **Note**: a rate of `< 1000 bytes/s` (i.e., < 8 kbps) becomes `rate_kbytes = 0` and the bucket never refills. Not a real concern at the design's scale.
- **Cap** (line 62-63): `if (tokens > rate_bytes_per_sec) tokens = rate_bytes_per_sec`. Maximum burst = 1 second × per-CPU byte rate. Correct.
- **Consumption** (line 67-72): `if (tokens >= pkt_len) tokens -= pkt_len; PASS;` else DROP. Consumption is **per-byte** of full Ethernet packet (`pkt_len = data_end - data` at line 268, includes L2 header but excludes FCS/preamble). Reasonable approximation of bandwidth.

Math is internally consistent. The catch is the per-CPU divisor → see Q2.

**Effective-rate cross-check of Phase 2a's claim.** Phase 2a said "10 Gbps configured → ~40 Mbps effective on 8 CPUs". Re-derive: `libbpf_num_possible_cpus()` returns `NR_CPUS` (e.g. 8192 on stock Fedora/RHEL). The divisor in `rule_compiler.cpp:287-289` is exactly that. So `rule->rate_bps` per CPU is `total_bps / 8192`. With actual RSS spreading across 8 active CPUs each running its own bucket, aggregate ceiling under sustained load = `(total_bps / 8192) × 8 = total_bps / 1024`. For a configured `10 Gbps`, that's ~9.77 Mbps aggregate — **worse than Phase 2a's ~40 Mbps estimate by another 4×**. (Phase 2a appears to have implicitly assumed a 256-cpu kernel; on 8192-cpu kernels the math degrades to ~0.1%.) On a 64-CPU Skylake system with `NR_CPUS=64` you'd see ~1.25 Gbps aggregate from a 10 Gbps configured rate. The bug is real and **its severity scales with `NR_CPUS`, not with online CPUs**.

Note: the first-packet free-pass (line 33) means the *first* packet on each CPU after a fresh deploy doesn't count against the bucket. With 8 CPUs and frequent reloads, this is a microscopic effect; with one extreme deploy-storm reload-per-second pattern it might be measurable.

### 2. `BPF_ANY` race — not a race in practice

`rate_state_map` is `BPF_MAP_TYPE_PERCPU_HASH` (`bpf/maps.h:219-224`). **Per-CPU storage means each CPU sees its own value-slot.** Two packets on two different CPUs cannot observe each other's bucket at all; they don't share state to race over. The "BPF_ANY race" Phase 1 §8 flagged is real for `BPF_MAP_TYPE_HASH` but **not for `PERCPU_HASH`**.

The remaining same-CPU concern: an NMI/preempting program could in principle land between `lookup_elem` and the `update_elem(BPF_ANY, &init)` (lines 24-32), causing the inner caller to write a fresh-full bucket while the outer caller is mid-flight. But XDP runs with preemption disabled and NMIs do not run BPF programs that can re-enter the same map. So the race window is effectively empty. **The `BPF_ANY` comment at line 26 is a misnomer** — it suggests a race that doesn't exist on this map type. (`BPF_ANY` here means "create or overwrite"; functionally identical to `BPF_NOEXIST` on a percpu map miss path.)

**Verdict**: not a security/correctness bug, but the comment is misleading. Reclassify as P2 doc/comment fix. The actual rate-limit bug is the divisor (Q1).

### 3. IPv6 extension-header walk (`layer4.bpf.c:151-178`)

- **Bound**: hardcoded 4 via `#pragma unroll for (int i = 0; i < 4; i++)` (line 154-155). The pragma forces the verifier to unroll, eliminating loop-bound complexity. Sensible.
- **Iteration 5 behaviour**: there is no iteration 5 — the loop exits, leaving `nhdr` holding *whatever the 4th iteration assigned*. If iteration 4 advanced from an ext-header (nhdr ∈ {0,43,60}) to *another* ext-header without ever reaching a transport type, `nhdr` after the loop is *still* an ext-header value. The post-loop code does:
  ```
  if (nhdr == 44) { drop fragment; }     /* line 175 */
  proto = nhdr;                          /* line 180 */
  l4 = cursor;
  ```
  then the action switch (line 189-204): if `proto` is 6 or 17, parse TCP/UDP at `cursor`; else fall through to "non-TCP/UDP → `get_default_action(meta)`" (line 204-213).

  Concretely: **if the attacker chains 5 Hop-by-Hop / Dest-Option / Routing headers**, after the bounded walk `nhdr` will be 0 / 60 / 43 (whatever sat at position 5), `proto` = that value, the TCP/UDP branch is skipped, and the packet falls into the **default-action arm** at line 204-213. **L4 rule matching is silently bypassed.** If the default action is `ACT_PASS`, the packet sails through with no L4 rule ever consulted. If the default is `ACT_DROP`, the packet is dropped with `STAT_DROP_L4_DEFAULT`.

  This **is** the adversary-resistant question's answer: an adversary who knows the operator's default action is PASS (common — operators set default to drop only in "ports must be allow-listed" deployments; many run with default-allow for blocklist semantics) can chain 5+ ext headers and **evade every L4 port rule and rate-limit on IPv6**. The chain is cheap (each Hop-by-Hop / Dest-Option header is 8 bytes minimum). One MTU-sized packet can carry ~180 of them.

  Owner brief is a Gi-side filter on a carrier where IPv6 traffic is a thing → this is exploitable in production.

- **Fragment detection inside the loop**: the loop only assigns `next` to `nhdr` at line 171, but never checks `next == 44` inside the loop. The check is at line 175, *after* the loop ends. **A Fragment header at iteration 5 will not be checked** — see above; `nhdr` will hold whatever ext-header type, not 44, so `STAT_DROP_L4_V6_FRAGMENT` does not fire.

  However, the loop *does* terminate early on a non-skippable `nhdr` at line 156 (`if (nhdr != 0 && nhdr != 43 && nhdr != 60) break`). So an immediate Fragment header at position N≤4 will land in the `break` arm (because 44 isn't 0/43/60), and the post-loop `if (nhdr == 44)` will fire. The bypass only opens up at position ≥5.

- **All standard ext-header types?** The skippable set in the walk is `{0 (HopByHop), 43 (Routing), 60 (Dest)}`. Missing: **`135` (Mobility)**, **`139` (HIP)**, **`140` (Shim6)**, **`51` (AH)** (Authentication Header — but AH is usually treated as terminal). The `Destination Options` header can appear *twice* per RFC 8200 (once before Routing, once before transport). The 4-iteration bound covers the standard "Hop-by-Hop + Routing + Frag + Dest" stack (4 headers), but **Mobility/HIP/Shim6 are not skipped — they cause the loop to break and fall into the non-TCP/UDP arm**, which is `get_default_action`. Not a bypass per se (same fail-open-or-fail-closed-by-default), but L4 rules on those packets never apply.

- **Unknown nexthdr values**: any unknown value `!= 0/43/60` terminates the loop early. So a packet with `nexthdr=129` (TCP-MD5 extension, hypothetical) exits the loop with `proto=129`, doesn't match TCP/UDP, goes to default.

**Severity**: the ext-header-5+ bypass is the largest finding in this file. Promote to **P0 SECURITY**: documented "L4 filters on (proto,dst_port)" silently doesn't apply on a crafted IPv6 packet, and **`rate-limit` is also bypassed by the same trick** — the customer's stated rate-limit on an IPv6 service is defeatable by a 5-deep Hop-by-Hop chain.

### 4. TCP flags filter (`layer4.bpf.c:241-246`)

```
if (rule->tcp_flags_set || rule->tcp_flags_unset) {
    if ((tcp_flags & rule->tcp_flags_set) != rule->tcp_flags_set)  // must-be-set check
        return get_default_action(meta);
    if (tcp_flags & rule->tcp_flags_unset)                          // must-not-be-set check
        return get_default_action(meta);
}
```

- Set-check: `(tcp_flags & set) == set` — bits in `set` must all be present. Correct.
- Unset-check: `(tcp_flags & unset) == 0`, expressed as `(tcp_flags & unset)` non-zero → fail. Correct.
- **UDP handling**: the local `tcp_flags` (line 187) is initialised to 0. On UDP (line 197-203) `tcp_flags` is never written, stays 0. If a user accidentally configures `tcp_flags` on a UDP rule, `(0 & set) == set` only when `set == 0` — so the rule still passes the must-be-set check only if `set==0`; with any non-zero `set` value the UDP packet falls through to default action. **No correctness disaster**: UDP header bytes are not silently compared against tcp_flags.
- **Compiler gating**: `rule_compiler.cpp` accepts `tcp_flags` on any L4 rule regardless of protocol (no gate visible). So a UDP rule with `tcp_flags: SYN` will fail to match any UDP packet at runtime — operator-visible silent disagreement. P2.
- The rule's `protocol` byte (`l4_match_key.protocol`) is the **lookup key** for `l4_rules_{0,1}` (line 224-227), so TCP and UDP rules live in distinct map slots. UDP packets only retrieve UDP-keyed rules; TCP-only rules can never apply to UDP traffic. The tcp_flags fields **are** in the rule value regardless, but harmlessly zero on a UDP-typed rule (unless the user manually sets them; see above).

**Verdict**: TCP flags filter is correct; UDP packets cannot accidentally trigger TCP-flag matches; user-error case (tcp_flags on UDP rule) silently never matches. Minor.

### 5. Port matching shape

- Single hash lookup keyed by `(protocol, dst_port)` against `l4_rules_{0,1}` (line 224-233). One map lookup per packet, O(1). No O(N) scan.
- Endianness: `l4_match_key.dst_port` is host order (per `bpf/common.h:138` and Phase 2a §6). The BPF reads `bpf_ntohs(tcp->dest)` (line 195) / `bpf_ntohs(udp->dest)` (line 203) and assigns to host. Consistent.
- **No wildcard support.** Every rule must name an exact port. A rule "all TCP traffic" cannot be expressed at L4. The compiler does not emit a wildcard entry (and the BPF program would not know how to match one — there's no fallback on `(protocol, 0)` or similar). This is by design but undocumented; an operator who wants "rate-limit all TCP" would need 65,535 rules (would overflow `MAX_PORT_ENTRIES=4096`). P2 design gap.

### 6. DSCP / CoS tag handoff

- L4 stamps both: `meta->dscp = rule->dscp` and `meta->cos = rule->cos` (lines 261-262), plus the `ACT_TAG` bit in `meta->action_flags` (line 260).
- `tc_ingress.bpf.c` reads `meta->dscp` (line 66) and rewrites IPv4 TOS only (line 83-105). **`meta->cos` is never read.** Confirmed: L4 dutifully forwards the CoS value, TC drops it on the floor. This matches Phase 1 P0 §7 ("CoS / VLAN PCP rewrite is advertised but unimplemented") — **L4 is innocent, TC ingress is where the gap is.** No new finding here.
- **No IPv6 DSCP rewrite**: `tc_ingress` only rewrites IPv4 TOS (byte 15 = offset-1 in IP header). For IPv6, the analogous Traffic Class field is split between the first and second bytes of the IPv6 header (top 4 bits in byte 0, bottom 4 in byte 1). The TC code does not handle this case. Phase 2e (tc_ingress) finding territory; flagging here because L4 stamps DSCP regardless of IP family, then TC silently ignores it for IPv6.

### 7. STAT_INC density on L4 hot path

Common path = "rule matched, action=ALLOW":
- Line 250: `STAT_INC(STAT_PASS_L4)` — 1 fire.

Common-path: **exactly 1** STAT_INC. (For TAG path: 1 fire at line 263. For ACT_DROP: 1 fire. For rate-limit pass: 1 fire at line 70.)

Cumulative pipeline counts for the most common case (IPv4 TCP ALLOW with `has_next_layer`):
- entry: 1 (`STAT_PACKETS_TOTAL`)
- L2: 0 (no match)
- L3: 0 (rule matched, ALLOW, has_next_layer → tail-call, no stat fire — see Phase 2b §10)
- L4: 1 (`STAT_PASS_L4`)
- **Total: 2 STAT_INC**. About ~10-14 ns of stats overhead. Phase 1's "8-10% overhead" estimate looks accurate.

Compared to L3, L4 is one STAT_INC denser per matched-allow packet (L3 has 0 on the chain-through case, L4 must fire 1 because it's terminal). Reasonable.

### 8. Bounds checks for TCP/UDP header dereferences

- IPv4: `iph + 1 > data_end` (line 118), `iph->ihl < 5` (line 123), `l4 = (iphdr + ihl*4)` (line 129-130), `l4 > data_end` (line 132). **Correct** — honours options (ihl > 5) properly. ihl is read from `iph` after the `iph+1` bounds check, so the read is safe. The `l4 > data_end` check uses `>` not `>=`; the subsequent `(tcphdr+1)>data_end` (line 191) / `(udphdr+1)>data_end` (line 199) re-checks. No off-by-one.
- IPv6: cursor advance per ext header (`cursor += ext_len`, line 166), re-check `cursor > data_end` after each step (line 167). After the loop, `(tcphdr+1)>data_end` / `(udphdr+1)>data_end` is the final guard. **Correct.**
- One nit: `__u8 hlen = *(cursor+1)` (line 164) is read after `cursor + 2 > data_end` (line 159), so the read is in-bounds. `ext_len = (hlen + 1) * 8` can be at most 256 × 8 = 2048 bytes — bounded. (Hop-by-Hop spec maximum is 2048 bytes.)
- **`pkt_len = data_end - data` at line 268** for rate-limit: full L2 frame size including L2 header. Doesn't include FCS but that's by design. Bounds-safe because `data_end - data` is a verified scalar diff.

Bounds checks are clean.

### 9. Default action retrieval at L4

`get_default_action` (line 80-96) is structurally identical to L3's `get_default_action`:
- Branch on `meta->generation`, lookup `default_action_{0,1}[0]`.
- If absent or `*def == ACT_DROP`: `STAT_INC(STAT_DROP_L4_DEFAULT)` and `XDP_DROP`.
- Else: `STAT_INC(STAT_PASS_L4)` and `XDP_PASS`.

**Double-count concern (analogous to L3's `STAT_PASS_L3`):** `STAT_PASS_L4` fires from two sites:
- Line 94 (default-pass)
- Line 250 (rule-matched-ALLOW)

For a rule-allow packet only line 250 fires (returns immediately; doesn't go through `get_default_action`). For a default-pass packet only line 94 fires. So unlike L3's MIRROR/PASS dual-fire, **L4 has no double-count** — the two sites are on mutually exclusive paths. Cleaner than L3 by accident.

No `_v6` variant — L4 has a single default-action path for both families. Good.

### 10. Code structure (v4/v6 duplication)

Only the IP-header parse arms are duplicated (lines 115-135 v4 vs 136-185 v6), which is unavoidable — the structs differ. After the IP parse, both families converge on the same `proto` and `l4` cursor and run a single rule lookup / action switch. **Significantly cleaner than L3**, which copy-pastes ~70 lines of `handle_l3_action`. ~50 lines of necessary v4/v6 divergence at L4, no avoidable duplication. Nothing to fix.

### 11. Verifier-complexity surface

- The IPv6 ext-header loop is the closest pathological pattern. `#pragma unroll` forces 4-fold unrolling; the verifier sees 4 sequential copies, each with its bounds check. Manageable.
- Generation `if/else` doubling appears at the rule-lookup site (line 230-233) and the default-action site (line 85-88). Two split-points, four arms total — like L3, well under the verifier complexity ceiling.
- The action switch (line 248-275) is jump-table-ish; no loops.
- No recursive or backwards-pointer patterns. Verifier-friendly overall.

### 12. Surprises / other observations

- **`rate_state` value is mutated in place via the lookup pointer** (`rs->tokens += refill` at line 59, `rs->last_refill = now` at line 65). For a `BPF_MAP_TYPE_PERCPU_HASH` this is legal — the kernel returns the per-CPU slot's address and direct mutation is the canonical pattern. No race. Good.
- **`rs->rate_bps` is read from the map** (line 40), but **`rule->rate_bps` is read for the *initial* tokens** (line 28) — both should be the same value (the compiler wrote `rs->rate_bps = rule->rate_bps`). However, on a *rate change* via reload, the entry in `rate_state_map` carries the **old** `rate_bps` until the rule_id falls out of the map (LRU? no — `BPF_MAP_TYPE_PERCPU_HASH` is not LRU). Since `rate_state_map` is shared across generations (not double-buffered, see `bpf/maps.h:217-224`) and indexed by `rule_id`, **a rule with `rule_id = N` and a new rate after reload will continue to use the *old* rate from `rate_state_map[N]`** until either (a) userspace explicitly deletes the entry, or (b) the rule's `rule_id` changes (compilers often re-assign IDs on reload). I don't see any userspace `bpf_map_delete_elem` against `rate_state_map` in `generation_manager.cpp` (would need a Phase 2 confirm). **If rule_ids are stable across reloads (likely), a rate-limit change does not take effect until the entry ages out — but `BPF_MAP_TYPE_PERCPU_HASH` does not age out.** This is a P1 latent bug.
- **`STAT_DROP_L4_NOT_IPV4`** (line 183) — named misleadingly; it fires when the packet is neither IPv4 nor IPv6, not "not IPv4". Cosmetic.
- **Non-TCP/UDP transport doesn't drop, it consults default.** Lines 204-213: if `proto` is ICMP, SCTP, GRE, ESP, etc., the packet falls into `get_default_action`. This means an operator who configures "default=DROP" will silently drop all ICMP. An operator who configures "default=ALLOW" will pass all ICMP unfiltered (no rule can apply). This is by design but undocumented in CONFIG.md. P2.
- **`STAT_DROP_L4_NO_META`** fires from two places (line 209 in non-TCP/UDP arm, line 219 in TCP/UDP arm). On a well-formed pipeline, `pkt_meta` is always present (entry stamps it). This stat firing is a strong signal of a bug — the only legitimate cause is `bpf_xdp_adjust_meta` having failed at entry (which would have already dropped) or the driver not preserving meta. So it's also a useful diagnostic counter; no change needed.
- **The `BPF_DBG` calls** are compiled out unless `-DBPF_DEBUG`. No release-time cost. Good.
- **`pkt_meta.redirect_ifindex`** — confirmed unused at L4 (L4 has no redirect action). Phase 2b §11 already noted this is allocated but unused at L3 either (L3 passes ifindex directly to `bpf_redirect`). Across L2/L3/L4, **`pkt_meta.redirect_ifindex` is never written or read**. Dead struct field. P2.

### 13. 40-Gbps-line-rate-reviewer perspective

**Where is L4 most painful?**

Common path (IPv4 TCP, rule match, ALLOW):
1. Eth re-parse + bounds check: ~2 ns
2. IPv4 parse + ihl check + l4 cursor compute + bounds check: ~3-4 ns
3. TCP header bounds + read dst_port (with bswap) + read tcp_flags: ~3 ns
4. Build `l4_match_key`, hash lookup `l4_rules_{gen}`: ~25-30 ns (hash lookup dominates)
5. Generation if/else: ~1 ns
6. `pkt_meta` bounds re-check: ~1 ns
7. TCP-flags check (often skipped via the `||` guard at line 241): ~0-1 ns
8. Action switch: ~1 ns
9. STAT_INC(STAT_PASS_L4): ~6 ns
10. **L4 total: ~45-55 ns** for the rule-allow TCP path.

For rate-limit on the same path:
- All of above except line 9, replaced by:
- `bpf_map_lookup_elem(rate_state_map, &rid)`: ~25-30 ns (PERCPU_HASH lookup)
- `bpf_ktime_get_ns()`: ~10-15 ns (vDSO-ish but actual helper call, includes lfence on x86)
- Token-bucket math (3 divisions): ~3-5 ns
- STAT_INC: ~6 ns
- **L4 rate-limit path total: ~80-100 ns** — meaningfully heavier.

For the IPv6 path with 2-3 ext headers: add ~5-10 ns for the unrolled loop iterations and the cursor advance/bounds-check on each.

For the divisor-bug-fixed case: per-packet cost is **unchanged**. The bug is a userspace number; the BPF math is the same. Fixing it gains correctness, not latency.

**Pessimal path** (rate-limit drop on IPv6 with 3 ext headers): ~100-120 ns at L4. Plus 50-80 ns L3 + 100-125 ns L2 (per Phase 2b's estimate) ≈ 250-325 ns. Above the 205 ns/pkt budget for 1024-byte 40 Gbps. For the common ALLOW path with no rate-limit, the pipeline is ~165 ns and fits.

**Recommendation**: L4 itself is in budget. The ext-header walk bypass (Q3 P0) is the dominant correctness issue. Rate-limit math is correct but rate-limit accuracy is the divisor bug (still a userspace fix). The single load-bearing latency optimisation that would survive scrutiny is recording the `l4_off` offset in `pkt_meta` at entry, so L4 doesn't re-walk Ethernet + IPv4/IPv6 + ext-headers (saves ~5-10 ns common path, ~10-20 ns IPv6+ext path).

## Additional findings

Beyond the questions list:

- **`rate_state_map` is shared across generations** (not double-buffered, see `bpf/maps.h:217-224` — single map keyed by `rule_id`, no `_0/_1`). On a rate-rule change via config reload, the *old* token bucket persists for the *same* `rule_id` because (a) `PERCPU_HASH` doesn't expire entries, (b) generation swap doesn't touch this map. If the compiler stably assigns the same `rule_id` to a logically-equivalent rule across reloads (which is the natural design), rate changes don't take effect. If the compiler re-assigns rule_ids, the new bucket starts at full and the old bucket leaks until `MAX_RATE_ENTRIES=4096` is hit. Either way **the lifecycle is undefined**. P1.
- **`bpf_ktime_get_ns()` cost** (~10-15 ns) is paid on every rate-limited packet, including ones that immediately PASS without rate-limiting. Could be skipped on the first-packet-init path (`do_rate_limit` line 25-34) where `last_refill` is set to `now` and tokens are pre-filled — the function still calls `bpf_ktime_get_ns` once (line 29) but not twice. OK.
- **The `STAT_PASS_L4` on default-pass path** (line 94 in `get_default_action`) — same naming-not-bug-but-confusing issue as L3's PASS counter. The user-facing semantic "packets passed L4" is the right sum; the question "due to rule or due to default" is lost. P2 doc.
- **No byte counters at L4 either** — confirms Phase 1 P0 globally. Rate-limit *does* measure bytes (pkt_len) but doesn't expose them through a stat. Would be a one-liner to add at line 70 / 75: `STAT_ADD(STAT_BYTES_RATE_LIMITED, pkt_len)`.
- **`__builtin_memset(meta, 0, sizeof(*meta))`** is in entry.bpf.c:45, so `meta->dscp` and `meta->cos` start zero. L4 only writes them on ACT_TAG. If a rule-allow packet flows through L4 without TAG, `meta->dscp` is 0 and `meta->cos` is 0 — TC will see `ACT_TAG` bit clear and skip the rewrite. Correct.

## Latency analysis (per-packet cost)

| Path | L4 contribution | Cumulative pipeline |
|------|-----------------|---------------------|
| IPv4 TCP rule-allow | ~45-55 ns | ~165 ns (Phase 1 number) |
| IPv4 UDP rule-allow | ~40-50 ns (no tcp_flags work) | ~160 ns |
| IPv4 TCP rate-limit pass | ~80-100 ns | ~200-220 ns |
| IPv4 TCP rate-limit drop | ~80-100 ns | ~200-220 ns |
| IPv4 TCP rule-allow with TAG | ~50-60 ns (extra: 2 stores into meta) | ~170 ns |
| IPv6 TCP rule-allow, 0 ext headers | ~50-60 ns | ~170-200 ns (L3 v6 LPM extra cost) |
| IPv6 TCP rule-allow, 3 ext headers | ~60-80 ns | ~190-220 ns |
| Non-TCP/UDP (ICMP etc.) → default | ~25-35 ns | ~150-165 ns |
| **Adversarial IPv6 5-ext-header bypass** | ~70-90 ns | ~200-235 ns, **but L4 rules silently skipped** |

The divisor-bug fix changes none of these latencies — it adjusts a userspace constant. The fix to make rate-limit *accurate* doesn't help (or hurt) per-packet cost.

The largest per-packet optimisation available: pre-compute `l4_off` at entry (~5-10 ns saved on the common path, ~10-20 ns on the IPv6+ext path).

## Findings (graded)

```
- [P0 SECURITY] IPv6 ext-header chain ≥ 5 deep bypasses all L4 rules and rate-limit
  Where: bpf/layer4.bpf.c:151-185
  What: The unrolled 4-iteration walk leaves `nhdr` still pointing at an extension-header
        type when the chain is longer than 4. The post-loop code treats this value as the
        L4 protocol; it's neither 6 nor 17, so the packet falls into the non-TCP/UDP arm
        and consults `get_default_action`. L4 port rules and rate-limits are silently
        bypassed. The Fragment-Header check (line 175) also misses, because the Fragment
        header sat at position ≥5.
  Why it matters: Owner brief is a Gi-side 40 Gbps carrier filter; carrier IPv6 traffic is
        real. An adversary chains 5+ Hop-by-Hop/Destination-Option headers (each ≥ 8 bytes,
        ~180 per MTU) and trivially:
          - Evades a configured rate-limit on an IPv6 service
          - Evades a port-based DROP rule
          - On default-allow deployments, the packet passes unfiltered
        On default-drop deployments the bypass becomes a DoS instead of an evasion (all
        such packets drop with STAT_DROP_L4_DEFAULT), which is also undesirable on a
        carrier link.
  Suggested action: Either (a) increase the loop bound to ~8 and add an "if `nhdr` is
        still an ext-header type after the bounded walk, DROP with a dedicated stat" guard
        at line 173; or (b) keep bound=4 and on loop-exit-with-still-ext-header, DROP
        (`STAT_DROP_L4_V6_BAD_EXTHDR` or similar). Option (b) is the security-safe choice;
        legitimate traffic does not require deep ext-header chains.

- [P1] rate_state_map is shared across generations and never garbage-collected
  Where: bpf/maps.h:217-224, bpf/layer4.bpf.c:24-32 (no delete path),
         src/pipeline/generation_manager.cpp (Phase 2 must confirm — no delete visible)
  What: rate_state_map is a single non-double-buffered PERCPU_HASH keyed by rule_id. On
        reload with a changed rate, the old bucket persists. If rule_ids are stable
        across reloads, the new rate is never applied. If rule_ids re-shuffle, dead
        entries leak until MAX_RATE_ENTRIES=4096 is hit, at which point new buckets
        cannot be created (BPF_ANY on a full PERCPU_HASH returns -E2BIG, which the code
        ignores: line 32 ignores the return value), and the rate-limit silently does
        nothing (rs stays NULL on the next packet → STAT_RATE_LIMIT_PASS, infinite
        pass-through).
  Why it matters: Configured rate-limit changes silently don't apply, and the long-term
        leak path silently disables rate-limit entirely.
  Suggested action: Either (a) make rate_state_map double-buffered (one per generation,
        clean on generation swap) or (b) have userspace explicitly bpf_map_delete_elem
        each rule_id on commit/rollback (b is simpler if rule_ids are tracked).

- [P2] BPF_ANY comment at layer4.bpf.c:26 misrepresents the race
  Where: bpf/layer4.bpf.c:25-32 + bpf/maps.h:219-224
  What: Comment says "with BPF_ANY to handle race" but rate_state_map is PERCPU_HASH —
        each CPU sees a private slot; cross-CPU race doesn't exist. Same-CPU
        re-entrancy via NMI doesn't run BPF programs that touch this map. The flag
        choice is fine; the comment is misleading.
  Suggested action: Update comment: "BPF_ANY = create-or-overwrite; PERCPU_HASH so no
        cross-CPU race".

- [P2] No wildcard / 'match any port' support; non-TCP/UDP falls to default silently
  Where: bpf/layer4.bpf.c:204-213 (non-TCP/UDP path), :224-227 (port-keyed lookup)
  What: L4 only matches exact (proto, dst_port) tuples. There's no way to write
        "rate-limit all TCP" or "drop all UDP" without enumerating ports.
        Non-TCP/UDP protocols (ICMP, SCTP, GRE, ESP) silently bypass L4 rule matching
        entirely, going straight to default action. Operator-visible silent
        disagreement with intent.
  Suggested action: Document in CONFIG.md; consider a "(proto, port=0)" wildcard
        convention that the BPF program checks as a fallback when the exact lookup
        misses. Cost: one extra hash lookup on miss.

- [P2] tcp_flags on UDP rules is accepted by compiler, silently never matches at runtime
  Where: bpf/layer4.bpf.c:187, :241-246; src/compiler/rule_compiler.cpp:294-298
  What: Compiler accepts tcp_flags on any L4 rule regardless of protocol. UDP packets
        carry tcp_flags=0 by construction in this BPF code, so any non-zero
        tcp_flags_set on a UDP rule causes the must-be-set check to fail → fall to
        default. Operator wrote a rule that never matches.
  Suggested action: Validator should reject tcp_flags on UDP rules.

- [P2] pkt_meta.redirect_ifindex is dead code across L2/L3/L4
  Where: bpf/common.h:167, no writes anywhere; no reads at L4
  What: Allocated 4 bytes in pkt_meta, never written, never read. L2/L3 pass redirect
        ifindex directly to bpf_redirect helper; TC ingress doesn't redirect.
  Suggested action: Remove field (4-byte savings, one less endian/byte-layout invariant
        to maintain), or wire it up if a future XDP→TC redirect deferral is planned.

- [P2] CoS handoff is one-way (L4 stamps, TC ignores) — not a new finding, just
  confirms Phase 1 P0 §7 from the L4 side
  Where: bpf/layer4.bpf.c:262 (writes meta->cos), bpf/tc_ingress.bpf.c (never reads it)
  No new action.

- [P2] STAT_DROP_L4_NOT_IPV4 is misnamed (also fires for non-IPv6)
  Where: bpf/common.h:226, bpf/layer4.bpf.c:183
  Suggested action: Rename to STAT_DROP_L4_NOT_IP or document.
```

## Test-audit notes

- **P0 SECURITY: IPv6 5-ext-header bypass.** No test exists that crafts an IPv6 packet with ≥5 Hop-by-Hop / Dest-Option headers and asserts that the configured L4 rule still fires (or that the packet is dropped). `functional_tests/test_l3_ipv6.py` (per recon, 10 tests) likely covers ext-headers but at chains ≤3 (the "normal" depth). **Test class: adversarial coverage missing.** Same class as the L3 fragment-behind-ext-header bypass (Phase 2b finding) — there's a pattern: ext-header handling has happy-path tests but no adversarial-depth tests.
- **P1: rate_state_map lifecycle.** A test that (a) configures rate-limit at X bps, (b) sends traffic and verifies rate, (c) reloads with a new rate Y, (d) verifies effective rate matches Y — would catch this. `functional_tests/test_zz_rate_limit.py` (per recon) probably tests one rate at a time. **Test class: lifecycle / reload coverage missing.**
- **P2 BPF_ANY comment.** Doc-only.
- **P2 no port wildcard.** Documentation, not a behaviour test.
- **P2 tcp_flags on UDP rule.** A negative unit test in `tests/test_config_validator.cpp` would catch this. **Test class: validator coverage absent.**
- **P2 redirect_ifindex dead field.** Static-analysis territory; no behavioural test would surface this.

## Open issues for later phases

- **`src/pipeline/generation_manager.cpp`**: verify there's no `bpf_map_delete_elem(rate_state_map, ...)` on commit/rollback — needed for the P1 rate_state lifecycle finding above.
- **`tc_ingress.bpf.c` (Phase 2e)**: IPv6 DSCP rewrite is absent. L4 stamps DSCP, but TC only rewrites the IPv4 TOS byte. For IPv6 traffic the tag silently disappears even if the operator configures it. (Combines with Phase 1 P0 §7 — CoS — to make `tag` action broadly under-implemented.)
- **`bpf/layer2.bpf.c` (Phase 2c)**: confirm the 5 hash lookups Phase 1 estimated at 100-125 ns are actually that, since L2 is the suspected pipeline bottleneck. Also confirm compound-rule secondary-mask logic with primary-by-lexical-order from Phase 2a.
- **Adversarial fuzz for the BPF data plane** (Phase 3 / cross-cutting): the ext-header bypass would be discoverable by a packet-level fuzzer mutating IPv6 headers and checking that documented filter semantics hold. `tests/bpf/test_bpf_dataplane.cpp` is unit-shaped, not fuzz-shaped.
- **Rule-ID stability across reloads** (control-plane review): if the compiler assigns rule_ids deterministically from rule content, the rate_state_map staleness is exploitable; if it assigns from a counter, the leak is the failure mode. Either way, behaviour needs to be characterized.
