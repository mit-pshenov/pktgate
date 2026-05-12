# 04 — bpf/layer3.bpf.c (Phase 2b)

## What this program does

`layer3.bpf.c` is the third XDP program in pktgate's per-packet tail-call chain (entry → L2 → L3 → L4). On entry it re-parses Ethernet (no L2 layout assumption — entry/L2 do not consume bytes, only walk the buffer) and reads the `pkt_meta` that `entry.bpf.c` placed in the `data_meta` area (generation, action flags, mirror/redirect ifindex). It decides between two parallel paths by `eth->h_proto`: IPv6 (`0x86DD`, line 188) or IPv4 (`0x0800`, line 238); anything else is dropped as `STAT_DROP_L3_NOT_IPV4`.

For each family the program: (a) bounds-checks the IP header, (b) drops fragments (IPv4 non-first via `frag_off & 0x1FFF`; IPv6 by detecting `nexthdr == 44` Fragment Header — no ext-header walk happens here, L3 only inspects `ip6h->nexthdr` directly), (c) looks up the source address in the per-generation LPM trie (`subnet_rules_{0,1}` / `subnet6_rules_{0,1}`), and (d) on LPM miss, falls back to a VRF hash lookup keyed by `ctx->ingress_ifindex` (`vrf_rules_{0,1}`). On rule hit `handle_l3_action[_v6]` dispatches: DROP/REDIRECT terminate; MIRROR stamps deferred TC flag and continues; ALLOW continues. "Continues" means either tail-call to L4 (`prog_array_{0,1}[LAYER_4_IDX]`) if `has_next_layer` set, or terminal `XDP_PASS` with `STAT_PASS_L3{,_V6}` increment.

On a complete miss (no LPM, no VRF) the program *unconditionally* attempts a tail-call to L4, and only if that tail-call falls through does it consult `default_action_{0,1}` via `get_default_action[_v6]` (line 290 / 234). The fall-through is the failure-mode signal for "no L4 program installed" — semantically: "no L3 rule said anything, let L4 decide; if L4 isn't there, apply the global default."

## Per-question findings

### 1. LPM-wildcard P0 confirmation — CONFIRMED, both v4 and v6

The Linux kernel `BPF_MAP_TYPE_LPM_TRIE` semantics are unambiguous longest-prefix match. An entry with `{prefixlen=0, addr=0}` is the catch-all that wins whenever no more-specific prefix matches. `layer3.bpf.c:257-266` (IPv4) builds `lpm_v4_key{prefixlen=32, addr=iph->saddr}` and does a single `bpf_map_lookup_elem` against `subnet_rules_{0,1}`. There is no post-lookup filter on `prefixlen` of the *returned* rule (the LPM helper returns the value associated with the matching key, not the key itself — the BPF program cannot tell whether it just matched a /32 or a /0). Whatever rule's action sits in the value pointer is executed by `handle_l3_action`. Same shape for IPv6 at `layer3.bpf.c:205-215`: `lpm_v6_key{prefixlen=128, addr=ip6h->saddr}`, single lookup against `subnet6_rules_{0,1}`, no prefixlen filter.

→ Phase 2a's P0 escalation is confirmed at the data plane. A `{prefixlen=0, addr=0}` entry inserted by the compiler (via the dst_ip-only-rule path identified in `03_rule_compiler.md` Q1) **does** match every IPv4 packet via `bpf_map_lookup_elem`, and there is no defensive guard. Same for IPv6. The "drop ALL IPv4 traffic" symptom is real.

The verifier does **not** save us here: the verifier checks code paths, not map contents. The map contents come from userspace via a happy-path compiler call. No code change in this file is necessary if the compiler stops producing such entries; if a belt-and-braces fix is wanted, see "Open issues".

### 2. STAT_PASS_L3 double-count — confirmed minor, intentional-by-naming-not-design

Two increment sites for `STAT_PASS_L3`:

- `layer3.bpf.c:36` inside `get_default_action`, on the "default is not DROP → XDP_PASS" branch (no rule matched, no L4 program available, default action lets it through).
- `layer3.bpf.c:110` inside `handle_l3_action`, on the "rule matched, action was ALLOW or MIRROR, no next layer" branch.

The `STAT_PASS_L3` name reads as "packet passed L3" which both sites do. So if you read the counter as "packets that traversed L3 without being dropped *and* terminated at L3", both sites are correct. The double-count Phase 1 worried about is **only** for the MIRROR-terminal case (rule has `action=MIRROR, has_next_layer=0`): then both `STAT_MIRROR` (line 89) and `STAT_PASS_L3` (line 110) fire on the same packet. For ALLOW-terminal there's only one fire. For DEFAULT-PASS there's only one fire.

→ Verdict: **counter-naming issue, not a bug.** The user-facing question "how many packets passed L3?" gets a correct sum; the question "what was the reason this packet was passed?" double-counts mirror-terminal. A clean design would split `STAT_PASS_L3_RULE` from `STAT_PASS_L3_DEFAULT`. Same applies to the v6 pair (lines 54 and 160). Phase 1 P2 (`02_architecture.md §7`) called this out — confirmed minor. **No new finding.**

### 3. Fragment handling correctness — IPv4 correct, IPv6 conservative-by-design

**IPv4 (line 250):** `bpf_ntohs(iph->frag_off) & 0x1FFF`. `iph->frag_off` is u16 NBO on the wire; `bpf_ntohs` converts to host; mask `0x1FFF` extracts the 13-bit fragment offset (the top 3 bits are flags: reserved/DF/MF). A non-zero result means "non-first fragment" (offset > 0). Endianness and mask are correct. First fragments (offset 0, MF=1) are **not** dropped here — they go through normally and L4 sees the TCP/UDP header in them, which is what the comment ("they lack L4 headers" specifically about non-first ones) describes. Verdict: correct, consistent with `ARCHITECTURE.md:130` and `CONFIG.md:165-166`.

Note: a first fragment with non-trivial L4 header tampering (small first fragment, only TCP source port in it, rest in second fragment) **is not detected** here — the project intentionally doesn't reassemble. Out of scope per owner notes §5.

**IPv6 (line 198):** `if (ip6h->nexthdr == 44)` — Fragment Header. This catches the case where the *immediate* next header is Fragment. **It does not catch the case where a Fragment Header is hidden behind other extension headers** (e.g., Hop-by-Hop, then Fragment). The IPv6 spec mandates Hop-by-Hop is always first if present, so `Hop-by-Hop → Fragment` is a real packet shape. L3 here will not detect that; `layer4.bpf.c:151-178` does walk ext headers (bounded to 4) and at line 175 *does* detect Fragment, dropping with `STAT_DROP_L4_V6_FRAGMENT`. So:

- L3 has a fast-path drop for the **common** "Fragment is first" case
- L4 catches the **rare** "Fragment hidden behind Hop-by-Hop/Routing/Dst" case

This is internally consistent — but only if every IPv6 packet eventually reaches L4. A packet that hits an L3 rule with `has_next_layer=0` and action=ALLOW skips L4 entirely. **An attacker can therefore evade fragment-drop on an L3-terminal IPv6 ALLOW rule by hiding the Fragment header behind a Hop-by-Hop ext header.** Likelihood that an operator writes an L3-terminal IPv6 ALLOW rule that an adversary controls source for: low. Severity if it happens: the operator thinks fragments are dropped and they aren't. → P2.

### 4. IPv6 extension-header walk in L3 — NOT PRESENT

`layer3.bpf.c:198` checks only `ip6h->nexthdr` directly. There is no ext-header loop. This is *good* for the cross-cutting latency goal (zero per-packet cost on the L3 IPv6 path beyond the single byte compare). It is the source of the §3 edge case above. No verifier-complexity exposure exists at L3 — only at L4, which Phase 2d will cover.

### 5. VRF lookup cost — fallback only, common path pays nothing

The VRF hash lookup happens **only on LPM miss** (`layer3.bpf.c:268`, `:214` for v6: `if (rule6)` returns before VRF). Common path with a populated `subnet_rules` map: one LPM lookup, no VRF. Pessimal path: one LPM miss + one VRF miss = two lookups. This is correct cost-shaping.

LPM-trie lookup cost is **not** O(1) hash like the other maps — kernel implementation walks the trie node-by-node from `prefixlen=0` toward `prefixlen=32` (or 128 for v6), so cost scales with the *depth of populated prefixes*. Worst case on v6 is 128 levels; with sparse population (a few dozen prefixes) it's much less. Phase 1 estimated 30-60 ns; on a heavily-populated v6 trie at the bottom of every miss path that pushes higher. Not a finding, just envelope.

### 6. Tail-call to L4 cost and failure mode — handled correctly, but two distinct failure semantics

Two distinct tail-call sites with different post-failure behaviour:

- **Inside `handle_l3_action`** (line 100-107 v4; line 151-157 v6): rule matched, has_next_layer set, attempt tail-call to L4. Failure → `STAT_INC(STAT_DROP_L3_TAIL)` and `XDP_DROP`. **Failure here drops the packet.** This is safe (fail-closed for matched rules) but also means a transient missing L4 prog entry on a matched rule = drop, not pass.
- **End of `layer3_prog`** (line 284-290 v4; line 229-234 v6): no rule matched, no VRF rule. Attempt tail-call to L4 unconditionally. Failure → `return get_default_action(meta)` which falls back to `default_action_{0,1}`. **Failure here is the normal "no L4 installed" signal** and applies the configured global default.

`bpf_tail_call` returns 0 on failure and execution falls through (kernel semantics; verifier permits the return value to be ignored). Both sites handle the fall-through. **The two sites disagree on default**: matched-rule-but-no-L4 drops; no-rule-but-no-L4 applies global default. The doc never names this asymmetry. Probably intentional (a matched rule that expected L4 confirmation but didn't get one is "broken pipeline" → drop is safer than wildcard-allow), but should be documented. Minor.

A concrete bug-trigger: if `prog_array_{gen}` is in a state where `LAYER_4_IDX` is unpopulated (e.g., partial deploy where L4 program failed to load), every packet that matches an L3 rule with `has_next_layer=1` is dropped while every packet that *doesn't* match an L3 rule applies the default action. That's an oddly skewed failure mode. Not a finding — `BpfLoader` populates the prog_array atomically with the rest of the deploy — but the asymmetry is worth flagging in a future doc pass. → P2.

### 7. Bounds checks — all present, two are redundant

Every dereference is preceded by a `+1 > data_end` (or equivalent) check:

- `eth + 1 > data_end` at `layer3.bpf.c:172` before `eth->h_proto`
- `meta + 1 > data` at `layer3.bpf.c:180` before `meta->generation`
- `ip6h + 1 > data_end` at `:190` before `ip6h->nexthdr` and `&ip6h->saddr`
- `iph + 1 > data_end` at `:244` before `iph->frag_off`, `iph->saddr`

No header has its fields read before its bounds are established. The verifier would reject otherwise. **No missing or duplicated check.** Note: the eth bounds check at `:172` and a hypothetical re-walk of eth at L4 each pay a verifier-mandated test; not redundant *within* L3.

One small note: `data_meta` is bounded against `data` (line 180) not `data_end` — correct per XDP semantics, `data_meta` is below `data` and reads of `pkt_meta` end exactly at `data`. Pattern matches entry.bpf.c:40 and layer2.bpf.c:113.

### 8. Endianness — clean, with one small honest description

| Read | Type | Comparison | Verdict |
|------|------|------------|---------|
| `eth->h_proto` (line 185) | NBO u16 | `bpf_htons(0x86DD)` / `bpf_htons(0x0800)` | OK (both NBO) |
| `iph->saddr` (line 259) | NBO u32 | stored into `lpm_v4_key.addr` whose comment says NBO | OK (direct copy, no convert) |
| `iph->frag_off` (line 250) | NBO u16 | `bpf_ntohs(...) & 0x1FFF` | OK (convert then mask host-order) |
| `ip6h->nexthdr` (line 198) | u8 | `== 44` | OK (byte-sized, no endianness) |
| `ip6h->saddr` (line 206) | NBO 16-byte | `memcpy` into `lpm_v6_key.addr` whose comment says NBO | OK |
| `ctx->ingress_ifindex` (line 218, 272) | host u32 | `vrf_key{.ifindex = ...}` whose comment is silent — implied host | OK (both host) |

No endianness bug. The `lpm_v4_key.addr` "already network byte order" comment at `:259` is accurate; the LPM-trie internals compare keys byte-wise so NBO is required.

### 9. Generation indirection cost — two literal `bpf_map_lookup_elem` paths

`layer3.bpf.c` uses an `if (meta->generation == 0) ... else ...` pattern for every per-generation lookup (lines 27-30, 45-48, 100-103, 151-154, 209-212, 220-223, 229-232, 263-266, 275-278, 284-287). This is **the literal-map form** — the verifier and JIT see two separate `bpf_map_lookup_elem` calls (one for each generation map) and one branch on a u32. Cost: one branch (predictable per deploy generation; predicts close-to-perfect after the first few packets per CPU) + one helper call (~5-10 ns on x86_64). The alternative (a map-of-maps with the generation as outer key) would add one extra lookup *per* per-packet decision — strictly worse on the per-packet axis. The chosen pattern is the cheap one.

One per-packet code-bloat consideration: every `if (gen == 0) else` doubles the code-path footprint for the verifier (it analyses both arms). For a single program (~290 LOC of source, ~600 BPF insns guesstimate) this is well under the 1M verifier limit. Fine.

### 10. Stat increment density on the hot path — modest

Counting `STAT_INC` on the **common-success** path (IPv4 packet, rule matches, action=ALLOW, has_next_layer=1, tail-calls L4):

- `entry.bpf.c`: `STAT_INC(STAT_PACKETS_TOTAL)` (1)
- `layer2.bpf.c`: 0 (no match → falls through to L3, no stat fire on the "no L2 rule" common case)
- `layer3.bpf.c`: 0 (rule matched, ALLOW, has_next_layer → no STAT_INC fires before tail call! `handle_l3_action` only increments inside the action switch — ALLOW breaks and proceeds; `STAT_PASS_L3` only fires on the no-next-layer leg at line 110)
- `layer4.bpf.c`: 1-2 depending on action

So the L3 hot path is **0 STAT_INC** when a rule matches and tail-calls L4. The L3 cost is dominated by the LPM lookup. Phase 1's "8-10% overhead from stats" is plausible at the *whole-pipeline* level (3-5 fires/packet) but L3 itself contributes little. Each STAT_INC costs ~5-7 ns on x86_64 (PERCPU_ARRAY: bounds check + per-CPU offset + atomic inc — actually the BPF macro uses `(*_cnt)++` which is *non-atomic* per-CPU which is faster but means concurrent NMI on same CPU could lose increments. Standard pattern, accepted.).

Hot path is lean. Cold and pessimal paths increment 1-2 times — also fine.

### 11. Surprises / other observations

- **`__u16 eth_proto = eth->h_proto;` at line 185**: read NBO into a u16 local; only ever compared with `bpf_htons(...)`. The comparison is u16-vs-u16 NBO. Correct. A pedant would write `__be16` but the BPF code doesn't import that type from `linux/types.h` and the pattern is consistent across `layer2.bpf.c` and `layer4.bpf.c`. Style only.
- **`get_default_action_v6` is a copy of `get_default_action` with two stat constants swapped.** ~13 lines of duplication. Easy to drift on the next change. → P2 maintainability.
- **`handle_l3_action_v6` is a near-verbatim copy of `handle_l3_action`** (lines 58-112 vs 115-162), differing only in the three stat constants. ~55 lines duplicated. Same drift risk. → P2.
- **`default` case in the action switch increments `STAT_DROP_L3_RULE` and drops** (line 94, 146). If the userspace compiler ever produces a rule with `action` outside the enum range (corrupt config, future enum addition not handled here), it silently counts as a rule drop. A separate `STAT_DROP_L3_BAD_ACTION` would be a clearer signal. → P2.
- **`ACT_TAG` and `ACT_RATE_LIMIT` are not in the L3 switch.** They fall into the `default:` arm — both will drop the packet. Per `bpf/common.h:37-44` these are valid actions, used only at L4. The compiler does enforce this (rule_compiler L3 path only emits ALLOW/DROP/REDIRECT/MIRROR). But if a future config or future enum extension makes `ACT_TAG` appear in an L3 rule, this program silently drops. A defensive comment "L3 only supports ALLOW/DROP/REDIRECT/MIRROR" would document the contract. → P2 doc.
- **No byte counter**: confirmed for L3, as Phase 1 P0 noted globally. `STAT_INC` is the only stat primitive; no `STAT_ADD(stat, len)` exists. Not a new finding.
- **`ip6h->saddr` LPM is on **source**, not destination, with no option for the alternative.** Confirmed (line 206). The Phase 2a dst_ip P0 covers the symptom; here we confirm the absence on the BPF side.
- **`ctx->ingress_ifindex` is used directly without bounds-checking.** It's a kernel-provided u32 — always valid. Just noting.
- **`prog_array_{0,1}` capacity is 4 (`MAX_LAYERS`).** Tail calls to `LAYER_4_IDX = 2` are within bounds. Index 0 is L2 (used by entry), index 1 is L3 (used by L2 → L3), index 2 is L4 (used by L3 → L4 and by L2 → L4 directly), index 3 unused. No off-by-one risk.
- **Re-parse of Ethernet at each layer.** L2 walked it; L3 walks it again; L4 walks it again. Each pays the bounds check the verifier requires. Cost: 1 memory load + 1 branch per layer, ~2-3 ns. Could be eliminated by recording `l3_off` in `pkt_meta`, paying the storage at entry. Not a per-packet *correctness* issue but it's the most obvious latency optimisation available — see "Latency analysis" below.

### 12. 40-Gbps-line-rate-reviewer perspective

The data plane's most painful per-packet cost at L3 is **not** in `layer3.bpf.c` itself — it's the cumulative re-parse work the design forces on every layer. L3 spends one ~30-60 ns LPM lookup on the matched-rule path, which is in the ballpark of "single-digit ns per layer". The lookup is unavoidable; the re-parse arguably isn't.

The next-most-painful is verifier complexity from per-generation `if/else`-doubled code paths. For 290 LOC it's harmless; if the layer ever grows new match types (e.g., dst_ip support), the code-bloat penalty compounds. A reviewer would push back on adding match types until either (a) the generation indirection is moved into a per-CPU constant or (b) the dual-map design is replaced with something verifier-friendly.

The IPv6 ext-header decision (L3 only checks `nexthdr` immediate, L4 walks) is the right perf-vs-correctness trade for the common case. The reviewer would still ask: *what happens with a Hop-by-Hop-Fragment chain on an L3-terminal IPv6 ALLOW rule?* (Today: it slips through L3 because nexthdr=0 not 44, and L4 is never invoked because the rule is terminal.) See §3 above.

## Additional findings

Beyond the per-question items:

- **`handle_l3_action` does not write the `redirect_ifindex` into `pkt_meta` before `bpf_redirect`.** The kernel `bpf_redirect(rule->redirect_ifindex, 0)` helper is given the ifindex directly. So `pkt_meta.redirect_ifindex` is unused at L3 (only set by L4 if at all — check Phase 2d). This is fine; just noting `pkt_meta` carries a field for which only some layers use the channel.
- **`meta->action_flags |= (1 << ACT_MIRROR)` at lines 87, 139** uses `ACT_MIRROR = 2` as a bit position. Result: bit 2 set, value 4. Since the bit is read by `tc_ingress.bpf.c` checking `flags & (1 << ACT_MIRROR)`, this works as long as both sides use the enum value as a bit index. Compile-time check would help. Not a bug.
- **No log/audit per matched rule.** Confirms Phase 1 §6's broader observation that scenarios_v2 require per-rule log primitives that don't exist anywhere in the data plane.

## Latency analysis (per-packet cost)

**Common IPv4 path** (rule matches `subnet_rules`, action=ALLOW, has_next_layer=1):

| Step | Cost (rough ns on x86_64) |
|------|---------------------------|
| L3 prologue: 2 bounds checks (eth, meta) | ~1 ns |
| eth_proto compare against `bpf_htons(0x86DD)` (skipped IPv6) and `bpf_htons(0x0800)` (IPv4) | ~1 ns |
| iph bounds check + frag_off mask | ~1 ns |
| Build `lpm_v4_key`, `bpf_map_lookup_elem(subnet_rules_{gen})` | ~30-50 ns (LPM trie depth-dependent) |
| Generation if/else branch | ~1 ns (well predicted) |
| `handle_l3_action`: switch on action, break, has_next_layer branch | ~2 ns |
| `bpf_tail_call(prog_array_{gen}, LAYER_4_IDX)` | ~15-25 ns (kernel tail-call overhead) |
| **Total L3 segment** | **~50-80 ns** |

No STAT_INC fires on this path — the only stat write in L3 happens on terminal-pass / drop / mirror legs.

**Common IPv6 path** (rule matches, action=ALLOW, has_next_layer=1):

Identical step pattern, with:
- One extra byte compare (`nexthdr == 44`)
- Memcpy of 16 bytes into LPM key (line 206) instead of single u32 assignment — but a 16-byte memcpy on cache-warm bytes is ~1-2 ns
- LPM trie depth up to 128 for v6 vs 32 for v4; with sparse population this costs ~5-10 ns extra; on a heavily-populated trie up to 20-30 ns extra
- **Total L3 segment: ~55-100 ns**

**Pessimal IPv4 path** (LPM miss + VRF miss + tail-call falls through to default):
- L3 prologue: ~3 ns
- LPM miss (trie still walks): ~50 ns
- VRF hash miss: ~25 ns
- Failed tail call: ~15 ns
- `get_default_action`: 1 lookup + 1 stat increment + return: ~12 ns
- **Total: ~105 ns** for the worst L3 path.

**Conclusion:** L3 is **not** the bottleneck. The LPM lookup is the single dominant cost (~30-50 ns), and it's unavoidable for the design. The pipeline bottleneck on the customer's 40 Gbps Gi at realistic packet sizes (≥1000 B average → 4.88 Mpps → 205 ns/pkt budget) sits at the **cumulative ent+L2+L3+L4 ~165 ns figure** Phase 1 quoted — that's a sum where L2 (5 hash lookups, ~100-125 ns) and L4 (rate-limit token-bucket math, hash) likely dominate over L3. The latency-relevant ask for L3 is therefore: don't grow it. Adding dst_ip support naively (a second LPM lookup per packet, see Phase 1 P0 suggested action) would add ~30-50 ns per packet — pushing the full-pipeline budget meaningfully.

## Findings (graded)

```
- [P0 CONFIRMED] LPM wildcard 0.0.0.0/0 from compiler reaches data plane and matches every IPv4 packet
  Where: bpf/layer3.bpf.c:257-266 (v4), :205-215 (v6) — vs src/compiler/rule_compiler.cpp:206-243
  What: This is the data-plane confirmation of Phase 2a's escalation. `bpf_map_lookup_elem`
        on an LPM trie with a `{prefixlen=0, addr=0}` entry returns that entry for ANY source
        address. No guard in layer3.bpf.c checks the returned prefixlen (the helper doesn't
        even expose it). The rule's action is executed.
  Why it matters: A dst_ip-only config produces an LPM wildcard from rule_compiler. The BPF
        program faithfully serves it. End-to-end: "drop traffic to 10/8" silently drops every
        IPv4 packet on the wire. This is the customer's worst-case outage scenario.
  Suggested action: Fix is unambiguously upstream of this file — reject in validator
        (config_validator.cpp) AND/OR guard in rule_compiler.cpp:242 against an empty-match
        L3 rule. Optional belt-and-braces at this file: after `bpf_map_lookup_elem` returns,
        check that `rule->rule_id != 0` (assuming compiler always emits non-zero IDs) before
        dispatching. This is defensive only; the real fix is at the compiler/validator layer.

- [P1 NEW — promoted from P2 by owner] IPv6 L3 fragment detection bypassable via ext-header chain (evasion-channel for intentional hardening)
  Where: bpf/layer3.bpf.c:198 — only checks `ip6h->nexthdr == 44`
  What: A packet with `nexthdr=0 (Hop-by-Hop)` followed by `next=44 (Fragment)` slips past
        L3 fragment-drop. L4 (layer4.bpf.c:151-178) DOES walk ext headers and catches this —
        but only if the packet reaches L4. An L3 rule with `has_next_layer=0, action=ALLOW`
        terminates at L3, skipping L4's defensive check.
  Why it matters: Fragment-drop is intentional hardening (ARCHITECTURE.md:130, owner notes §5).
        The invariant CONFIG.md publishes — "IPv6 fragments are dropped at L3" — is not held
        when a terminal-allow IPv6 rule applies. This is an active evasion channel on a
        documented security boundary, which makes it a security finding regardless of
        likelihood. Promoted to P1 per owner decision (review session 2026-05-11).
  Suggested action: (a) Add a 4-iteration unrolled ext-header walk before the Fragment-Header
        check in layer3.bpf.c (mirror of layer4.bpf.c:151-172). Cost: ~5-10 ns on the IPv6
        path even on common packets without ext headers, due to the unrolled compare. (b)
        Force ALLOW L3 rules to always tail-call L4 regardless of `has_next_layer`, so L4's
        defensive check always fires. Option (b) changes the L3-vs-L4 contract but adds zero
        per-packet cost on packets without ext headers. Owner to choose.

- [P2 NEW] Two tail-call sites disagree on fail-mode (matched-rule drops, no-rule defaults)
  Where: bpf/layer3.bpf.c:99-107, :150-157 (matched-rule, fail=DROP) vs :284-290, :229-234
        (no-match, fail=apply default)
  What: Both sites attempt `bpf_tail_call(prog_array, LAYER_4_IDX)`. On failure (slot
        unpopulated): the matched-rule site drops the packet; the no-match site applies
        the global default action. This is probably-intentional ("a matched rule that
        expected L4 confirmation is broken if L4 is gone, drop is safest") but unstated.
  Why it matters: An operator who sees skew between "matched rule drop count" and
        "default action count" during a partial deploy has no diagnostic for why.
  Suggested action: Document the asymmetry in ARCHITECTURE.md §3.3; add a comment in
        handle_l3_action explaining the fail-closed choice.

- [P2 NEW] handle_l3_action / handle_l3_action_v6 / get_default_action / get_default_action_v6
  are near-verbatim duplicates differing in stat constants
  Where: bpf/layer3.bpf.c:22-38 vs :40-56; :58-112 vs :115-162 (~70 lines duplicated)
  What: Four copies; only the STAT_* constants differ. Future changes (e.g., per-rule byte
        counter from Phase 1 P0) must be applied in two places each.
  Why it matters: Drift risk on future maintenance. The IPv6-as-an-afterthought feel from
        Phase 1's architecture findings is reinforced here.
  Suggested action: Macro-parameterise on the stat-key set, or pass a small struct of stat
        keys. Cost: one indirection at compile time, zero per-packet cost (always-inline).

- [P2 NEW] ACT_TAG and ACT_RATE_LIMIT fall into the default-case "DROP_L3_RULE" arm without
  a distinct counter or comment
  Where: bpf/layer3.bpf.c:93-95, :145-147
  What: The action switch handles ALLOW/DROP/REDIRECT/MIRROR. ACT_TAG (4) and ACT_RATE_LIMIT
        (5) fall through to `default:` which increments STAT_DROP_L3_RULE and drops.
        Compiler currently never emits these for L3 (rule_compiler.cpp limits which actions
        each layer accepts) — so this is unreachable in practice. But the contract is
        implicit, not stated.
  Suggested action: Add a `// L3 only supports ALLOW/DROP/REDIRECT/MIRROR — others compiled
        away by rule_compiler.cpp` comment, OR add a dedicated STAT_DROP_L3_BAD_ACTION counter
        so an unexpected config still produces a diagnosable failure.
```

## Test-audit notes

- **LPM-wildcard P0 (confirmed data plane half)** — a `BPF_PROG_TEST_RUN` against `subnet_rules_{0,1}` populated with `{prefixlen=0, addr=0}` and assertions "an arbitrary saddr packet matches" would have caught this end-to-end. `tests/bpf/test_bpf_dataplane.cpp` exists (per recon) but evidently doesn't have a "what does the data plane do when the compiler produces a wildcard" test. **Test class: absent.** Same gap applies to v6.
- **P2 IPv6 fragment-behind-ext-header bypass** — a functional test in `functional_tests/test_l3_ipv6.py` sending `IPv6/HopByHop/Fragment/...` and asserting drop would have caught this. Existing test suite likely tests only the direct `nexthdr=44` case. **Test class: test wrong layer / absent.**
- **P2 tail-call asymmetry** — a `BPF_PROG_TEST_RUN` running L3 with `prog_array[LAYER_4_IDX]` unpopulated and varying whether a rule matches would surface the two different fail outcomes. Probably not tested today.
- **P2 duplicate v4/v6 handlers** — N/A; structural finding, not behavioural.
- **P2 unreachable action codes (ACT_TAG/RATE_LIMIT at L3)** — could be caught by a fuzzer that emits map contents with arbitrary action values; the existing fuzz harnesses target the parser/compiler upstream, not direct map-content injection.

## Open issues for later phases

- **Verify in Phase 2d (`bpf/layer4.bpf.c`)** that the ext-header walk's 4-iteration bound is sufficient for adversarial input (e.g., crafted chain of 5+ Hop-by-Hop headers — does the loop bail safely?). This relates to the §3 / P2 finding above.
- **Tail-call to L4 from "matched rule but L4 missing" silently drops** (line 105-107). Is there a libbpf-loader path where this transient happens during gen swap? Phase 2c (loader/generation_manager) should confirm the prog_array population is atomic with the rest of generation commit.
- **Adversarial LPM trie depth**: an attacker who controls a single source-IP /128 in `subnet6_rules` (via co-tenant rule) could make their packet's LPM lookup walk deeper than legitimate flows. Phase 3 (cross-cutting perf) should validate that LPM trie cost stays within the per-packet budget under worst-case populated tries.
- **`pkt_meta.redirect_ifindex` is allocated but unused at L3** (L3 passes ifindex directly to `bpf_redirect`). Verify in Phase 2d / 2e that L4 / TC ingress actually use this channel, or remove the field. Minor.
- **STAT_PASS_L3 / STAT_PASS_L3_V6 ambiguity** — see §2 above. Document or split, depending on owner preference.
