# 06 — bpf/layer2.bpf.c (Phase 2c)

## What this program does

L2 is the second program in the chain (entry → L2 → L3 → L4). Entry has only stamped `pkt_meta.generation` and zeroed everything else; it has not advanced past Ethernet. L2 itself:

1. Bounds-checks the Ethernet header (`layer2.bpf.c:104-108`) and reads `pkt_meta` from `data_meta` (`:112-116`).
2. Parses 802.1Q if `eth->h_proto == 0x8100`: extracts `vlan_id` (12 LSB of TCI), `pcp` (3 MSB of TCI), and inner ethertype (`:128-140`). QinQ (`0x88a8`) is **not** parsed — treated as a normal ethertype.
3. Performs **up to five sequential hash lookups** in the fixed order src_mac → dst_mac → ethertype → vlan_id → pcp (`:142-197`). Each lookup is gated on a generation `if/else` doing one `bpf_map_lookup_elem` against `l2_<x>_{0,1}`. On every hit the matched `l2_rule`'s `filter_mask` is checked via `l2_filters_match` (`:20-35`) — secondary fields (ethertype/vlan/pcp) are register-compared against the already-parsed metadata; src_mac and dst_mac are **not** secondary fields (no `L2_FILTER_SRCMAC` / `L2_FILTER_DSTMAC` bit exists in `common.h:103-105`).
4. On first matching rule with passing filter_mask, `handle_l2_action` (`:37-95`) runs the action: ALLOW/MIRROR continue and either tail-call L3/L4 (per `rule->next_layer`) or `XDP_PASS` (terminal); DROP/REDIRECT terminate; unknown action drops with `STAT_DROP_L2_RULE`.
5. On no match in any of the five maps, the program **unconditionally** tail-calls L3 (`:200-203`). Tail-call fall-through drops with `STAT_DROP_L2_NO_MATCH`. **L2 never consults `default_action_{0,1}`.**

## Per-question findings

### 1 & 2. CONTRADICTION with Phase 2a — five hash lookups per packet, not one

**Phase 2a's data-plane prediction is wrong.** Phase 2a (`03_rule_compiler.md` Q3, latency-impact table line 107) claimed: *"One primary hash lookup (~25 ns) regardless of choice; secondary checks are register compares… latency-neutral."* That is **only true on the matched-rule fast path** (first map happens to be the primary). It is **not** what the BPF code does on no-match.

What L2 actually does (`layer2.bpf.c:142-197`):
- Lookup 1 — src_mac (always).
- On src_mac miss OR filter_mask fail → Lookup 2 — dst_mac.
- On dst_mac miss/fail → Lookup 3 — ethertype.
- On ethertype miss/fail → Lookup 4 — vlan (only if `has_vlan`).
- On vlan miss/fail → Lookup 5 — pcp (only if `has_vlan`).

Architecture §3.2 (`ARCHITECTURE.md:91`) was right all along: *"4 hash maps в фиксированном порядке (first match wins)"*. The compiler-side "primary by lexical order" model (`rule_compiler.cpp:130-144`) was a **misread by Phase 2a**: the compiler picks *which map* to write each rule into, but the BPF program walks **all five maps** until something hits. The primary choice in the compiler only determines which map carries the rule; on a packet that doesn't match any rule, L2 pays for all five lookups.

Concrete cost (x86_64, native, cache-warm BPF hash):
- Each `bpf_map_lookup_elem` on `BPF_MAP_TYPE_HASH` ≈ 20-30 ns.
- 5 misses on an untagged packet → 3 lookups (src, dst, ethertype) ≈ 60-90 ns.
- 5 misses on a VLAN-tagged packet → 5 lookups ≈ 100-150 ns.
- Plus ~5-10 ns for parse + bounds + generation branches.

**→ Phase 1's "100-125 ns" estimate is essentially correct for the no-match path.** Phase 2a's "register-compares only, 25 ns" is **wrong for the no-match path**, which is the common case on a Gi-side link where most packets transit without matching any L2 rule (operator typically uses L2 for narrow allow/deny sets, the bulk goes through to L3).

The matched-rule path *can* hit on lookup 1 (src_mac) and pay just ~25-30 ns, but only if every L2 rule the operator wrote has src_mac as primary. For a rule that's only `{vlan_id:42}`, the compiler emits a vlan-keyed entry that is the **fourth** map L2 checks → the packet pays 3 prior misses (src, dst, eth) before the vlan hit. Worst-case matched-rule path: ~80-100 ns.

This finding is **new and material**: it reaffirms Phase 1's bottleneck call and refutes Phase 2a's "primary-by-lexical-order is latency-neutral" claim.

### 3. `filter_mask` secondary checks — register-only, ~0 ns each — confirmed

`l2_filters_match` (`layer2.bpf.c:20-35`): reads `rule->filter_mask`; on zero, short-circuits true; otherwise three branched register-compares against `eth_proto`, `vlan_id`, `pcp` — all parsed once before lookup 1 (`:122-140`). No additional map lookups. All three secondary fields are pre-parsed; no re-parse of Ethernet inside the helper.

Note: `filter_mask` covers only ethertype/vlan/pcp. **MACs cannot be secondaries.** A compound rule like `{src_mac:M, dst_mac:N}` would be impossible: the compiler picks src_mac as primary by lexical order (`rule_compiler.cpp:130-144`) and the dst_mac is silently dropped from the rule (no `L2_FILTER_DSTMAC` bit). This is a real correctness gap in the compound-rule model that Phase 2a glossed over. **→ P2 NEW** (operator-visible silent semantic drop).

### 4. Tail-call destination logic — three modes present, fail-mode is DROP

All three modes exist in `handle_l2_action`:
- **Terminal** (`next_layer == 0`): `STAT_PASS_L2` then `XDP_PASS` (`:92-94`).
- **L2 → L3** (`next_layer == LAYER_3_IDX`): `bpf_tail_call(..., LAYER_3_IDX)` (`:74-80`).
- **L2 → L4** (`next_layer == LAYER_4_IDX`): `bpf_tail_call(..., LAYER_4_IDX)` (`:83-89`).

Tail-call fall-through (slot unpopulated) → `STAT_DROP_L2_TAIL` + `XDP_DROP` for the matched-rule case. This matches L3's fail-closed pattern for matched rules (`04_layer3.md` §6).

**The no-match tail-call** (`:200-203`) has **no failure stat for the L3 prog_array missing case specifically** — fall-through increments `STAT_DROP_L2_NO_MATCH` (`:205`). The counter name lies a bit: it says "no L2 rule matched", but it also fires when L3 prog wasn't installed. Combined effect: if L3 prog_array slot were ever unpopulated during a partial deploy, every packet would be charged to `STAT_DROP_L2_NO_MATCH` regardless of whether L2 rules existed. Operator diagnostic confusion. → P2.

### 5. L2 default action — none. Always tail-calls L3 on no match

`layer2.bpf.c:199-208` shows no consultation of `default_action_{0,1}`. If L3 is not installed (extremely unusual) → all unmatched L2 packets drop. With L3 installed (normal deploy) → unmatched L2 packets continue to L3, which may consult its own default. So the "global default action" is effectively an L3/L4 concept; L2 has no default, only "forward to L3".

This is fine but unstated in ARCHITECTURE.md.

### 6. Ethernet parse, VLAN, QinQ — single tag only

- Standard Ethernet: `eth + 1 > data_end` then `eth->h_proto` read.
- 802.1Q (`0x8100`): one-level parse at `:128-140`. Bounds check is `eth + 14 + 4 > data_end` — covers TCI (2B) + inner ethertype (2B). Correct.
- **QinQ (`0x88a8`)**: not handled. Confirmed by `tests/bpf/test_bpf_dataplane.cpp:1048-1082` (`test_l2_qinq_not_parsed`). A QinQ-tagged frame has `h_proto = 0x88a8` which doesn't match the `0x8100` test → `vlan_id` / `pcp` stay 0, `eth_proto` stays 0x88a8 → `l2_ethertype` lookup uses 0x88a8 as key. **The inner VLAN tag is invisible to L2.** An operator with a service-provider VLAN stack (Q-in-Q is common on carrier Gi links) cannot match on the customer VLAN. **→ P1 NEW** for the customer's stated Gi-40-Gbps environment.

Also worth flagging: an inner 802.1Q tag (after one strip) is not recursively parsed. `eth_proto` after the first VLAN strip might be `0x8100` again (double-tagged with both outer + inner using `0x8100/0x8100` for non-standard QinQ). L2 doesn't recurse — the second VLAN's vlan_id never reaches L2 rules.

### 7. PCP extraction — correct mask/shift

`tci_host = bpf_ntohs(*vlan_tci); pcp = (tci_host >> 13) & 0x7;` (`:135-137`). TCI on the wire is u16 in NBO: top 3 bits = PCP, next 1 bit = DEI, low 12 bits = VID. After `ntohs` to host order, PCP sits in bits 15-13 → `>>13 & 0x7` is correct. Mask `0x0FFF` for VID is also correct (`:136`).

**PCP for untagged frames is 0** (initialised at `:124`, never overwritten if `has_vlan == false`). An operator who writes a rule "PCP == 0" can match: (a) tagged frames with PCP=0, AND (b) accidentally untagged frames (since the PCP-lookup branch is gated on `has_vlan` at `:188`, untagged frames don't get a PCP lookup at all). Good — the `has_vlan` gate prevents untagged-frame PCP-0 false positives. Verdict: correct.

### 8. Bounds checks — all present, no off-by-one

- `eth+1 > data_end` (`:105`)
- `meta+1 > data` (`:113`) — `data_meta`-region check, correct direction
- 802.1Q region: `eth + 14 + 4 > data_end` (`:130`) — covers VLAN TCI + inner ethertype

The inner ethertype is read via `*(__u16 *)((unsigned char *)eth + 16)` at `:138`. Offset 16 = 14 (Ethernet) + 2 (TCI), and the bounds check covers up to offset 18, so the 2-byte read at 16 is bounded. Correct.

No dereferences without prior bounds. Verifier-accepted. Clean.

### 9. Endianness — clean, internally consistent

| Field | Source | Stored | Compared against |
|-------|--------|--------|------------------|
| `eth_proto` | `eth->h_proto` NBO | NBO (`:122`, or post-VLAN-strip at `:138`) | `bpf_htons(0x8100)` NBO (`:128`) — OK |
| `vlan_id` | TCI host-order, masked | host (`:136`) | `vlan_key.vlan_id` is host per `common.h:95` — OK |
| `pcp` | TCI host bits 15-13 | host u8 (`:137`) | `pcp_key.pcp` is host u32 per `common.h:121` — OK |
| `src_key.addr` / `dst_key.addr` | wire bytes via memcpy (`:144,155`) | byte-array | `mac_key.addr` is byte-array — OK (no endianness applies to MAC) |
| `ethertype_key.ethertype` | `eth_proto` NBO straight in (`:165`) | NBO | comment on `common.h:89` says NBO — OK |

No endianness bugs. The "primary stored as NBO via htons in compiler / read directly in BPF" pattern from `03_rule_compiler.md` Q6 holds end-to-end.

### 10. Stat increment density on hot path — zero on common success

Common rule-match-and-tail-call-L3 path: **0 STAT_INC** in L2.
- Rule matched in any of 5 lookups: action switch falls through ALLOW → `next_layer == LAYER_3_IDX` → `bpf_tail_call` → no stat fire before the tail.
- Common no-match → tail to L3: **0 STAT_INC** at L2 (`STAT_DROP_L2_NO_MATCH` only fires on tail-call fall-through).

L2 contributes zero stats overhead on the success path. The entire stats budget for the hot pipeline is `STAT_PACKETS_TOTAL` at entry + `STAT_PASS_L4` at L4 = 2 STAT_INC per packet. Matches `05_layer4.md §7`.

Drop/mirror paths fire 1-2 stats. Reasonable.

### 11. Generation indirection — 10 literal map paths

Every lookup uses the `(gen == 0) ? lookup(map_0) : lookup(map_1)` pattern: 5 primary lookups × 2 generations = **10 literal `bpf_map_lookup_elem` call sites** in the verifier's view, plus 2 sites for the no-match tail call. Each pair contributes its own arm; the verifier analyses both. For ~210 LOC source / ~600-800 BPF insns, well under the 1M ceiling, but **L2 is the most verifier-heavy program** in the chain because it has the most maps × 2 generations. Adding a 6th lookup type (e.g. inner-VLAN for QinQ fix) would compound this. Not a bug; envelope.

### 12. Surprises / dead branches

- **`emit_entry` lambda in `rule_compiler.cpp:163-201` is called only with `primary`**, already noted in Phase 2a §additional-finding-4. Confirmed irrelevant to the data plane.
- **`STAT_DROP_L2_NO_MATCH` is named misleadingly** — also fires on tail-call-to-L3 failure (`:205-207`), conflating two failure causes. P2 doc/rename.
- **`STAT_DROP_L2_TAIL` (`:79,88`)** fires only on matched-rule-but-tail-failed. Symmetric to L3's matched-rule fail-DROP pattern. Good.
- **No DROP for malformed 802.1Q with too-short data**: `:130` does drop with `STAT_DROP_L2_BOUNDS`. Good.
- **Compound rule with only MACs is impossible** — see Q3 above; `{src_mac:M, dst_mac:N}` silently becomes `{src_mac:M}` because filter_mask has no MAC bits. P2 NEW.
- **The `l2_filters_match` short-circuit `if (!mask) return true` (`:25-27`)** means a single-field rule (filter_mask=0) always passes the secondary check. Correct semantics for back-compat with non-compound rules, but it means a rule like `{src_mac:M}` with `next_layer=L3` will fire on every packet from M regardless of context. By design.

### 13. 40 Gbps reviewer perspective — L2 IS the bottleneck Phase 1 said it was

**Refined latency model:**

| Path | Lookups | Cost estimate |
|------|---------|---------------|
| **Worst no-match (VLAN-tagged)** | 5 (src, dst, eth, vlan, pcp) | ~100-150 ns |
| **Common no-match (untagged)** | 3 (src, dst, eth — vlan/pcp gated on has_vlan) | ~60-90 ns |
| **Match on src_mac (lookup 1)** | 1 + register compares | ~25-35 ns |
| **Match on vlan (lookup 4, tagged)** | 4 (src,dst,eth all miss; vlan hits) | ~80-110 ns |
| **Match on pcp (lookup 5, tagged)** | 5 (src,dst,eth,vlan all miss; pcp hits) | ~100-140 ns |

Phase 1's 100-125 ns estimate is **accurate for the no-match VLAN case**, optimistic for the no-match untagged case (~60-90 ns), and pessimistic for first-lookup matches.

**Pipeline budget recap at 40 Gbps, 1024 B average → 205 ns/packet.** Common-case combined L2 (60-90 ns no-match) + L3 (~50-80 ns matched) + L4 (~45-55 ns matched-allow) = **~155-225 ns**. The pipeline is in budget for the median packet, but **VLAN-tagged no-match packets bust it** (5 L2 lookups + L3 + L4 ≈ 200-280 ns).

For carrier Gi traffic, **VLAN tagging is the norm, not the exception**. The Phase 1 conclusion stands: **L2 is the structural bottleneck**, and the structural reason is the linear search across 5 distinct maps.

**Largest available correctness-preserving optimisation:**

The L2 walk should be replaced with a **dispatch on a per-rule primary-type field** — what Phase 2a thought was already there. Concretely:
- Have entry stamp `pkt_meta.l2_primary_hint` based on the deploy's actual primary distribution (or fix the primary-type at compile time and dispatch on it).
- OR: collapse all 5 L2 maps into one `BPF_MAP_TYPE_HASH` keyed by `(match_type, key_bytes)` with a tag — single lookup per packet, ~25 ns.
- OR: re-architect L2 to do **one lookup, the most-selective one chosen by the compiler**, and rely on `filter_mask` to handle the rest (which is what `03_rule_compiler.md` thought the design was). This would cut L2 latency by **~50-100 ns** on the no-match path.

Any of these would save ~50% of L2 latency. None changes correctness if filter_mask is extended to cover all five field types (i.e., add `L2_FILTER_SRCMAC`/`L2_FILTER_DSTMAC` bits and compare 6 bytes inline — still register-only).

## Additional findings

- **L2 compound rules with two MAC fields are silently degraded** (see Q3). `filter_mask` covers only ethertype/vlan/pcp; the compiler picks the lexically-first MAC field as primary and discards the other. → P2 NEW.
- **`STAT_PASS_L2`** fires only on terminal ALLOW/MIRROR-with-no-next-layer (`:93`). Mirror-terminal also fires `STAT_MIRROR` at `:63` — same double-count semantic as L3 had (`04_layer3.md` Q2). Counter-naming issue, not a bug. P2.
- **No byte counter**: as Phase 1 P0 globally. Each `STAT_INC` is packets only.
- **No log/audit per matched rule**: confirmed for L2 as well.
- **The `has_vlan` gate on lookups 4 and 5** (`:176, :188`) means an operator's PCP rule never matches an untagged packet. By design — but also means an attacker who wants to evade a PCP-based rate-limit can send untagged frames if the upstream tolerates them. Edge case, P2 doc.

## Latency analysis (per-packet cost)

**L2 itself, x86_64 native, cache-warm:**

| Step | Cost |
|------|------|
| Eth + meta bounds | ~1 ns |
| 802.1Q parse (if applicable) | ~2 ns |
| Per hash lookup (HASH map miss) | ~20-30 ns |
| Per hash lookup (HASH map hit) | ~25-35 ns |
| `l2_filters_match` (filter_mask=0) | ~0 ns |
| `l2_filters_match` (filter_mask=7) | ~2 ns (3 compares) |
| `bpf_tail_call` to next layer | ~15-25 ns |
| Generation if/else | ~1 ns |
| **Common no-match untagged (3 lookups + tail to L3)** | **~65-100 ns** |
| **Common no-match VLAN-tagged (5 lookups + tail to L3)** | **~110-160 ns** |
| **First-lookup match (src_mac) + tail to L3** | **~40-60 ns** |
| **Last-lookup match (pcp, tagged) + tail to L3** | **~125-180 ns** |

**Refined pipeline numbers (combining 04 + 05 + this):**

| Pipeline path | L2 | L3 | L4 | Total |
|---------------|----|----|----|-------|
| Untagged TCP, no-L2-match, L3-rule-allow-with-L4, L4-rule-allow | 65-100 | 50-80 | 45-55 | **160-235 ns** |
| VLAN-tagged TCP, no-L2-match, same downstream | 110-160 | 50-80 | 45-55 | **205-295 ns** |
| VLAN+L2-vlan-rule match (terminal at L2) | 80-110 | 0 | 0 | **80-110 ns** |
| Adversarial IPv6 5-ext-header bypass on VLAN-tagged frame | 110-160 | ~55-100 | ~70-90 | **235-350 ns** |

The 205 ns/pkt budget at 40 Gbps / 1024 B is **violated for VLAN-tagged Gi traffic on a single core** in the no-match-at-L2 case. Multi-core RSS spreading hides this on average packet sizes ≥ ~1200 B; at the worst-case 1024-B-avg the operator needs ≥ 2 cores in lockstep just to absorb L2.

**The Phase 1 estimate (100-125 ns at L2) was for VLAN-tagged no-match, which is the common Gi case.** Confirmed correct. **The Phase 2a refinement to "25 ns" was wrong** and needs to be retracted in the consolidated 99_REPORT.

## Findings (graded)

```
- [P1 NEW — PHASE 2a CORRECTION] L2 actually performs up to 5 sequential hash lookups per packet, not 1
  Where: bpf/layer2.bpf.c:142-197 vs 03_rule_compiler.md Q3 / latency-impact table
  What: Phase 2a (rule_compiler review) claimed L2 does "one primary hash lookup + register-only
        secondary compares" because the compiler picks a primary by lexical order. The BPF code
        walks ALL FIVE maps (src_mac → dst_mac → ethertype → vlan → pcp) on no-match, performing
        up to 5 hash lookups per packet. The compiler's "primary" choice only determines which
        map carries each rule; the BPF program is a linear search across all maps.
  Why it matters: Phase 1's 100-125 ns L2 estimate stands. Phase 2a's "L2 is latency-neutral"
        framing is wrong and would mislead the consolidated report. For a 40 Gbps Gi link at
        1024 B average, VLAN-tagged no-match packets pay ~110-160 ns at L2 alone — half the
        205-ns/packet single-core budget burned before L3 is reached.
  Suggested action: (1) Update 99_REPORT to retract the Phase 2a latency model. (2) Refactor
        L2 to a single dispatch lookup: either (a) compiler picks primary field via per-rule
        hint and BPF reads only that map (requires extending filter_mask to cover src_mac and
        dst_mac), or (b) collapse 5 maps into 1 keyed by (type, bytes). Either cuts L2 latency
        by ~50-100 ns on no-match. Correctness-preserving.

- [P1 NEW] L2 silently drops the dst_mac half of {src_mac, dst_mac} compound rules
  Where: bpf/common.h:103-105 (filter_mask bits ETHERTYPE/VLAN/PCP only — no SRCMAC/DSTMAC);
         src/compiler/rule_compiler.cpp:130-144 (picks src_mac as primary if both present);
         bpf/layer2.bpf.c:20-35 (l2_filters_match doesn't compare MACs)
  What: A rule `{src_mac: M, dst_mac: N}` compiles to a single entry in l2_src_mac_* keyed by
        M, with filter_mask containing zero MAC bits. At runtime the rule fires for ANY packet
        with src_mac == M regardless of dst_mac. The dst_mac restriction is silently dropped.
        Same applies to {dst_mac, src_mac} where dst_mac wins by being primary, src_mac
        ignored.
  Why it matters: Compound rules are a documented L2 feature (CONFIG.md). Operator writes a
        narrow rule, gets a wider one. On a Gi-side filter this is a quieter version of the
        dst_ip P0: rule applies broader than intent, but at least it doesn't catch the
        whole wire.
  Suggested action: Either (1) reject {src_mac, dst_mac} compound rules in the validator with
        "L2 compound rules can use at most one MAC field plus any of ethertype/vlan/pcp", or
        (2) add L2_FILTER_SRCMAC / L2_FILTER_DSTMAC bits + 6-byte memcmp in l2_filters_match.
        Option (1) is the quick fix; option (2) is the proper fix and pairs naturally with
        the P1 above (single-lookup dispatch).

- [P1 NEW] QinQ (0x88a8) ignored: customer-VLAN invisible to L2 on service-provider stacks
  Where: bpf/layer2.bpf.c:128 (checks only 0x8100), tests/bpf/test_bpf_dataplane.cpp:1048-1082
  What: An 802.1ad QinQ-tagged frame has outer h_proto=0x88a8. L2's VLAN parser tests only for
        0x8100, so vlan_id and pcp stay 0; eth_proto stays 0x88a8. An operator wanting to
        match on the customer VLAN (the inner tag) cannot. Also nested 0x8100/0x8100 frames
        are not recursively stripped.
  Why it matters: The customer brief is a Gi-side 40 Gbps filter — carrier Gi commonly carries
        QinQ from upstream aggregation. A VLAN-based rule may simply fail to fire on real
        production traffic, with no diagnostic. Combined with the no-match-at-L2 latency
        cost above, traffic also pays the 5-lookup penalty.
  Suggested action: Parse outer 0x88a8 (or any of {0x8100, 0x88a8, 0x9100}) as outer VLAN,
        then recurse one level on 0x8100. Tests already cover the un-parsed case
        (test_l2_qinq_not_parsed asserts the current behaviour as DROP-via-L3). Either fix
        the parse or document the limitation in CONFIG.md.

- [P2 NEW] STAT_DROP_L2_NO_MATCH conflates "no rule matched" with "tail-call to L3 failed"
  Where: bpf/layer2.bpf.c:199-207
  What: The unconditional tail-call-to-L3 on no-match falls through and increments
        STAT_DROP_L2_NO_MATCH whether the cause was "no L2 rule" (with L3 missing — abnormal)
        or "L3 prog_array unpopulated" (rare). Operator can't distinguish "no L2 rules
        configured" from "L3 program failed to load".
  Suggested action: Add STAT_DROP_L2_NO_L3_PROG (or repurpose STAT_DROP_L2_TAIL for both
        matched and unmatched tail-call failures) and reserve STAT_DROP_L2_NO_MATCH for
        the "L3 ran but didn't pass" semantic via a different aggregation.

- [P2 NEW] L2 has no default-action concept; semantically tied to L3 being installed
  Where: bpf/layer2.bpf.c:199-203 (always tail-calls L3; never reads default_action_{0,1})
  What: ARCHITECTURE.md treats default_action as a global concept; in fact L2 cannot apply
        it. If an operator imagines "default=DROP" should fire at L2 when no L2 rule matches,
        they are wrong — L2 will tail-call L3, and L3 will eventually consult default. Subtle
        but undocumented.
  Suggested action: Document in ARCHITECTURE.md §3.2 that L2 is non-terminal-by-default and
        the "global default" semantically lives at L3/L4.

- [P2 NEW] L2 verifier-complexity surface is the heaviest in the chain
  Where: bpf/layer2.bpf.c:146-203 (5 paired generation-dispatch lookups + 1 tail-call pair)
  What: 10 literal bpf_map_lookup_elem call sites + 2 tail-call sites; verifier analyses both
        generation arms for each. Not a bug; flagging because any new L2 feature (inner VLAN,
        MAC-pair compound, new match field) compounds this. The 1M-instruction ceiling is far
        but the doubling is structural.
  Suggested action: When refactoring (per P1 above), prefer the single-lookup-with-dispatch
        approach over adding more parallel maps.
```

## Test-audit notes

- **P1 NEW — five-lookup latency vs Phase 2a's one-lookup claim**: no benchmark exists that measures the no-match L2 path specifically. The published ARCHITECTURE.md table has "L2 MAC drop = 76 ns" — which is the rule-match-on-src_mac (one lookup) path, the best case. The no-match path that an L3-only deploy serves on every packet is **not** in the table. **Test class: benchmark coverage absent for the common-case latency.** Adding a no-match-VLAN-tagged BPF_PROG_TEST_RUN measurement would have caught this.
- **P1 NEW — silent MAC-pair drop**: a unit test `{src_mac:M, dst_mac:N}` rule, then assert that packets with `src_mac=M, dst_mac=X (≠N)` are NOT matched, would surface this. `tests/test_rule_compiler_edge.cpp` has compound-rule tests (filter_mask asserts at lines 1265-1565) but none constructs a MAC-pair rule. **Test class: test absent**.
- **P1 NEW — QinQ ignore**: `tests/bpf/test_bpf_dataplane.cpp:1048-1082` exists and **asserts the bug as the contract** ("QinQ not parsed → L3 → non-IPv4 → DROP"). This is **worst-class test gap**: a test that locks in the wrong behaviour. Operator reading the test thinks QinQ-drop is intentional; in fact it's an unimplemented feature. **Test class: wrong test exists / false safety**.
- **P2 NEW — STAT_DROP_L2_NO_MATCH overloaded**: a test with a deliberately unpopulated L3 prog_array would surface the dual-meaning. Not in `test_bpf_dataplane.cpp`.
- **P2 NEW — L2 no default-action**: a config test that sets `default_behavior=DROP` and an unmatched packet, asserting it drops at L2, would expose the actual L2-tail-to-L3 behaviour. Probably no such test (the test would currently fail because L3 consults default).

## Open issues

- **L2 latency optimisation requires coordinated compiler + BPF change.** Phase 2a's "primary by lexical order" idea was correct as an *aspiration*, just not implemented in the BPF. Implementing single-lookup-with-dispatch would shift work from per-packet hash to per-rule compile, and the compiler is already set up for it (`L2MatchType primary` at `rule_compiler.cpp:132` is exactly the dispatch hint). The BPF program would need: (a) read primary type from `pkt_meta` (stamped where? — needs a per-active-config map, or a fixed-per-rule field), and (b) one lookup against the indicated map. Phase 4 (consolidated report) should treat this as a coherent single workstream.
- **Per-CPU contention on L2 maps under multi-queue.** All L2 maps are `BPF_MAP_TYPE_HASH` (not per-CPU). At 40 Gbps with 8+ RSS-distributed cores, contention on the global hash is a real concern that PROG_TEST_RUN does not measure. Phase 3 (cross-cutting perf) territory.
- **Eth re-parse across L2/L3/L4** is still on the table as a 2-3 ns/packet × 3-layer optimisation (`04_layer3.md` §11 last bullet). On VLAN packets it's worse because each layer re-walks the 802.1Q tag. Recording `l2_off` + `l3_off` in `pkt_meta` at entry would save ~5-10 ns per packet on the common chain-through path.
- **QinQ fix in L2** is a 1-3 day change including tests; **must verify ARCHITECTURE.md `§3.2` line 110 says "QinQ (0x88a8) не парсится"** so the doc-side is already self-aware (it is — confirmed). The bug is "implementation matches doc, doc matches design intent, but customer environment needs more". Owner-decision required (implement vs explicitly limit-and-warn).
