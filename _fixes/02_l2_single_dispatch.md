# 02 — L2 single-dispatch lookup

## Motivation

Closes the biggest single performance loss in the data plane plus two structural L2 bugs (`_review/99_REPORT.md` recommendation #10, P1 #2, #3, #9):

- **P1 #2** — `bpf/layer2.bpf.c:142-197` performs up to 5 sequential hash lookups per packet (src_mac, dst_mac, ethertype, vlan, pcp). On VLAN-tagged no-match traffic — the carrier-Gi-typical case — L2 costs 110–160 ns. Path-4 from the consolidated envelope (VLAN-tagged TCP allow) is 300 ns total, **outside the 205 ns/packet budget on a single core**.
- **P1 #3** — `filter_mask` (`bpf/common.h:103-105`) has no SRCMAC/DSTMAC bits, so a compound rule `{src_mac, dst_mac}` silently keeps only the primary MAC and drops the other. Two-MAC restrictions match wider than written.
- **P1 #9** — primary key choice is hard-coded by lexical order (src_mac > dst_mac > vlan_id > ethertype > pcp); two compound rules sharing the lexically-first field collide and the second one is rejected.

The three are symptoms of one structural fact: **the L2 rule table is shaped as five independent maps**, queried sequentially. A composite-key design queries once (or a small bounded number of times) and unifies the filter_mask vocabulary.

> **Honest framing.** A true 1-lookup-per-packet design is not achievable for the current rule shape — different rules constrain different field combinations, and a single hash key cannot match wildcards. The realistic goal is **bounded dispatch by active filter-mask set**: typically 2–3 lookups, never more than N (compile-time cap), with most-specific matching first. "Single-dispatch" in the report title is aspirational; this design ships the achievable savings (~50–75 ns/packet typical).

## Decision

Three load-bearing structural moves, landed together.

1. **One composite L2 key, one composite L2 map per generation.** Replace `l2_src_mac_{0,1}`, `l2_dst_mac_{0,1}`, `l2_ethertype_{0,1}`, `l2_vlan_{0,1}`, `l2_pcp_{0,1}` (10 maps total) with `l2_rules_{0,1}` (2 maps total). Key:
   ```c
   struct l2_key {
       __u8   filter_mask;   /* bits: SRC_MAC|DST_MAC|VLAN|ETHERTYPE|PCP */
       __u8   pcp;
       __be16 ethertype;
       __u16  vlan_id;       /* host byte order */
       __u8   src_mac[6];
       __u8   dst_mac[6];
   };  /* 18 bytes, padded to 20 */
   ```
   Fields not in the rule's filter_mask are stored as zero. Compiler emits one entry per rule.

2. **Extended `filter_mask` vocabulary.** Add `FILTER_MASK_SRCMAC` and `FILTER_MASK_DSTMAC` bits (closes P1 #3). Filter mask becomes the single authoritative description of which fields a rule constrains; compiler and BPF agree on it byte-for-byte.

3. **Bounded dispatch through active-mask set.** Compiler computes the set of distinct filter-mask values actually present in the deployed ruleset and writes them to a per-generation `l2_active_masks_{0,1}` array (max 8 entries; `MAX_L2_MASKS = 8`). BPF iterates this array with `#pragma unroll for (int i = 0; i < MAX_L2_MASKS; i++)`, builds the lookup key for each mask by projecting the parsed packet through the mask (zeroing out non-constrained fields), and stops on first hit. Iteration order is **most-specific-mask first** (highest popcount of filter_mask bits), so a `{src_mac, dst_mac, vlan}` rule wins over a `{src_mac}` rule on a packet that matches both.

## Alternatives considered

- **True single-lookup composite key.** Cost: requires the hash to match arbitrary subsets of fields. No standard BPF map type supports that. Rejected: would require a userspace-managed bloom + secondary scan, more LOC than the current design saves.
- **LPM-trie on the composite key.** Cost: LPM does prefix matching, not bitset matching; the L2 fields aren't prefix-orderable. Rejected: wrong tool.
- **Per-mask `HASH` map, one per active mask.** Same idea as the design here but with one BPF map per mask. Cost: map FD overhead, generation-swap complexity. Rejected: the active-mask array is cheaper and the iteration cost is identical (unrolled in either case).
- **Keep the current 5-map design, add SRCMAC/DSTMAC filter_mask bits, fix primary-key selection.** Cost: minimal. Benefit: closes P1 #3 and P1 #9 without touching latency. Rejected for the perf-focused workstream: doesn't move P1 #2 at all. Still a viable fallback if the composite-key redesign turns out riskier than expected — call it "Plan B" and revisit if implementation hits an unforeseen verifier wall.

## Implementation steps

Each step buildable; the redesign is necessarily one atomic commit (BPF, compiler, maps, tests) once started, but the structural prep can stage.

1. **`bpf/common.h`** — define new key shape and extended filter_mask bits:
   ```c
   #define FILTER_MASK_SRCMAC    0x01
   #define FILTER_MASK_DSTMAC    0x02
   #define FILTER_MASK_VLAN      0x04
   #define FILTER_MASK_ETHERTYPE 0x08
   #define FILTER_MASK_PCP       0x10

   struct l2_key {
       __u8   filter_mask;
       __u8   pcp;
       __be16 ethertype;
       __u16  vlan_id;
       __u8   src_mac[6];
       __u8   dst_mac[6];
       __u8   _pad[2];        /* explicit padding to 20 bytes, stable layout */
   };

   #define MAX_L2_MASKS 8
   ```
   Update `tests/test_byte_layout.cpp` with the new offsets.

2. **`bpf/maps.h`** — drop the five per-field L2 maps, add the composite map and the active-mask array:
   ```c
   /* per generation */
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __type(key, struct l2_key);
       __type(value, struct l2_rule);
       __uint(max_entries, MAX_L2_ENTRIES);  /* sum of old MAX_MAC + MAX_VLAN + ... */
   } l2_rules_0 SEC(".maps"), l2_rules_1 SEC(".maps");

   struct {
       __uint(type, BPF_MAP_TYPE_ARRAY);
       __type(key, __u32);
       __type(value, __u8);   /* filter_mask value */
       __uint(max_entries, MAX_L2_MASKS);
   } l2_active_masks_0 SEC(".maps"), l2_active_masks_1 SEC(".maps");
   ```
   Old per-field maps removed entirely; `MAX_MAC_ENTRIES` / `MAX_VLAN_ENTRIES` / etc. consolidated into `MAX_L2_ENTRIES` (sum of typical worst-cases, ~4096 for now; revisit on real traffic).

3. **`src/compiler/rule_compiler.cpp`** — single L2 compile loop replaces the per-primary-field branches. Algorithm:
   ```
   for each rule in pipeline.layer_2:
       compute filter_mask from which match fields are present
       reject if filter_mask == 0 (mirror of L2 match-count guard at validator)
       build l2_key projecting present fields, zero elsewhere
       emit CompiledL2Rule { key, rule_value }
       record filter_mask in active_masks set

   active_masks: sort by popcount desc; truncate to MAX_L2_MASKS;
   if more than MAX_L2_MASKS distinct masks → reject deploy with clear error.

   collision check: for each (filter_mask, key) pair, error on duplicate rule_id
                    (mirror of today's per-map collision detection)
   ```
   The lexical-order "primary by selectivity" comment block at lines 130-202 is deleted; compound rules just emit a multi-bit filter_mask. Closes P1 #9.

4. **`bpf/layer2.bpf.c`** — replace the five sequential hash lookups with the iterated active-mask dispatch:
   ```c
   /* parse Ethernet + optional VLAN/Q-tag once; populate packet_fields */
   struct l2_packet_fields p;
   parse_l2(ctx, &p);   /* fills src/dst MAC, ethertype, vlan_id, pcp */

   #pragma unroll
   for (__u32 i = 0; i < MAX_L2_MASKS; i++) {
       __u8 *mask = bpf_map_lookup_elem(active_masks_for(meta->generation), &i);
       if (!mask || *mask == 0) break;     /* end of active set */

       struct l2_key key = {0};
       key.filter_mask = *mask;
       if (*mask & FILTER_MASK_SRCMAC)    __builtin_memcpy(key.src_mac, p.src_mac, 6);
       if (*mask & FILTER_MASK_DSTMAC)    __builtin_memcpy(key.dst_mac, p.dst_mac, 6);
       if (*mask & FILTER_MASK_ETHERTYPE) key.ethertype = p.ethertype;
       if (*mask & FILTER_MASK_VLAN)      key.vlan_id   = p.vlan_id;
       if (*mask & FILTER_MASK_PCP)       key.pcp       = p.pcp;

       struct l2_rule *r = bpf_map_lookup_elem(l2_rules_for(meta->generation), &key);
       if (r) return handle_l2_action(ctx, meta, r);
   }
   /* no L2 rule matched → tail-call L3 (unchanged) */
   ```
   The `parse_l2` helper is also load-bearing: it should bound-check Ethernet once, handle Q-tag (0x8100) extraction, and stamp `p.vlan_id = 0` and `p.pcp = 0` for untagged frames. **QinQ (0x88a8) handling is still out of scope** (P1 #4) — keep `parse_l2` v0 untagged + single Q-tag aware; add a TODO comment naming the QinQ design as a follow-up.

5. **`src/pipeline/generation_manager.cpp`** — update the prepare/commit path:
   - `populate_l2_rules`: writes the composite `l2_rules_{gen}` map.
   - `populate_l2_active_masks`: new function, populates the array. On commit, both must be ready before `gen_config[0]` flips.
   - `clear_shadow_maps`: drop the old per-field L2 clear logic; add the two new maps.

6. **`src/config/config_validator.cpp`** — add the L2 deploy-time cap check: if the compiled rules surface more than `MAX_L2_MASKS` distinct filter masks, fail with a clear "too many distinct L2 field combinations" error. Cleaner here than at the BPF map level.

7. **Tests** — both new and refactored:
   - `test_l2_byte_layout` — verifies new `l2_key` offsets match BPF.
   - Existing `test_l2_*` — rewrite to use the composite map (no functional change in behaviour; just storage shape). All should pass.
   - New `test_l2_compound_src_and_dst_mac` — two rules both setting src_mac AND dst_mac with different values, asserts both compile and both match their respective packets. Closes P1 #3 directly.
   - New `test_l2_compound_same_primary_field` — two rules both starting with ethertype IPv4 but different VLANs, asserts both compile (P1 #9 fix).
   - New `test_l2_too_many_masks_rejected` — deploy with 9 distinct filter masks, asserts validator rejects.
   - Benchmark `bench_l2_lookup` — measure new vs old via `BPF_PROG_TEST_RUN`. Target: ≥30% reduction on the VLAN-tagged no-match path. Numbers go into the commit message.

## Acceptance criteria

The fix lands only when all of these are green **in CI** (so prereq: recommendation #1 from `99_REPORT.md` must land first).

- All existing L2 functional tests pass with the composite map.
- New compound-rule tests above pass (P1 #3 and P1 #9 closed observably).
- `bench_l2_lookup` shows: untagged no-match ≥40 ns saved; VLAN-tagged no-match ≥60 ns saved (per Phase 2c estimates; ~50% improvement). If measured savings fall below 30%, **stop and revisit** — the design assumption is wrong somewhere.
- BPF verifier accepts on target kernels (5.15 LTS minimum).
- Updated `02_architecture.md` table (the one with map counts) — refresh per Appendix-A note in the final report.

## Migration / rollout

- `pkt_meta` layout: untouched. Only the L2 map shape changes.
- Generation-swap: works because all L2 maps are per-generation; old and new co-exist during prepare/commit transition.
- Compiler `rule_id` stability: the new composite design **changes which map a rule lives in**, so rule_ids may legitimately shift between the old and new compiler. This matters mainly for the rate_state_map P1 (#7) — but L2 rules don't currently use rate-limit, so the interaction is empty.
- Single PR. Atomic. Co-ordinate with the existing test suite: the BPF dataplane tests (`tests/bpf/test_bpf_dataplane.cpp`) reference today's `l2_src_mac` etc. by name — they must be edited in the same commit. `test_l2_qinq_not_parsed` (the anti-pattern test from P1 #4) is unaffected by this fix and stays as-is; remediation belongs in the QinQ follow-up design.

## What this does not fix

- **QinQ (0x88a8) parsing** — P1 #4. Separate design; the new `parse_l2` helper should leave a clean attachment point (one branch on `eth->h_proto`).
- **The map-size limit `MAX_L2_ENTRIES`** is set as a typical worst-case (sum of today's per-field caps). The real number depends on rule cardinality; revisit after live testing.
- **L2 verifier complexity.** With `MAX_L2_MASKS = 8` unrolled iterations plus the per-field memcpy chains, the verifier-instruction count grows. Should fit comfortably under 1M, but if a future kernel tightens the limit, raise it via `bpf_loop` (kernel ≥5.17) instead of `#pragma unroll`. Documented as a follow-up risk.
- **The IPv4-only L3 default-action arm naming concern** (P2 from Phase 2b) — unrelated, separate cleanup.

## Open questions for the owner before implementation

1. **`MAX_L2_MASKS = 8`.** Picked off the top of the head — eight distinct filter-mask values is more than any plausible config I've seen, but if production hits this in practice the deploy fails ugly. Increase to 16? Make it a CMake option? My default: 8, and revisit on the first deploy that hits the cap.
2. **`MAX_L2_ENTRIES` value.** Sum of today's per-field caps is `4096 + 4096 + 64 + 4096 + 8 = 12,360`. Round to 16,384? Or pick a value driven by the largest deployed config? My default: 16,384 (round to power of two, fits comfortably in the BPF map size limits).
3. **Plan B fallback.** If the composite-key design hits an unexpected verifier wall on the target kernel during implementation, the smaller-scope alternative ("keep 5 maps, fix filter_mask vocabulary, fix primary-key selection") closes P1 #3 and P1 #9 without the perf win. Worth keeping Plan B in mind, or commit to the full redesign? My read: commit to the full redesign; verifier complexity is well within bounds for 8-iteration unrolled lookups.
4. **`parse_l2` helper placement.** Goes in `bpf/common.h` (header-only inline) or `bpf/layer2.bpf.c` (program-local static)? Inline helper is reusable if L3/L4 ever needs the same parse, but bloats every BPF object. My default: header-only inline, marked `static __always_inline`; revisit if BPF binary size becomes an issue.

## Resolutions (owner sign-off, 2026-05-11)

1. `MAX_L2_MASKS = 8`. Confirmed default; revisit on first cap-hit.
2. `MAX_L2_ENTRIES = 16384`. Power-of-two, headroom over current 12,360 sum.
3. Full redesign, no Plan B. Verifier complexity expected to fit; if it doesn't, escalate at implementation rather than pre-emptively scoping down.
4. `parse_l2` is header-only `static __always_inline` in `bpf/common.h`.
