# 01 — IPv6 as a class

## Motivation

Closes three findings that share one root cause (`_review/99_REPORT.md` Class 1):

- **P0-03** — `bpf/tc_ingress.bpf.c` hard-codes IPv4 byte offsets in the TAG path with no IP-family gate; an IPv6 packet matching a tag rule gets its Flow Label mangled and source-address bytes overwritten by `bpf_l3_csum_replace`.
- **P0-04** — `bpf/layer4.bpf.c` walks at most 4 extension headers; a chain of 5+ leaves `nhdr` as an ext-header value, falls into the non-TCP/UDP arm, consults default action — all L4 rules and rate-limit silently bypassed.
- **P1 #8** — `bpf/layer3.bpf.c` only checks immediate `ip6h->nexthdr == 44`; a Hop-by-Hop → Fragment chain hides the Fragment header and bypasses fragment-drop on L3-terminal ALLOW rules.

Each was added as a separate IPv6 arm without a shared structural contract. The pattern propagates: every new feature that touches packets will repeat one of these mistakes unless we lift IPv6-awareness into the data-plane skeleton.

## Decision

Three load-bearing structural moves, landed together:

1. **Add `u8 ip_family` to `pkt_meta`** (in `bpf/common.h`). Stamped exactly once, by **L3 entry** (`bpf/layer3.bpf.c`), immediately after the `eth_proto` family branch — either `IP_FAMILY_V4` or `IP_FAMILY_V6` (new enum in `common.h`, values `4` and `6` for self-documentation). All downstream code reads `meta->ip_family` instead of re-parsing Ethernet.

2. **L4 IPv6 ext-header walker fails closed at depth bound.** If the unrolled 4-iteration walk (`bpf/layer4.bpf.c:151-185`) exits with `nhdr` still in `{0, 43, 60}` (an ext-header type), the packet is dropped with a new counter `STAT_DROP_L4_V6_EXT_DEPTH`. The depth bound stays at 4 (legitimate IPv6 traffic uses ≤3 ext headers; raising it adds verifier cost for no real-world benefit). Fragment detection moves **inside** the loop so it fires for any chain depth, not only at position-1.

3. **TC ingress action sites gate on `meta->ip_family`.** `bpf/tc_ingress.bpf.c` TAG path:
   - If `ip_family == IP_FAMILY_V4`: existing IPv4 TOS rewrite + `bpf_l3_csum_replace` (unchanged).
   - If `ip_family == IP_FAMILY_V6`: stub that increments `STAT_TC_TAG_V6_UNIMPL` and skips. Real IPv6 Traffic-Class rewrite is **out of scope** for this fix — it's a separate compile-time helper (different byte offsets, no checksum to fix in v6). The point of this design is to **stop the corruption** today; implementing v6 rewrite is later work.
   - Mirror path is unchanged (`bpf_clone_redirect` is family-agnostic).

## Alternatives considered

- **Re-parse Ethernet at every action site.** Cost: ~2-3 ns per call, ~3 sites = ~6-9 ns/packet. Risk: same as today — if the next maintainer adds an action site and forgets the family check, the bug returns. Rejected: brittle, doesn't enforce.
- **Reuse the dead `pkt_meta.redirect_ifindex` field** (P2 from the review) for `ip_family`. Cost: 0 bytes; saves a struct slot. Risk: `redirect_ifindex` is a u32; using its low byte for a u8 means the next person to revive `redirect_ifindex` for actual redirects fights us. Rejected: clean break is cheaper than the layout interaction.
- **`__attribute__((sentinel))` macro at action sites** like `BPF_V4_V6_DISPATCH(meta, stmt_v4, stmt_v6)`. Cost: macro hygiene, conditional execution. Benefit: linter can flag bare `0x0800` / `0x86DD` literals outside the macro. Rejected for now: macro adds noise for two-line action gates; keep simple `if (meta->ip_family == IP_FAMILY_V6) { ... } else { ... }` and lint via grep in CI later if drift returns.
- **Raise ext-header bound to 8.** Cost: 4 more verifier-unrolled iterations, ~5-10 ns. Benefit: fewer false drops on pathological-but-legitimate traffic. Rejected: zero real traffic in carrier Gi uses 5+ ext headers; fail-closed at 4 is security-correct, raising bound just delays the cliff.

## Implementation steps

Each step leaves the tree buildable.

1. **`bpf/common.h`** — add:
   ```c
   #define IP_FAMILY_V4 4
   #define IP_FAMILY_V6 6

   struct pkt_meta {
       /* ... existing fields ... */
       __u8 ip_family;   /* IP_FAMILY_V4 or IP_FAMILY_V6, stamped by L3 */
       /* keep redirect_ifindex for now; separate P2 to remove */
   };

   /* new stat slots */
   STAT_DROP_L4_V6_EXT_DEPTH,
   STAT_TC_TAG_V6_UNIMPL,
   ```
   Update `STAT__MAX` accordingly. Update `tests/test_byte_layout.cpp` to match new offsets.

2. **`bpf/layer3.bpf.c`** — stamp the field. Two sites:
   ```c
   if (eth_proto == bpf_htons(ETH_P_IP)) {
       meta->ip_family = IP_FAMILY_V4;
       /* existing v4 path */
   } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
       meta->ip_family = IP_FAMILY_V6;
       /* existing v6 path */
   }
   ```
   Also add the Hop-by-Hop ext-header walker for fragment detection (mirror of L4's walker, 4 iterations, fail-closed). On exit with `nhdr == 44` → drop with existing `STAT_DROP_L3_V6_FRAGMENT`. On exit with `nhdr` still in `{0, 43, 60}` → drop with `STAT_DROP_L3_V6_EXT_DEPTH` (also new). Closes P1 #8.

3. **`bpf/layer4.bpf.c`** — change the post-loop arm:
   ```c
   #pragma unroll
   for (int i = 0; i < 4; i++) {
       if (nhdr == 44) {
           STAT_INC(STAT_DROP_L4_V6_FRAGMENT);
           return XDP_DROP;
       }
       if (nhdr != 0 && nhdr != 43 && nhdr != 60) break;
       /* existing advance */
   }
   if (nhdr == 0 || nhdr == 43 || nhdr == 60) {
       STAT_INC(STAT_DROP_L4_V6_EXT_DEPTH);
       return XDP_DROP;
   }
   /* now nhdr is the real transport protocol */
   ```
   Closes P0-04.

4. **`bpf/tc_ingress.bpf.c`** — gate the TAG path:
   ```c
   if (meta->action_flags & (1 << ACT_TAG)) {
       if (meta->ip_family == IP_FAMILY_V4) {
           /* existing IPv4 TOS rewrite + bpf_l3_csum_replace */
       } else if (meta->ip_family == IP_FAMILY_V6) {
           STAT_INC(STAT_TC_TAG_V6_UNIMPL);
           /* skip — leave packet alone */
       }
   }
   ```
   Closes P0-03 (no more corruption; the v6 packet is delivered intact with the TAG silently no-op'd until v6 rewrite lands).

5. **Documentation:**
   - `CONFIG.md`: under `tag` action, add "IPv6 traffic-class rewrite is not yet supported; tag rules on IPv6 packets are accepted but no-op'd, counted as `STAT_TC_TAG_V6_UNIMPL`."
   - `ARCHITECTURE.md` §3.5: mark CoS / VLAN PCP rewrite still unimplemented (P0-09, separate workstream); mark IPv6 DSCP rewrite as deferred to a follow-up design.

6. **Tests** — see Acceptance Criteria below. All new tests go in `tests/bpf/test_bpf_dataplane.cpp` (BPF_PROG_TEST_RUN) and `functional_tests/test_l3_ipv6.py` (live veth).

## Acceptance criteria

The fix lands only when all of these are green **in CI** (so prerequisite: recommendation #1 from `99_REPORT.md`, CI shape fix, must land first or in parallel).

- `tests/test_byte_layout.cpp` — passes with new `pkt_meta` layout. Adds an assertion that `offsetof(pkt_meta, ip_family)` matches the BPF side.
- New `test_l3_stamps_ip_family_v4` / `_v6` — sends each, asserts `meta->ip_family` matches in the data plane.
- New `test_l4_ipv6_ext_chain_5_drops_with_stat` — sends IPv6 + 5 Hop-by-Hop + TCP, asserts `STAT_DROP_L4_V6_EXT_DEPTH` increments, packet drops. Parameterise over chain depths {1, 4, 5, 8}.
- New `test_l3_ipv6_fragment_behind_hbh_drops` — sends IPv6 + HopByHop + Fragment, asserts `STAT_DROP_L3_V6_FRAGMENT` increments. Parameterise over which position the Fragment header sits at.
- New `test_tc_ipv6_tag_does_not_corrupt` — sends IPv6 packet matching a tag rule; captures egress; asserts source address and Flow Label bits are unchanged; asserts `STAT_TC_TAG_V6_UNIMPL` increments. **The critical regression check.**
- Existing IPv4 path tests — unchanged behaviour, all green.
- BPF verifier — all programs load on target kernels (5.15 LTS minimum per implicit support).

## Migration / rollout

- `pkt_meta` layout changes once. Generation-swap is unaffected because `pkt_meta` lives in XDP `data_meta`, not in any BPF map — it's stamped fresh per packet. New BPF programs use the new layout; old BPF programs are gone the moment the new generation commits.
- Single-PR atomic move: all four BPF files + `common.h` + `test_byte_layout.cpp` ship together. Partial landing breaks the data plane.
- Run the full `bpf;privileged` ctest label locally before pushing. Once recommendation #1 lands, CI will gate this automatically.
- No userspace changes — `pkt_meta` is BPF-only.

## What this does not fix

- **IPv6 Traffic-Class rewrite in TC ingress.** Deliberately scoped out. P0-03 is closed in the "stop the corruption" sense; the feature itself (IPv6 DSCP/ECN rewrite) is a separate design. The right design is its own helper paralleling the IPv4 path with the correct offsets (byte 0 high nibble + byte 1 low nibble, no header checksum to update). Track as a new finding once this lands.
- **CoS / VLAN PCP rewrite** (P0-09). Separate workstream — touches `bpf_skb_vlan_push/pop` and Ethernet rewrite, orthogonal to IPv6.
- **IPv6 fragment reassembly.** Deferred per `00_OWNER_NOTES.md`. This fix closes the *evasion channel* (Fragment hidden behind ext headers); reassembly is still not on the table.
- **Per-rule IPv6 byte counters.** Folded into P0-08 (bytes counter helper); same primitive will count both families once that lands.
- **Adversarial fuzz coverage of the BPF data plane.** A packet-level fuzzer would generalise the new tests above. Separate item; out of scope here.

## Open questions for the owner before implementation

1. **`ip_family` field placement in `pkt_meta`.** New byte vs reusing `redirect_ifindex`'s low byte. I chose new byte for clarity. Override?
2. **Naming.** `IP_FAMILY_V4` / `IP_FAMILY_V6` with literal values 4 and 6, or stick with `AF_INET`/`AF_INET6` (10 and 28)? Numeric `4`/`6` are self-documenting in stat dumps but diverge from POSIX. I went with `4`/`6`; default if you don't override.
3. **Sequence with CI shape fix.** Should this design land before or after recommendation #1 (CI shape)? My read: #1 lands first because otherwise the new tests above stay invisible. But if the owner wants to ship this fix to production first and CI second, the tests can still be run locally. Confirm.
