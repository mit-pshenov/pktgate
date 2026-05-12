# 09 — bpf/tc_ingress.bpf.c (Phase 2f)

## What this program does

`tc_ingress.bpf.c` is the only non-XDP BPF program in pktgate. Attached as `tc` ingress, it runs on every packet the XDP pipeline let through with `XDP_PASS`. It performs the two deferred actions that require skb context:

1. **Mirror** — `bpf_clone_redirect(skb, mirror_ifindex, 0)` when `ACT_MIRROR` is set and `mirror_ifindex != 0` (`tc_ingress.bpf.c:69-80`).
2. **Tag (DSCP rewrite)** — for IPv4, rewrite TOS at frame offset 15 (preserve bottom-2 ECN bits) and apply incremental IP csum fixup at frame offset 24 (`tc_ingress.bpf.c:83-105`).

Inputs from `pkt_meta` in `skb->data_meta`. Output is always `TC_ACT_OK` — TC ingress never drops.

## Per-question findings

### 1. CoS / VLAN PCP rewrite — CONFIRMED NOT IMPLEMENTED

- No `bpf_skb_vlan_push` / `bpf_skb_vlan_pop` anywhere (`grep` of file is empty).
- `meta->cos` is **never read** in this file. L4 dutifully stamps `meta->cos = rule->cos` at `bpf/layer4.bpf.c:262`; TC drops it on the floor.
- This **finalises the Phase 1 P0** in `02_architecture.md §7`. CONFIG.md exposes a working `cos` parameter, validator accepts it, the data plane writes it into metadata, and TC silently does nothing with it. From the operator's perspective, `cos` is a working knob with no effect.

### 2. IPv6 DSCP rewrite — ABSENT AND PACKET-CORRUPTING

The TAG path (`tc_ingress.bpf.c:83-105`) is hard-coded for IPv4 byte offsets with **no IP-family gate**. Specifically:

- Line 86 loads byte at offset `14+1 = 15` and treats it as IPv4 TOS.
- Line 90 stores a recomputed "TOS" back to that byte.
- Lines 98-100 apply `bpf_l3_csum_replace` at offset `14+10 = 24`, treating that as the IPv4 header-checksum field.

L4 sets `ACT_TAG` regardless of IP family (`bpf/layer4.bpf.c:259-265` — no v4 gate). So a matched IPv6 tag rule causes TC to:

- **Corrupt byte 15 of the frame**, which for IPv6 is `(Traffic-Class-low-nibble<<4) | Flow-Label-high-nibble` — both fields mangled. The DSCP value does not land in the IPv6 Traffic Class field (which is split across bytes 14 *and* 15, top 6 bits = TC, of which top 6 are DSCP — i.e., DSCP lives in `byte[14].low4 || byte[15].high2` after the version nibble, *not* anywhere addressable by `(dscp<<2) | (old & 0x03)` at byte 15).
- **Corrupt bytes 24-25 of the frame** via `bpf_l3_csum_replace`, which for IPv6 is bytes 10-11 of the IP header — part of the **source IP address** (bytes 8-23 are src addr). IPv6 has no header checksum at offset 10, so the helper writes a garbage 16-bit delta into the src address.

**Net effect**: an IPv6 packet that matches an L4 tag rule reaches the host stack with a mangled Flow Label and a corrupted source address. The host either silently delivers the broken packet, the stack drops it (bad checksum at L4 pseudo-header), or a downstream router drops it. On a Gi 40 Gbps IPv6 link, any `tag` rule corrupts every matched IPv6 packet.

**This is materially worse than "DSCP rewrite is absent for IPv6"** as Phase 2d framed it. The original framing assumed a no-op; the actual behaviour is silent corruption.

**Promote to new P0 SECURITY/CORRECTNESS.**

### 3. `stats_map` shared layout — IDENTICAL, depends on loader for actual sharing

- TC declaration (`tc_ingress.bpf.c:26-31`): `BPF_MAP_TYPE_PERCPU_ARRAY`, `max_entries=MAX_STATS (=40)`, `key=__u32`, `value=__u64`.
- XDP declaration (`bpf/maps.h:200-205`): identical in every field.

Layouts are **byte-identical**. `bpf_map__reuse_fd()` is a valid path for the loader to point TC's `stats_map` at the XDP map FD. **If the loader does not call `reuse_fd` for this map**, the two declarations become two *distinct* PERCPU_ARRAY maps and:

- `STAT_TC_MIRROR/MIRROR_FAIL/TAG/NOOP` increments (slots 26-29) land in the TC-private map.
- Userspace `stats_reader` reads the XDP-private map → TC stats appear as zero.
- The Prometheus exporter under-reports.

Phase 2h (`src/loader/bpf_loader.cpp`) must verify the `reuse_fd` call exists for `stats_map` against the TC object. **Layout invariant is satisfied; loader behaviour is the open question.**

### 4. Mirror via `bpf_clone_redirect` — correct

- `flags & (1 << ACT_MIRROR)` test (`tc_ingress.bpf.c:69`) reads cached `flags` from `meta->action_flags`. Correct bit.
- `mirror_ifindex` cached at line 65 from `meta->mirror_ifindex`. Cached **before** the helper call — necessary because `bpf_clone_redirect` invalidates packet/data_meta pointers (commented at lines 58-64; correctly handled).
- Call `bpf_clone_redirect(skb, mirror_ifindex, 0)` with flags=0 (line 71): clones to the named iface, original continues. Failure path stamps `STAT_TC_MIRROR_FAIL`. Success stamps `STAT_TC_MIRROR`.
- **On clone failure the original still passes** — function returns `TC_ACT_OK` at line 107 regardless. Contract: best-effort mirror, never drop the original. Correct.
- **`mirror_ifindex == 0` is silently skipped** — line 70 `if (mirror_ifindex)` guards. No diagnostic stat for "mirror flag set but ifindex zero" (config bug). Minor — P2.

### 5. DSCP rewrite — IPv4 checksum recompute IS CORRECT

Traced `bpf_l3_csum_replace` on x86_64 LE: helper accepts `from`/`to` as `__be16` (cast inside `inet_proto_csum_replace2`); `csum_partial` reads bytes in network order. TOS sits in the LOW byte of the offset-0 network word. `bpf_htons((__u16)tos)` on LE puts TOS into the high byte of the host u16, which stored in LE memory gives `[0x00, tos, ...]`; the helper's BE read recovers delta `= tos`. **Matches the actual sum delta.** ECN preserved correctly (`new_tos = (dscp<<2) | (old_tos & 0x03)`, line 88). Early-return on equal TOS (line 89) avoids redundant work. **No P0 here for IPv4.**

### 6. `data_meta` read on TC side — correct, single bounds check

- `data = skb->data`, `data_meta = skb->data_meta` at lines 42-43.
- Bounds check `(meta + 1) > data` at line 46 — the same pattern used by all XDP layers, adapted to TC's `data_meta` semantics. Single check covers the entire 20-byte `pkt_meta` read.
- On bounds-check failure, stamps `STAT_TC_NOOP` and returns `TC_ACT_OK`. This collapses two distinct cases into one counter:
  - Driver doesn't preserve `data_meta` across XDP→TC handoff (the Phase 1 P1 / Phase 2e re-confirmation).
  - `action_flags == 0` (no deferred work).
- An operator seeing a high `STAT_TC_NOOP` rate cannot distinguish "everything is fine, almost no packets need deferred actions" from "the driver is stripping our metadata and TC sees garbage". P2 diagnostic gap.

### 7. Bounds checks for packet reads in TC

- `(meta + 1) > data` for the 20-byte `pkt_meta` — present (line 46).
- TC reads packet bytes only via `bpf_skb_load_bytes(skb, 14+1, &old_tos, 1)` (line 86), which **internally validates the offset against `skb->len`** and returns negative on out-of-range. The code checks `== 0` before proceeding. No direct packet-pointer dereference, no need for `data_end` bounds.
- `bpf_skb_store_bytes` and `bpf_l3_csum_replace` similarly self-validate offsets.

No bounds-check gaps in the TC code itself. (The IPv6 corruption finding from §2 is not a bounds gap — the helpers happily store within bounds; it's the offsets that are semantically wrong for IPv6.)

### 8. STAT_INC sites in TC

Five total:
- `STAT_TC_NOOP` (line 48 — no meta) — also fires for "valid meta but no flags" (line 54).
- `STAT_TC_MIRROR` (line 73).
- `STAT_TC_MIRROR_FAIL` (line 76).
- `STAT_TC_TAG` (line 101) — fires only when `new_tos != old_tos` (i.e., when DSCP actually changed).

A tag rule that re-tags a packet to its existing DSCP fires no counter (line 89 skips the write *and* the increment). An operator who configures DSCP=0xCS6 expecting *all* matching packets to register a hit will see fewer hits than expected when traffic was already at that DSCP. P2 cosmetic.

The TC stats vs documentation cross-reference is constrained: only 4 distinct events. Mirror failure mode is well-counted; tag has a "fired vs no-op" distinction it can't express. Acceptable.

### 9. Action ordering — mirror BEFORE tag

`tc_ingress.bpf.c:69` (mirror) comes textually and lexically before `:83` (tag), and both are independent `if` blocks. So when both `ACT_MIRROR` and `ACT_TAG` are set:

1. Mirror clones the packet *as it currently exists* — i.e., still bearing the **original DSCP** (XDP didn't touch the TOS byte; XDP only stamped `meta->dscp` for TC).
2. Then tag rewrites the original's TOS to the new DSCP.

**Semantic**: the mirror-target sees the packet with the *original* DSCP; the on-stack packet continues with the *new* DSCP.

Whether this matches operator intent depends on the use case:
- For forensic/IDS capture, mirroring the *original* is the right call.
- For "remarking + telemetry" use cases, the operator might want the mirror to show the *new* DSCP so the telemetry sink sees what downstream will see.

CONFIG.md doesn't document the ordering. **P2 doc gap** — the contract is "mirror sees the original; the live path sees the tagged version" and that should be written somewhere user-facing.

### 10. Failure modes

- `pkt_meta` missing (driver dropped data_meta): `STAT_TC_NOOP` + `TC_ACT_OK`. Silent — same counter as "no deferred work" (see §6, P1 below).
- `mirror_ifindex == 0` with ACT_MIRROR set: silently skipped, **no stat**. P1 below.
- `mirror_ifindex` invalid (deleted iface, wrong namespace): `STAT_TC_MIRROR_FAIL`. Diagnosable.
- `dscp > 63`: `dscp << 2` overflows into ECN bits. Garbage TOS. Not defensively masked. P2 below.
- `action_flags == 0`: `STAT_TC_NOOP` + `TC_ACT_OK`. Common fast path.
- **IPv6 packet with ACT_TAG**: silent packet corruption (see §2). No counter. **P0**.
- VLAN-tagged frame with ACT_TAG: unreachable today (L3/L4 drop VLAN-tagged frames before TC). Latent P2.

### 11. Surprises

- `bpf_skb_store_bytes` called with `flags=0` (not `BPF_F_RECOMPUTE_CSUM`) — correct per the in-code comment (that flag only touches `skb->csum`, not the IP header field); the explicit `bpf_l3_csum_replace` handles the IP csum.
- The cache-before-helper comment (lines 58-64) is unusually educational about verifier pointer-invalidation semantics.
- No DSCP sanity mask (see §10). `STAT_TC_NOOP` overload (see §6).

### 12. 40 Gbps-line-rate-reviewer perspective

Common-path cost (no deferred actions): two pointer loads + bounds check + meta read + branch + `STAT_INC(STAT_TC_NOOP)` ≈ **~10-15 ns**. Paid on every packet that survives XDP.

Deferred:
- Mirror: `bpf_clone_redirect` allocates an skb clone, refs pages, queues to qdisc — likely **>500 ns**. Reserve for low-rate audit flows.
- Tag: load_bytes + store_bytes + l3_csum_replace + STAT_INC ≈ **40-60 ns** (comparable to one L3 LPM).

Adding ~10-15 ns to the published 165 ns full pipeline yields ~180 ns — inside the ~205 ns 1024-byte 40-Gbps budget. Tagged-only flows reach ~205-225 ns: **at the edge**. The unconditional `STAT_TC_NOOP` increment on every packet costs ~5 ns that could be elided if we accept losing the denominator.

## Additional findings

- **TC ingress never drops**: every path returns `TC_ACT_OK`. Fail-open contract at the post-XDP stage. Worth documenting.
- `pkt_meta.redirect_ifindex` not consumed here either — confirms Phase 2e dead-field finding across all layers.
- `BPF_DBG` calls (lines 74, 77, 102) compile out without `-DBPF_DEBUG`. Zero hot-path cost.
- Local `stats_map` redeclaration (vs `#include "maps.h"`) is a scope-narrowing choice; `MAX_STATS` comes via `common.h` so the two declarations stay in lockstep. Acceptable.

## Latency analysis

| Path | TC contribution | Cumulative |
|---|---|---|
| No deferred actions (common) | ~10-15 ns | ~180 ns |
| Tag only (IPv4, DSCP changed) | ~50-70 ns | ~230 ns |
| Tag only (IPv4, DSCP same) | ~25-35 ns | ~200 ns |
| Mirror only | ~500-1000+ ns (clone) | dominated by clone |
| IPv6 with ACT_TAG (corruption) | ~50-70 ns | + downstream drop |

Common-path TC adds ~10 ns — well inside budget. Tag is ~one L3 LPM. Mirror is order-of-magnitude heavier; reserve for low-rate audit flows.

## Findings (graded)

```
- [P0 NEW] IPv6 packets with ACT_TAG are silently corrupted
  Where: bpf/tc_ingress.bpf.c:83-105 (the entire TAG branch),
         bpf/layer4.bpf.c:259-265 (L4 sets ACT_TAG without IP-family gating)
  What: TAG path hard-codes IPv4 byte offsets (TOS at 14+1, IP csum at 14+10)
        with no v4 gate. An IPv6 packet that matches a tag rule reaches TC,
        the code:
          (a) overwrites byte 15 with (dscp<<2)|ecn — that byte holds the LOW
              nibble of Traffic Class and the HIGH nibble of Flow Label;
              DSCP does not land in the right bits at all, and Flow Label is
              corrupted.
          (b) calls bpf_l3_csum_replace at frame offset 24 (= IP offset 10),
              which for IPv6 is bytes 2-3 of the SOURCE ADDRESS. A 16-bit
              checksum delta is written into the src addr.
        Result: every IPv6 packet hitting a tag rule has Flow Label mangled
        and source IP corrupted. No counter fires to indicate the mistake.
  Why it matters: Carrier Gi-side filter; IPv6 traffic is expected. The "tag"
        action is one of the project's three documented action verbs. Silent
        data corruption on a documented feature path. Worse than the Phase 2d
        framing of "rewrite is absent" — it's not no-op, it's destructive.
  Suggested action: Gate the TAG branch on IP family. Cheapest: check
        eth->h_proto (re-load via bpf_skb_load_bytes at offset 12) and only
        rewrite for 0x0800. Proper: implement IPv6 TC rewrite — the TC field
        spans byte 14 high-nibble (top 4 bits of "vihl"-equivalent are the
        Version, then 4 bits TC-high; byte 15 high-nibble = TC-low). Writing
        DSCP correctly requires two-byte read-modify-write on bytes 14-15
        (preserve Version nibble, ECN bits, Flow Label high nibble). IPv6
        has NO header checksum, so the csum_replace call must be removed
        for the v6 path entirely.

- [P0 CONFIRMED — Phase 1 §7 closed] CoS / VLAN PCP rewrite not implemented
  Where: bpf/tc_ingress.bpf.c (no bpf_skb_vlan_push/pop calls anywhere,
         no read of meta->cos)
  What: L4 stamps meta->cos at layer4.bpf.c:262. TC never reads it. CONFIG.md
        and ARCHITECTURE.md §3.5 advertise CoS as a tag parameter.
  Status: This is the Phase 1 P0 from 02_architecture.md §7. Now finalised
        from the TC side. Either implement (bpf_skb_vlan_push/pop on a
        re-encap path) or reject "cos" at the validator.
  Cross-ref: 02_architecture.md §7, 05_layer4.md §6.

- [P1 NEW] STAT_TC_NOOP conflates "driver stripped data_meta" with
            "no deferred work today"
  Where: bpf/tc_ingress.bpf.c:48 (no-meta path) and :54 (zero-flags path)
  What: Both fire the same counter. An operator seeing STAT_TC_NOOP at
        100% of packet rate cannot tell:
          - benign: "common case, almost no packets need TC actions" — fine
          - broken: "driver doesn't preserve data_meta across XDP→TC" — bug
            that silently disables ALL deferred actions
        Same class of overload as STAT_DROP_NO_META in entry (Phase 2e P2).
  Why it matters: This is the diagnostic counter for the Phase 1 P1
        data_meta driver dependency. Today it's load-bearing and ambiguous.
  Suggested action: split into STAT_TC_NO_META (bounds failure) and
        STAT_TC_NOOP (valid meta, no flags). One extra enum slot.

- [P1 NEW] mirror flag set but mirror_ifindex == 0 is silently ignored
  Where: bpf/tc_ingress.bpf.c:69-80
  What: If L2/L3 set ACT_MIRROR but somehow mirror_ifindex is 0 (config
        bug, partial deploy, race in shadow-clear), the mirror is skipped
        with no counter. Operator's audit pipeline silently misses traffic.
  Suggested action: Add STAT_TC_MIRROR_NO_IFINDEX and increment when the
        condition fires. Cheap diagnostic.

- [P2] STAT_TC_TAG fires only when DSCP actually changes
  Where: bpf/tc_ingress.bpf.c:89-103
  What: The early-return `if (new_tos != old_tos)` is correct optimisation
        but means a tag rule that re-tags packets already at the target DSCP
        registers no STAT_TC_TAG hit. The "how often did this rule fire"
        question is unanswerable from this counter alone.
  Suggested action: Either fire STAT_TC_TAG outside the conditional (count
        invocations, not actual writes), or add a separate
        STAT_TC_TAG_REDUNDANT for the same-DSCP case.

- [P2] No defensive mask of dscp value before shift
  Where: bpf/tc_ingress.bpf.c:88
  What: `new_tos = (dscp << 2) | (old_tos & 0x03)`. dscp is __u8. If a
        validator bug lets a value > 63 through, the high bits overflow
        into ECN and beyond, producing garbage TOS. Validator is the
        primary defence; TC should also mask: `(dscp & 0x3F) << 2`.
  Suggested action: mask defensively. One AND, zero perf cost.

- [P2] Mirror-before-tag ordering not documented
  Where: bpf/tc_ingress.bpf.c (the order is structural)
  What: Mirror sees the ORIGINAL DSCP; the on-stack copy carries the NEW
        DSCP. CONFIG.md doesn't say which one the mirror target receives.
  Suggested action: Document the contract in CONFIG.md / ARCHITECTURE.md.

- [P2 LATENT] Hard-coded IPv4 offsets would corrupt VLAN-tagged frames if
            any future path lets them reach TC with ACT_TAG
  Where: bpf/tc_ingress.bpf.c:86 (14+1), :98 (14+10)
  What: Currently unreachable because L3/L4 drop VLAN-tagged frames before
        TC (eth->h_proto = 0x8100 isn't IPv4/v6 — L3 drops with
        STAT_DROP_L3_NOT_IPV4). If anyone ever wires VLAN-tagged IPv4
        through L3 (which a fix for separately-flagged "L3 doesn't strip
        VLAN" would do), this code corrupts the VLAN tag instead of TOS.
  Suggested action: Either dynamically compute L3 offset from a 802.1Q
        probe, or assert at deploy time that the deployment strips VLAN
        before TC sees the frame.

- [P2] stats_map declared locally rather than via #include "maps.h"
  Where: bpf/tc_ingress.bpf.c:26-31
  What: Phase 1 §2 noted this. Confirmed: layout IS byte-identical to
        bpf/maps.h:200-205 (same type, key_size, value_size, max_entries
        derived from same MAX_STATS constant). bpf_map__reuse_fd() is
        therefore a valid mechanism for sharing. Whether the loader
        actually does it is a Phase 2h question.
  Suggested action: Either include maps.h with a feature-flag to suppress
        the unused-map declarations, or leave as-is and add a
        _Static_assert that MAX_STATS matches between the two files.
        Phase 2h must verify reuse_fd.

- [P2] No diagnostic split between "TC saw packet, no flags" and
       "TC saw packet, processed something" — total volume is unknowable
  Where: bpf/tc_ingress.bpf.c overall
  What: There's no STAT_TC_TOTAL counter. The denominator for "what
        fraction of packets needed deferred actions" can be derived from
        STAT_PACKETS_TOTAL (entry) — but only after subtracting the XDP
        terminal drops/redirects. Adding STAT_TC_TOTAL at the top of the
        function would simplify this telemetry.
  Suggested action: Optional. P2 ergonomics.
```

## Test-audit notes

- **P0 IPv6 ACT_TAG corruption**: no existing test sends an IPv6 packet against a tag rule and captures the modified frame to verify (a) the IPv6 Traffic Class field correctly carries the new DSCP, (b) the Flow Label and source address are unchanged. `functional_tests/test_dscp_tag.py` (3 tests per recon) almost certainly covers only IPv4 — the test name and the implementation's IPv4-only scope co-confirm. **Test class: dual-stack coverage absent on the tag path.** Same pattern as Phase 2b/2d (IPv6 ext-header bypass): IPv6 happy paths exist but no adversarial / dual-stack-symmetry tests.
- **P0 CoS unimplemented**: the test `test_dscp_tag.py` would catch this only if it (a) sets `cos` in the config and (b) captures the frame on a VLAN-tagged mirror target and (c) asserts the PCP bits. The absence of CoS implementation across multiple phases without test failure suggests the test only sets `dscp`. **Test class: validator/compiler/data-plane contract gap not exercised end-to-end.**
- **P1 STAT_TC_NOOP overload**: a test that runs against a driver without `data_meta` preservation would fire `STAT_TC_NOOP` at 100% and pass spuriously (no observable malfunction beyond mirror/tag silently failing). **Test class: negative-state coverage of driver-dependency invariant absent.** Same diagnostic gap as Phase 2e's `STAT_DROP_NO_META` overload.
- **P1 mirror with ifindex=0**: trivial functional test (`config has mirror but target_port resolves to 0 / fails to lookup`). No such test apparent.
- **P2 mirror-before-tag ordering**: a test capturing both the mirror target and the on-stack path, asserting they have *different* DSCPs when both ACT_MIRROR and ACT_TAG are configured. Almost certainly absent.

## Open issues for later phases

- **Phase 2h (`src/loader/bpf_loader.cpp`)**: confirm `bpf_map__reuse_fd(tc.stats_map, xdp.stats_map.fd)` is called. If not, TC stats are split into a TC-private map and userspace under-reports the four `STAT_TC_*` counters. Layout is identical so the call would work.
- **Phase 2g (`src/pipeline/generation_manager.cpp`)**: prog_array atomicity & rate_state lifecycle still open.
- **Phase 2i (`src/config/validator.cpp`)**: must add IPv6 + tag rejection (or accept and require the v6 rewrite implementation). Currently the validator accepts tag rules without considering IP-family — the new P0 is partially a validator gap.
- **CONFIG.md**: document (a) mirror-before-tag ordering, (b) IPv4-only DSCP rewrite (or remove this caveat once IPv6 is implemented), (c) CoS unsupported (or implement).
- **Test gap**: an IPv6+ACT_TAG functional test is the cheapest possible reproducer for the new P0; one scapy invocation.
