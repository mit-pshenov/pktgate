# 07 — bpf/entry.bpf.c (Phase 2e)

## What this program does

`entry.bpf.c` is the first XDP program every packet hits. ~45 LOC of actual code in a single `entry_prog`. Per-packet, in order:

1. **`STAT_INC(STAT_PACKETS_TOTAL)`** (`entry.bpf.c:18`) — the one global packet counter. Single percpu-array lookup + non-atomic increment.
2. **`bpf_map_lookup_elem(&gen_config, &key)`** with `key=0` (`entry.bpf.c:21`) — read active generation. `gen_config` is `BPF_MAP_TYPE_ARRAY, max_entries=1` (`maps.h:11-16`).
3. **`bpf_xdp_adjust_meta(ctx, -sizeof(struct pkt_meta))`** (`entry.bpf.c:29`) — grow XDP head-room for `pkt_meta` (20 bytes including padding; struct is `4+4+4+4+1+1+2=20` per `common.h:164-172`).
4. **Bounds check** `(meta+1) > data` (`entry.bpf.c:40`).
5. **`__builtin_memset(meta, 0, sizeof(*meta))`** (`entry.bpf.c:45`) — zero-fill the 20-byte meta.
6. **`meta->generation = *gen`** (`entry.bpf.c:46`).
7. **`bpf_tail_call(ctx, &prog_array_{0|1}, LAYER_2_IDX)`** (`entry.bpf.c:50-52`) — branch on `*gen == 0` and tail-call.

Three drop paths: `STAT_DROP_NO_GEN`, `STAT_DROP_NO_META`, `STAT_DROP_ENTRY_TAIL`.

## Per-question findings

### 1. Per-packet step list with cost

| Step | Cost (x86_64, rough ns) |
|------|-------------------------|
| `STAT_INC(STAT_PACKETS_TOTAL)` (lookup percpu-array slot 0, ++) | ~5-7 ns |
| `bpf_map_lookup_elem(&gen_config, &key)` (array helper) | ~5-10 ns |
| Null-check on `gen` (verifier-mandated) | ~0 ns (predicted) |
| `bpf_xdp_adjust_meta(ctx, -20)` (helper, head-room grow) | ~10-20 ns |
| `(meta+1) > data` bounds check | ~0-1 ns (verifier-mandated) |
| `__builtin_memset(meta, 0, 20)` (compiler emits 2-3 stores) | ~1-2 ns |
| `meta->generation = *gen` | ~1 ns |
| Branch on `*gen == 0` (well-predicted per deploy) | ~1 ns |
| `bpf_tail_call(prog_array_{gen}, LAYER_2_IDX)` | ~15-25 ns |
| **Total entry segment** | **~40-65 ns** |

The two biggest items are the tail-call (unavoidable structural cost of the indirection) and `bpf_xdp_adjust_meta` (unavoidable for the `data_meta` channel design). Stat-fire and gen lookup are ~5-10 ns each; both could in principle be elided if combined into a single percpu-cached generation/counter pair, but that's a redesign not a micro-tweak.

### 2. `bpf_xdp_adjust_meta` failure mode — handled, but driver dependency unstated **at the call site**

The return code is checked (`entry.bpf.c:30-34`). On failure: `STAT_INC(STAT_DROP_NO_META)` + `XDP_DROP`. **The fail-mode is fail-closed: every packet drops** if the driver doesn't support `bpf_xdp_adjust_meta`. That's diagnosable (operator sees zero throughput and a counter pinned to the input rate), but it's silent on **which** driver / NIC / netdev caused it. No log on first failure; the stat counter is the only signal.

This is the **data-plane half of the Phase 1 P1 `data_meta` driver dependency** (`02_architecture.md §3` and finding "data_meta XDP→TC contract is unstated and driver-dependent"):
- Phase 1 flagged the **XDP→TC** half (TC reads `pkt_meta` and the kernel may not preserve `data_meta` across the handoff on some drivers).
- entry.bpf.c covers the **XDP-internal half** (the helper may simply refuse on certain drivers — e.g., some offloaded XDP modes, certain virtio-net configurations).

The entry code's behaviour is correct (fail-closed, counter). What's missing is operator-facing: a startup self-test in the loader that sends a synthetic packet through `BPF_PROG_TEST_RUN` on the live program and verifies the helper succeeds. **No new finding** — this is the same P1 from Phase 1, now confirmed observed in data-plane code.

### 3. Generation read

- **One map lookup per packet**: confirmed (`entry.bpf.c:21`). ~5-10 ns.
- **Cached into `pkt_meta`**: yes, `meta->generation = *gen` (`entry.bpf.c:46`) is set before tail-call. L2/L3/L4 read `meta->generation` from `data_meta` and **do not re-read `gen_config`** — verified in `layer2.bpf.c:118`, `layer3.bpf.c:181` (per Phase 2b), `layer4.bpf.c:222` (per Phase 2d). Good design.
- **Map type**: `BPF_MAP_TYPE_ARRAY, max_entries=1, key=__u32, value=__u32` (`maps.h:11-16`). Confirmed array, not hash. Array lookup is bounds-check-and-offset, ~5 ns; hash would be ~20-30 ns. Correct choice.

### 4. `memset` of pkt_meta — confirmed, cheap

`__builtin_memset(meta, 0, sizeof(*meta))` at `entry.bpf.c:45`. `sizeof(struct pkt_meta) == 20` bytes (4 u32 + 2 u8 + 2 u8 pad, `common.h:164-172`). On x86_64 the compiler emits 2-3 store instructions (likely one 16-byte SSE store + one 4-byte store, or 3×8-byte stores). ~1-2 ns. If `pkt_meta` ever grew past 32 bytes the cost would step up; today negligible.

The memset matters: without it, downstream layers reading `meta->action_flags` / `meta->dscp` etc. would read prior packets' (or uninitialised XDP head-room) bytes. The zero-init is load-bearing for the contract that "L2 sees a clean `pkt_meta` with only `generation` set".

### 5. Tail-call to L2 — confirmed, fail-mode is `STAT_DROP_ENTRY_TAIL`

`bpf_tail_call(ctx, &prog_array_{0|1}, LAYER_2_IDX)` at `entry.bpf.c:50-52`, conditional on `*gen == 0` vs else. `LAYER_2_IDX = 0` (`common.h:32`). `prog_array_{0,1}` have `max_entries=MAX_LAYERS=4` (`maps.h:20-32`, `common.h:20`).

If `prog_array_{gen}[0]` is unpopulated, `bpf_tail_call` returns and execution falls through to line 55 → `STAT_INC(STAT_DROP_ENTRY_TAIL)` + `XDP_DROP`. **Fail-closed.** This is the loader-invariant safety net: if the L2 program failed to load and the prog_array slot is missing, every packet drops with a dedicated counter (rather than passing through unfiltered).

Compare with Phase 2b's L3 asymmetry: entry is consistently fail-closed (drop) on tail-call failure; L3 has two different fail-modes depending on whether a rule matched. entry's choice is the safer one for an "always-filter" stance.

### 6. Pre-computation opportunities — NOT taken, biggest miss

Every downstream layer re-parses Ethernet from `ctx->data`: L2 (`layer2.bpf.c:100-108`), L3 (`layer3.bpf.c:167-185`), L4 (`layer4.bpf.c:101-115`) — confirmed via grep. Cost ~2-3 ns × 3 layers ≈ 6-9 ns cumulative. entry never reads `eth->h_proto` and never computes L3/L4 offsets.

**Cheapest plausible pre-compute** in entry: `__be16 eth_proto`, `__u8 l3_off` into `pkt_meta`, optionally `vlan_id`/`pcp` for L2's tagged path. Cost in entry ~3-4 ns (one bounds check, 802.1Q probe, 1-2 stores). **Net saving ~3-6 ns/packet** on the common pipeline; bigger win is verifier simplification downstream.

**Verdict**: most obvious in-file latency optimisation, not done. P2-performance. Not P1 because saving is small, requires lockstep refactor across 4 BPF files, and the redundancy is defence-in-depth (every layer self-bounds-checks).

### 7. `STAT_PACKETS_TOTAL` — fires exactly once per packet, at entry

`STAT_INC(STAT_PACKETS_TOTAL)` is at `entry.bpf.c:18`, before any conditional. Every packet that reaches the XDP program fires this counter exactly once.

Cross-reference with Phase 2b/2d:
- L3 hot-path (rule match → tail-call): 0 STAT_INC fires.
- L4 hot-path (rule match → ALLOW): 1 STAT_INC fire (`STAT_PASS_L4`).
- L2 hot-path (no match → tail-call to L3): 0 STAT_INC.

So the typical L2→L3→L4-allow packet fires **2 stats total**: `PACKETS_TOTAL` at entry + `PASS_L4` at L4. ~10-14 ns of stat overhead. Phase 1's "8-10% stat overhead" estimate is plausible only on stat-heavy paths (mirror-terminal: `MIRROR` + `PASS_L3` + `PACKETS_TOTAL` = 3 fires). The common path is cheap.

`STAT_PACKETS_TOTAL` is the only counter that gives a denominator for "what fraction of packets were dropped at layer X". Confirmed it's reliably the single guaranteed fire.

### 8. Bounds check on Ethernet header — **entry does NOT do this**

entry never touches `eth`. It does **not** check `eth+1 > data_end`. The only bounds check is `(meta+1) > data` for the `data_meta` region (`entry.bpf.c:40`).

Consequence: a runt frame (say, a 6-byte packet that somehow reached XDP) would pass entry's tail-call to L2, and L2's `eth+1 > data_end` check (`layer2.bpf.c:105`) would drop it with `STAT_DROP_L2_BOUNDS`. Correct division of labour, but means **the eth bounds check is paid at L2 only** (and re-paid at L3 and L4, verifier-mandated, on top of L2). If entry pre-computed offsets (§6), it would have to pay this check too — adding cost rather than removing it. So the "pre-compute" idea is not free; it merely **front-loads** the eth bounds check from L2 to entry, and the layers still re-check the **L3 header** bounds.

### 9. `pkt_meta` layout — `redirect_ifindex` is dead

`struct pkt_meta` (`common.h:164-172`):

| Field | Set by | Read by |
|-------|--------|---------|
| `generation` u32 | entry (`entry.bpf.c:46`) | L2/L3/L4 |
| `action_flags` u32 | L2 (`layer2.bpf.c:61`), L3, L4 (TAG bit) | TC ingress |
| `redirect_ifindex` u32 | **nowhere** | nowhere |
| `mirror_ifindex` u32 | L2 (`layer2.bpf.c:62`), L3 | TC ingress |
| `dscp` u8 | L4 (TAG) | TC ingress |
| `cos` u8 | L4 (TAG) | TC ingress (but CoS not implemented — Phase 1 P0) |

**`redirect_ifindex` is dead** — `bpf_redirect(ifindex, 0)` is called directly in L2 (`layer2.bpf.c:55`) and L3 redirect paths without going through `pkt_meta`. Confirms Phase 2b's note. 4 bytes of `pkt_meta` are dead weight; removing it shrinks `pkt_meta` to 16 bytes.

**`cos` is half-dead** — written by L4 TAG; the TC PCP rewrite that would consume it is unimplemented (Phase 1 P0).

### 10. Anything surprising

- **`(meta+1) > data` not `data_end`** — correct: `data_meta` lives below `data`. Consistent with all layers.
- **`BPF_DBG` calls** (lines 24, 32, 56) compiled out without `-DBPF_DEBUG`. Zero hot-path cost.
- **No L2 short-circuit** — entry can't skip L2 even when no L2 rules exist (would need an extra map lookup). Acceptable.
- **No CO-RE relocations** — entry only touches `ctx` (stable ABI). Good.
- **`prog_array_0` vs `prog_array_1` if/else** — same cheap pattern as L3 (Phase 2b).

## Additional findings

- **`STAT_DROP_NO_META` overloaded** — fires both for `bpf_xdp_adjust_meta` failure (line 31) and the `(meta+1) > data` bounds-check (line 41, unreachable on successful adjust). Splitting would aid diagnosis. P2.
- **Line-40 bounds check is dead in practice** — successful `bpf_xdp_adjust_meta(-20)` guarantees `data - data_meta >= 20`. The verifier requires the compare; it's never true. Not a finding.

## Latency analysis

**Common path** ~40-65 ns; breakdown in §1. No worst case (no loops, no LPM, no hash).

Versus the published 165 ns full-pipeline figure, entry is ~25-40%. **Dominated by the indirection mechanism itself**: `bpf_xdp_adjust_meta` ~10-20 ns + `bpf_tail_call` ~15-25 ns = ~25-45 ns of structural cost. Work-content (stat + gen lookup + memset + assignment) is only ~10-15 ns.

In-file optimisation potential: ~3-6 ns from pre-computation (§6). Beyond that, only structural changes (combine stat-fire and gen-lookup; eliminate one indirection) — out of scope.

## Findings (graded)

```
- [P1 RE-CONFIRMED — not new] data_meta driver dependency
  Where: bpf/entry.bpf.c:29-34 (the XDP-internal half); cross-references Phase 1 P1
  What: bpf_xdp_adjust_meta may silently refuse on some drivers; entry fail-closes and
        bumps STAT_DROP_NO_META, but no operator-facing diagnostic beyond the counter.
  Status: this file's behaviour is correct (fail-closed, counter). The finding is the
        same as Phase 1 P1 — already filed there. No new entry needed in 99_REPORT.md
        beyond what Phase 1 captured.

- [P2 NEW] redirect_ifindex field in pkt_meta is dead (set nowhere, read nowhere)
  Where: bpf/common.h:167 (struct field); entry.bpf.c:45 (zeroed); not written by
         layer2/3/4; not read by tc_ingress (per Phase 2b note)
  What: 4 bytes of pkt_meta carry no information. bpf_redirect() is called directly
        with the ifindex argument in L2 and L3 redirect paths — they don't channel
        through pkt_meta.
  Why it matters: minor — wastes 4 bytes of data_meta head-room and confuses readers
        ("when is redirect_ifindex consulted?"). Removing it shrinks pkt_meta to 16B
        and tightens the XDP→TC contract.
  Suggested action: delete the field, drop the now-redundant 2-byte _pad, re-run
        test_byte_layout.cpp asserts. Or: write a comment "set by future layers".

- [P2 NEW] STAT_DROP_NO_META overloads two distinct error classes
  Where: bpf/entry.bpf.c:31 (adjust_meta failure) and :41 (post-adjust bounds check)
  What: The counter fires for both "driver doesn't support bpf_xdp_adjust_meta" and
        the verifier-mandated bounds check (which should be unreachable on a
        successful adjust). An operator seeing this counter pinned cannot tell
        driver-incompat from kernel-bug.
  Suggested action: add STAT_DROP_META_BOUNDS as a separate counter; differentiate
        them at the call sites. Cost: one enum slot.

- [P2 NEW — performance] entry does not pre-compute eth/L3/L4 offsets into pkt_meta
  Where: entry.bpf.c (the entire file); contrast with layer{2,3,4}.bpf.c which each
         re-parse Ethernet from ctx->data
  What: L2, L3, L4 each pay an eth bounds check + h_proto read (~2-3 ns each, ~6-9 ns
        total across pipeline). Adding eth_proto + l3_off to pkt_meta in entry would
        let downstream layers skip the eth re-parse, saving ~3-6 ns/packet at the
        cost of one bounds check + load + store in entry.
  Why it matters: at the 40 Gbps line-rate target, 3-6 ns × 4.88 Mpps ≈ 15-30 µs/sec
        per CPU. Small but real. The bigger win is verifier complexity — downstream
        programs simplify.
  Suggested action: add `__be16 eth_proto; __u8 l3_off; __u8 _pad;` to pkt_meta;
        populate in entry; refactor layer{2,3,4} to consume. Requires lockstep
        change across all four BPF files. Defer until a perf benchmark shows
        per-packet headroom matters.
  Trade-off: "every layer re-parses what it needs" is easier to reason about and
        provides defence-in-depth (entry mis-offset still caught at the layer).
        Recommend keeping current design unless benchmarks show eth-re-parse
        materially limits line-rate.
```

No P0. No new P1. The Phase 1 P1 (`data_meta` driver dependency) is confirmed as observed in this file; it remains a single P1 finding tracked in `02_architecture.md`.

## Test-audit notes

- **`bpf_xdp_adjust_meta` failure handling** — easy to add a `BPF_PROG_TEST_RUN` asserting `STAT_DROP_NO_META` stays at 0 on normal packets. Failure path itself is hard to trigger (would need a kernel stub). Test class: **happy-path-only**, matching the Phase 2b/2d pattern.
- **P2 redirect_ifindex dead field** — static-analysis class; not behavioural. `test_byte_layout.cpp` checks sizeof/offsetof but not field use.
- **P2 STAT_DROP_NO_META overload** — both error classes are hostile to test in the current harness.

## Open issues

- Verify in Phase 2c (loader) that `prog_array_{0,1}[LAYER_2_IDX]` is populated **before** entry is attached. A gap window would drop every packet with `STAT_DROP_ENTRY_TAIL` until filled. Fail-closed limits impact.
- entry's `bpf_xdp_adjust_meta` failure path is **fail-closed** (drop). The customer brief asks for fail-open/bypass on failure (Phase 1 P0). On an unsupported driver, entry drops 100% of traffic — opposite of fail-open. Cross-ref Phase 1 §7.
- `pkt_meta` can shrink 20 → 16 bytes if dead `redirect_ifindex` is removed. Minor.
