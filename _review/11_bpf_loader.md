# 11 — `src/loader/bpf_loader.{hpp,cpp}` (Phase 2h)

## What this module does

`BpfLoader` owns the libbpf skeletons for all five BPF programs (`entry`, `layer2`, `layer3`, `layer4`, `tc_ingress`) and exposes typed map / program FD accessors to `GenerationManager` and `PrometheusExporter`. Lifecycle is three phases:

1. `load()` — opens each skeleton, loads `entry` first (which creates every map in the kernel), then `bpf_map__reuse_fd`s every map symbol in the four sibling skeletons to point at the entry's FDs, then loads them. This guarantees one kernel map per logical name regardless of how many skeletons declare it.
2. `attach(iface)` — `bpf_xdp_attach` the entry program; tries `XDP_FLAGS_DRV_MODE` first, falls back to `XDP_FLAGS_SKB_MODE`.
3. `attach_tc(iface)` — `bpf_tc_hook_create` (clsact qdisc, `EEXIST` tolerated) then `bpf_tc_attach` for the TC ingress program.

`detach()` / `detach_tc()` are the inverses. Destructor invokes both then calls each `*_bpf__destroy`.

`map_manager.{hpp,cpp}` is a thin static-method wrapper over `bpf_map_{update,delete}_elem`, `bpf_map_update_batch` (with a non-supported-fallback signal), `clear_hash_map` (iterate-and-delete), and `delete_keys` (LPM-friendly batch delete). All errors are propagated as `std::expected<void, std::string>`. Reviewed in §10 already.

## Per-question findings

### Q1 — `stats_map` reuse_fd between XDP and TC — CONFIRMED PRESENT, contract held

`bpf_loader.cpp:122-136` is a dedicated reuse block for the TC skeleton. It calls `REUSE_TC_MAP(stats_map)`, which expands to:

- `bpf_map__fd(impl_->entry->maps.stats_map)` → the FD of the XDP-side stats map.
- `bpf_map__reuse_fd(impl_->tc_ingress->maps.stats_map, fd)` → before the TC skeleton is loaded.

Order is correct: `tc_ingress_bpf__load(impl_->tc_ingress)` at line 151 runs **after** the reuse block. libbpf's `reuse_fd` contract is "must be called before `bpf_object__load`" — held.

This **closes the Phase 1 `02_architecture.md §2` open item** and the cross-reference in `09_tc_ingress.md §3`. The TC and XDP `stats_map` declarations being byte-identical (`MAX_STATS=40`, `PERCPU_ARRAY`, `key=u32 value=u64` on both sides) makes the reuse semantically valid. Per-CPU counters are not split. Prometheus is correct.

### Q2 — Same reuse_fd treatment for other TC-referenced maps

TC ingress (`bpf/tc_ingress.bpf.c`) declares **only** `stats_map` locally (`grep` confirms one `SEC(".maps")` entry at line 31, no other map symbols referenced in the program body). The four XDP skeletons each reuse all 25 entry-side maps (`bpf_loader.cpp:83-107`).

Verdict: **no other map needs TC-side reuse** because the TC program doesn't reference any other map. If a future TC change ever reads `gen_config`, `default_action_*`, `prog_array_*`, or `rate_state_map`, that reuse will need to be added — the current `REUSE_TC_MAP(stats_map)` block is minimal-by-design. Worth a code comment, currently absent.

### Q3 — Already-attached XDP / TC behaviour on restart

**XDP path (`bpf_loader.cpp:172-195`)**: `bpf_xdp_attach(ifidx, prog_fd, XDP_FLAGS_DRV_MODE, &opts)` is called with neither `XDP_FLAGS_UPDATE_IF_NOEXIST` nor `XDP_FLAGS_REPLACE` nor an `old_prog_fd` in `opts`. With the default kernel semantics, this:

- If no program is attached: succeeds, attaches.
- If a program is attached **in the same mode** (DRV): **replaces silently**. No `EBUSY`. No log of "we replaced a stale program".
- If a program is attached **in a different mode** (e.g., previous run was SKB): `EBUSY`. The code then falls through to SKB mode (line 185), which again silently replaces a stale SKB-mode program but fails with `EBUSY` against a DRV-mode one. Net effect on the cross-mode case: attaches fail-then-fail → returns an error.

Force-replace is therefore the **dominant behaviour on the same-mode restart path**, which is the common operator scenario. No `XDP_FLAGS_REPLACE` flag is used — that's the explicit "replace this specific old prog_fd" form, which would be wrong here anyway (the old FD is gone after the previous daemon crashed).

The footgun is the **cross-mode** case: pktgate previously attached as SKB on veth, operator moves it to a NIC that supports DRV, new daemon tries DRV first — `EBUSY` against the stale SKB program — falls back to SKB and succeeds, **but the operator's intent of running native is silently lost**. The log line at `:179` vs `:190` is the only operator-visible signal. **P2 diagnostic gap.**

**TC path (`bpf_loader.cpp:210-234`)**: `bpf_tc_hook_create` with `EEXIST` tolerated (line 218) is correct — re-using an existing clsact qdisc is fine. But `bpf_tc_attach` does **not** specify an `old_prog_fd` or `BPF_TC_F_REPLACE`-equivalent flag in `tc_opts`. If a stale TC ingress program is attached at the same priority/handle slot from a previous daemon, this will fail with `EEXIST`. There is **no detach-on-load-failure** path.

In practice, the prior daemon's crash leaves the clsact qdisc and its TC programs in place. A new daemon then:
- Creates clsact: `EEXIST`, tolerated → OK.
- Tries to attach TC program at priority 0 / handle 0 → libbpf auto-allocates; if all priorities are full or the kernel collides, fails.

**P1**: on a crashed-daemon restart, TC attach is more likely to fail than XDP attach, and the failure path returns an error from `attach_tc()` → `main.cpp:202-204` → daemon exits without `detach()`. **No `loader.detach()` on the TC error path** (the deploy is done, XDP is attached, but `main.cpp` returns 1). XDP stays attached → traffic still filtered → fine for fail-stable behaviour, but the operator's view is "TC attach failed, daemon dead" with no remediation hint.

Mitigation would be: have `attach_tc()` defensively destroy any existing clsact (or query existing filters via `bpf_tc_query` and detach them) before attaching. Currently no such cleanup.

### Q4 — Native vs SKB XDP detection

The detection mechanism is **try-native-then-fallback-to-SKB**, no capability query (`bpf_loader.cpp:174-192`). The startup log is the only diagnostic:

- Line 179: `XDP attached (native)` on success.
- Line 184: `Native XDP failed on %s, trying SKB mode...` — INFO-level, would be visible.
- Line 190: `XDP attached (SKB/generic)` on SKB success.

So the mode IS visible at startup — good. But:

1. **No metric or persisted flag**: an operator looking at `pktgate` running cannot tell from `systemctl status` or Prometheus which mode it's in. The information is in the journal only.
2. **No native-required mode**: a Gi 40 Gbps deployment that silently falls back to generic XDP is 5–10× slower; pktgate has no `--require-native` flag or config option to refuse SKB.
3. **`data_meta` driver dependency (Phase 1 P1 §7 / Phase 2e)**: native XDP doesn't guarantee `data_meta` is preserved across XDP→TC handoff. Some drivers strip it. There is **no startup self-test** that verifies the data_meta path actually works against the configured iface — the operator only learns by seeing `STAT_TC_NOOP` at 100% in production.

**P1 — confirmed**: the README's "auto-detects native vs SKB" line is real, the auto-detection is simple, but there's no native-required mode and no data_meta sanity-check. Both have been called out before; this loader review confirms it isn't fixable inside `bpf_loader` alone (would need a startup `BPF_PROG_TEST_RUN` against the live entry program + TC hook).

### Q5 — Loader atomicity at startup (entry attached before prog_array populated?)

Tracing `main.cpp:168-204`:

1. `loader.load()` — line 170 — creates all maps + loads all programs. Map state: kernel zero-init (`prog_array_0/1` empty, `gen_config[0]=0`, `default_action_*=0`).
2. `pktgate::pipeline::GenerationManager gen_mgr(loader)` — line 177 — ctor only; `active_gen_=0`, shadow=1.
3. `builder.deploy(cfg, resolver)` — line 186 — internally: `prepare(shadow=1)` fills gen-1 maps + `install_programs(1)` populates `prog_array_1[*]`, then `commit()` writes `gen_config[0]=1`.
4. `loader.attach(cfg.interface)` — line 193 — entry XDP becomes live.

**At step 4, `gen_config[0]=1` and `prog_array_1[*]` is fully populated.** The first packet to hit the entry program reads gen=1, tail-calls into `prog_array_1[LAYER_2_IDX]` → fully resolved → no `STAT_DROP_ENTRY_TAIL`.

**No startup window exists** where the entry is attached but prog_array is empty. Phase 2g's lifecycle diagram has this right.

Caveat (already in Phase 2g §Q4): the **shadow generation 0 is never populated until the second deploy**. If anything triggered a flip to gen=0 before the second deploy (today nothing does — `rollback()` is dead code), all traffic would drop. This is a latent trap; the loader does NOT pre-populate `prog_array_0` or `default_action_0` at `load()` time. **P2 latent**, cross-references Phase 2g P1.

Verdict: **startup atomicity is correct by construction** (deploy precedes attach). No new P0/P1.

### Q6 — `map_manager` discovery

It is a thin wrapper, not a batch/iteration engine. Four primitives (`update_elem`, `batch_update`, `delete_elem`, `clear_hash_map`, `delete_keys`). All static. Quirks:

- `batch_update` signals "fallback needed" via `std::unexpected("batch_not_supported")` — a magic string. The caller (`generation_manager.cpp:193-208`) string-compares against it. Brittle. **P2.**
- `clear_hash_map`'s "do not advance the cursor on successful delete" pattern (lines 27-30 comment, code at line 63 sets `first=true` after each successful delete) is the correct safe-iterate-and-delete pattern for `BPF_MAP_TYPE_HASH`. Good.
- `delete_keys` treats `ENOENT` as success (line 109). Correct for the "shadow already cleared" case but does mean a typo in an LPM key would never be reported.
- No iteration support for `PERCPU_HASH` lifecycle (the rate_state map gap from Phase 2d/2g). `clear_hash_map` would work on `rate_state_map` mechanically; nobody calls it.

### Q7 — Skeleton lifecycle

Per-skeleton: `*_bpf__open()` at `load():45-63`, then `*_bpf__load()` at lines 67, 139, 143, 147, 151. **No `*_bpf__attach()` call anywhere** — pktgate does manual XDP/TC attach via `bpf_xdp_attach` / `bpf_tc_attach`, bypassing libbpf's auto-attach. Reason: libbpf's skeleton auto-attach would attach all program SECs by name; pktgate needs the explicit attach (XDP to a specific iface, TC to a specific clsact hook).

Skeletons are kept alive for the daemon's lifetime via `Impl::*` raw pointers, destroyed in `~BpfLoader` (line 35-39). FDs returned by `bpf_map__fd` / `bpf_program__fd` are owned by the skeleton — destroying the skeleton closes them. No `dup()` and no `bpf_obj_pin`. Lifecycle is therefore: program/map FDs exist exactly as long as the skeletons live, which is exactly as long as the daemon lives. Clean.

### Q8 — Error paths on partial attach failure

`main.cpp:193-204`:

```cpp
auto ar = loader.attach(cfg.interface);
if (!ar) {
    LOG_ERR("XDP attach failed: %s", ar.error().c_str());
    return 1;       // <-- destructor runs, detach() is no-op (attached_=false)
}
auto tr = loader.attach_tc(cfg.interface);
if (!tr) {
    LOG_ERR("TC attach failed: %s", tr.error().c_str());
    return 1;       // <-- destructor runs: detach() removes XDP, detach_tc() no-op
}
```

**XDP-then-TC ordering means: if TC fails, XDP gets cleaned up by the destructor.** The destructor is `~BpfLoader() { detach(); detach_tc(); ... }` (line 31-33). On the TC-fail path, `attached_=true` → destructor's `detach()` removes XDP. The daemon exits cleanly without traffic flowing through a half-configured pipeline.

**But**: the deploy already ran (line 186) — `gen_config[0]=1`, all maps populated, prog_array installed. None of that is cleaned up because the maps are pinned to the entry skeleton, which gets destroyed → maps closed → kernel GCs them. So no leak, no stale state. **Verdict: error paths are clean.**

One edge: if `attach()` succeeds but the `tr` check `!loaded_` fires (impossible after `load()` succeeded — same `loaded_` flag), no issue. There's no "rollback XDP attach on TC failure" code, but the destructor handles it.

### Q9 — Detach on SIGTERM, "stay active across restart" mode

`main.cpp:278-279`:

```cpp
loader.detach_tc();
loader.detach();
```

`detach_tc()` (`bpf_loader.cpp:246-263`) destroys the **entire clsact qdisc** (line 253-255: `BPF_TC_INGRESS | BPF_TC_EGRESS`), which removes all TC programs on both directions. Aggressive — if the operator had any other (non-pktgate) TC filter at egress, it's gone. **P2 collateral risk**, mostly latent because nothing else typically lives there.

`detach()` (`bpf_loader.cpp:237-244`) calls `bpf_xdp_attach(ifindex, -1, attach_flags_, ...)` — the `prog_fd=-1` form is the libbpf-supported way to detach. Correctly uses the same mode flag the attach used (DRV or SKB) — important because mode-mismatched detach fails.

**No `--ifdetach-on-exit=no` flag** or equivalent. The cleanup is unconditional on graceful exit. So an operator stopping the daemon for a quick restart **loses filtering** for the duration of the gap. Customer brief's "no noticeable latency, no throughput impact on 40 Gbps Gi" implies graceful degradation is acceptable (since fail-open is the brief's other ask), but a `--keep-attached` mode would be a useful operator knob.

**`detach_tc()` ordering quirk** (`bpf_loader.cpp:259-262`): `attach_ifindex_` and `attach_flags_` are reset **only if `!attached_`**. So calling `detach_tc()` before `detach()` (which main.cpp does) leaves ifindex/flags set; then `detach()` consumes them and clears `attached_`. The next time anyone calls a method on this loader, the reset will run. Functionally correct, but the ordering coupling is implicit. Destructor (`~BpfLoader`) reverses the order (`detach()` then `detach_tc()`) and still works — `detach_tc()` reads `attach_ifindex_` first (line 247-249) before the `if(!attached_)` reset block. **OK by inspection, brittle by design. P2.**

### Q10 — SIGKILL / crash behaviour

On SIGKILL, no destructors run. The kernel does:
- Closes all FDs held by the dying process.
- XDP program: FD closed, but the kernel-level **attachment** (program installed on the iface's `xdp_prog`) persists because the kernel holds an independent reference once attached. Same for the TC program attached to the clsact qdisc.
- Maps: ref-counted; the BPF programs hold refs. Maps survive because the kernel-attached programs hold them.

**Net effect on SIGKILL**: XDP and TC both continue running with the **last loaded generation's maps frozen at their last committed state**. The data plane keeps filtering. This is **correct fail-stable behaviour** as the question stated — confirmed.

A subsequent daemon start will encounter the stale-attached case (Q3): same-mode XDP attach will succeed via replace; TC attach is the riskier path because `EEXIST` on the filter is not handled. **The crash-recovery story is therefore: XDP heals automatically, TC needs operator intervention (`tc qdisc del dev IFACE clsact`) to recover cleanly.** P1 unless TC defensive cleanup is added.

### Q11 — FD ownership and leaks

Every FD-returning accessor (`{l2,l3,l4,subnet,...}_fd`, `gen_config_fd`, `rate_state_fd`, `stats_map_fd`, `*_prog_fd`) uses `bpf_map__fd` / `bpf_program__fd` directly on the skeleton. **No `dup()`, no stored caches.** The integer is non-owning; the skeleton owns. Lifecycle is unambiguous: FDs are valid for the lifetime of the skeleton, which is the daemon. No leaks. No double-close. Clean.

The one `bpf_map__reuse_fd` call (TC stats_map, line 128) is the libbpf-correct way to point one skel's map slot at another's already-created kernel object — libbpf takes care of ref-counting; the caller does not need to track the FD separately.

### Q12 — Anything surprising

- **Macro-defined reuse loops** (lines 72-110 and 124-135): two near-duplicate `REUSE_MAP` / `REUSE_TC_MAP` macros, each defined and `#undef`ed inline. Not a bug, but a single shared helper templated over `Skel*` (or a constexpr list of map names) would compress 23 lines of identical reuse calls. P2 ergonomics.
- **`int err` shadow at lines 66 and 82**: the outer `err` (line 66) is shadowed by the inner `err` declared inside the lambda (line 82). The macro `REUSE_MAP` assigns to "err" — which one? It binds to the **inner** `err` due to lookup. Outer `err` is used at line 67-69 (entry load) and lines 139-153 (later layer loads). The inner err is the lambda-local. No actual bug because the inner err is only read inside the lambda; but the shadowing is unhygienic and would confuse a maintainer. **P2 cleanup.**
- **`tc_attached_` and `attached_` share `attach_ifindex_`**: the same field tracks both. If a hypothetical future caller did `attach(ethA)` and then `attach_tc(ethB)`, the second call would overwrite `attach_ifindex_` and the detach path would be wrong. Today both always go to `cfg.interface` so impossible — but a `static_assert` or a separate `tc_ifindex_` would harden it. **P2.**
- **`is_loaded()` getter** exists on the header but isn't called anywhere I can see (would have to grep — not done; mention as P2 dead-API candidate).
- **No `bpf_map__set_pin_path`** anywhere — maps are explicitly not pinned to bpffs. Consistent with the owner note (no zero-downtime restart story today) and with Phase 2g's lifecycle assumption.
- **`bpf_xdp_attach_opts opts` is initialized empty** (`LIBBPF_OPTS(...)`, line 173) and never populated with `old_prog_fd`. So the kernel uses default-replace semantics. Correct, but a comment naming this would help.
- **No log on `attach_tc` priority allocation**: the log line (line 232-233) reports `tc_opts.handle` and `tc_opts.priority` post-attach, which is good for diagnosability of "which slot did libbpf pick?". One of the few well-instrumented spots.

## Additional findings

1. **The TC reuse block is silently single-purpose.** The macro is named `REUSE_TC_MAP` but used exactly once. If a TC ingress change adds a new map reference (e.g., reading `gen_config` to gate behaviour by generation), the developer needs to add a `REUSE_TC_MAP(...)` line, and there's no compile-time check that the TC skeleton's map symbols are exhaustively reused. **A stale-map-in-TC-skel** scenario today: only `stats_map` is in the TC source, so no risk; latent for future changes. P2.

2. **No fail-mode for "TC attach failed but XDP attached"**. As §Q8 shows, the destructor cleans up XDP if TC fails — but the daemon exits with code 1. There's no fallback "continue without TC" mode (which would degrade `mirror`/`tag` actions but keep filtering working). Customer-brief fail-open expectation isn't fully met: an operator that doesn't use mirror/tag actions still loses everything if TC attach fails. P2 ergonomics.

3. **Detach is unconditional and removes the entire clsact qdisc**, including egress (`bpf_loader.cpp:253-255`). If anything else attached an egress TC filter on the same iface, pktgate's stop nukes it. Surprising side effect. P2.

4. **No verification at attach() that the entry's first deploy ran.** The `loaded_` check guards "we loaded BPF", but nothing prevents an `attach()` before any `commit()` — which would attach an entry that reads `gen_config[0]=0` (kernel default) → tail-call to empty `prog_array_0` → all packets `STAT_DROP_ENTRY_TAIL`. `main.cpp` happens to deploy before attach (good), but the loader API doesn't enforce it. Defensive `assert` or `attached_after_deploy_` flag would document the contract. P2.

5. **The XDP fallback log "Native XDP failed on %s, trying SKB mode..."** (line 184) is INFO level. On a Gi production NIC where native is required, this should be a WARN with the underlying errno included. Currently the operator gets no `errno` hint about *why* native failed. Diagnostic gap. P2.

## Lifecycle table

| Phase | Step | Effect on data plane | Map state |
|---|---|---|---|
| **Startup: load** | `BpfLoader::load()` | none (no attach) | All maps kernel-zero-init: `gen_config[0]=0`, `prog_array_{0,1}` empty, `default_action_{0,1}=ACT_DROP` |
| **Startup: deploy** | `builder.deploy()` → `prepare(1)` + `commit()` | none (still no attach) | gen-1 maps populated; `prog_array_1[*]` populated; `default_action_1` set; `gen_config[0]=1` |
| **Startup: attach XDP** | `loader.attach()` | XDP live | Same; first packet reads gen=1, finds prog_array_1 populated → correct |
| **Startup: attach TC** | `loader.attach_tc()` | TC live for deferred actions | clsact qdisc created; TC ingress prog attached |
| **First packet** | enters entry XDP | uses gen-1 pipeline | All consistent |
| **Reload (success)** | `do_reload()` → `prepare(0)` → `commit()` → flip `gen_config[0]=0` | in-flight packets see either gen, both populated | gen-0 now populated; usleep(100ms) drain |
| **Reload (failure)** | `prepare(0)` returns error | no change to live traffic | shadow may carry partial state (Phase 2g P2) |
| **SIGTERM** | main loop exits, `detach_tc()` + `detach()` | XDP removed, TC removed, traffic flows unfiltered | Skeleton destruction closes FDs; kernel GCs maps |
| **SIGKILL** | no cleanup | **XDP + TC stay attached, last gen's maps frozen** → filtering continues | Maps held by kernel-attached programs; daemon restart faces stale-attach |
| **Restart after SIGKILL** | new `load()` + `attach()` | XDP same-mode: silently replaces stale | TC: `bpf_tc_attach` may fail with `EEXIST` on stale filter — **P1, no remediation** |
| **Destructor** | `~BpfLoader` | `detach()` then `detach_tc()` then `*_bpf__destroy` | All FDs closed; maps GCd if no other holders |

## Findings (graded)

```
- [P1 NEW] Stale TC ingress filter after SIGKILL is not handled at restart
  Where: src/loader/bpf_loader.cpp:198-234 — attach_tc()
  What: bpf_tc_hook_create tolerates EEXIST (line 218, correct), but
        bpf_tc_attach is called WITHOUT BPF_TC_F_REPLACE-equivalent
        and without first detaching any stale filter. After SIGKILL,
        the prior daemon's TC ingress program remains attached at
        the auto-allocated priority; the new daemon's bpf_tc_attach
        races for the same slot and may fail with EEXIST. There is no
        cleanup path. Operator must `tc qdisc del dev IFACE clsact`
        manually before restart.
  Why it matters: customer brief asks for fail-safe behaviour;
        SIGKILL is the canonical crash. XDP self-heals on restart
        (same-mode replace), but TC doesn't. Asymmetric recovery.
  Suggested action: in attach_tc(), defensively query existing TC
        ingress filters (bpf_tc_query loop) and detach them before
        bpf_tc_attach. Or pass BPF_TC_F_REPLACE through tc_opts.
        Alternative: detach the clsact qdisc on attach_tc() entry,
        then recreate — heavier, but guaranteed clean slate.

- [P2] Cross-mode stale XDP attach silently demotes to SKB
  Where: src/loader/bpf_loader.cpp:172-192 — attach()
  What: bpf_xdp_attach with no UPDATE_IF_NOEXIST means "replace".
        Same-mode stale: silent replace (no log). Cross-mode stale:
        EBUSY on first attempt → falls back to SKB → succeeds via
        replace of the stale SKB attach. The operator who intended
        native XDP gets generic and only sees "XDP attached (SKB/
        generic)" in the log — no indication that they expected
        native and got demoted by a stale attachment.
  Why it matters: a 5-10x slowdown that hides behind a log line the
        operator might not check.
  Suggested action: detect the stale-replace case via bpf_xdp_query
        before attach; log WARN if replacing; provide --require-
        native to refuse SKB fallback.

- [P2] detach_tc() destroys entire clsact qdisc (incl. egress)
  Where: src/loader/bpf_loader.cpp:253-255
  What: hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS before
        bpf_tc_hook_destroy. This removes all TC filters on both
        directions, not just pktgate's ingress filter. Any other
        software attached to egress (e.g., an unrelated tc-htb
        shaper) is collaterally removed.
  Why it matters: in a multi-tenant deployment, pktgate stop nukes
        unrelated traffic-control configuration on the same iface.
        Surprising, undocumented.
  Suggested action: detach the specific TC ingress program slot
        (using stored handle/priority from attach_tc) rather than
        destroying the qdisc. Only destroy the qdisc if pktgate
        created it (track creation via the EEXIST-vs-success
        distinction at line 217-220).

- [P2] No native-XDP-required mode, no errno on fallback
  Where: src/loader/bpf_loader.cpp:174, 184
  What: LOG_INF on native failure, no errno reported. No CLI / config
        knob to refuse SKB. For a 40Gbps Gi target, native is
        mandatory; the daemon should be able to fail-loud when it
        can't get it.
  Suggested action: log errno on native failure, add --xdp-mode=
        {auto,drv,skb} with strict mode rejection.

- [P2] No data_meta self-test at startup
  Where: src/loader/bpf_loader.cpp attach() / attach_tc()
  What: The Phase 1 P1 §7 / Phase 2e finding "data_meta preservation
        across XDP→TC is driver-dependent" has no diagnostic at
        startup. Symptom (STAT_TC_NOOP at 100%, mirror/tag silently
        not firing) only appears in production.
  Suggested action: at the end of attach_tc(), use BPF_PROG_TEST_RUN
        on the live entry program with a sentinel packet, then
        verify the TC program receives the expected pkt_meta. If
        not, fail-loud or refuse to continue.

- [P2] No `attached_after_deploy_` invariant enforced
  Where: src/loader/bpf_loader.cpp attach()
  What: API permits attach() before any deploy. With prog_array_0
        empty and gen_config[0]=0 (kernel default), every packet
        drops with STAT_DROP_ENTRY_TAIL. main.cpp orders deploy
        before attach (correct), but the loader API doesn't enforce.
  Suggested action: track "first commit succeeded" via a callback
        from GenerationManager, refuse attach until set; or
        document the contract loudly.

- [P2] REUSE_MAP / REUSE_TC_MAP macros duplicate; unhygienic shadow
  Where: src/loader/bpf_loader.cpp:72-110, 124-135; int err shadow
         at lines 66 vs 82
  What: Two near-identical macros, both inline-defined-and-undef'd.
        Inner lambda `int err` shadows the outer `int err` used by
        entry/layer/tc loads. Refactor into a single helper taking
        a span of map names. P2 ergonomics + minor readability.

- [P2] batch_update fallback signal is a magic string ("batch_not_
       supported")
  Where: src/loader/map_manager.cpp:97
  What: caller (generation_manager.cpp:193-208) string-compares.
        Brittle to typo; localised. Use a dedicated error type or
        an enum-coded outcome.

- [P2 latent] prog_array_0 / default_action_0 never written until
              second deploy
  Where: src/loader/bpf_loader.cpp load() doesn't pre-populate
  What: Phase 2g Q4 finding. Loader could initialise both gens'
        prog_array and default_action to safe defaults at load
        time. Currently relies on the deploy-before-attach ordering.
        Latent rollback-to-virgin-gen-0 trap (Phase 2g P1).
  Suggested action: at end of load(), write prog_array_{0,1}[L2,L3,
        L4] = (layer prog FDs) and default_action_{0,1}[0] =
        ACT_DROP. Makes rollback safe to use.
```

## Test-audit notes

- **Stats_map reuse confirmation**: a unit-level test of "after load(), `bpf_map__fd(entry.stats_map) == bpf_map__fd(tc_ingress.stats_map)`" would catch any future regression in the reuse block. Trivially writable in `test_pipeline_integration.cpp`. **Test class: absent.** Given this is the **most likely place for a future regression** (someone adds a new TC-referenced map and forgets the reuse), one line of code adds a regression check.
- **Stale-XDP / stale-TC restart**: no test exercises the SIGKILL-then-restart path. `functional_tests/test_zz_*` lifecycle tests likely cover normal start/stop, not crash recovery. **Test class: absent.** This is the test that would have caught the TC-stale-EEXIST P1.
- **Native-vs-SKB fallback**: cannot be tested without a NIC that supports both. veth is SKB-only, so the fallback path is exercised by every functional test (they all log "Native XDP failed... trying SKB"). The native path itself is unexercised in CI. **Test class: environment-dependent gap.**
- **data_meta preservation**: same as above — only the SKB path is exercised in CI, which DOES preserve data_meta on Linux. The Phase 1 P1 driver-dependency-on-native bug class has zero CI coverage. **Test class: adversarial coverage on the driver invariant, absent.**
- **Loader error paths**: `tests/test_pipeline_integration.cpp` likely covers happy path. A test that injects a load failure (e.g., kernel rejects the program) and asserts clean teardown — almost certainly absent. **Test class: fault-injection at loader layer absent.**

## Open issues for later phases / consolidation

- **Phase 3 (cross-cutting)**: the TC-restart-EEXIST P1 belongs in the "operability / fail-safe" cluster alongside Phase 1's no-watchdog P0 and the customer-brief asks for bypass mode.
- **Tests phase**: stats_map reuse regression check is a one-liner; native-XDP path needs a NIC-attached CI tier (out of scope per project state).
- **For `99_REPORT.md` consolidation**:
  - Move "stats_map reuse confirmed" from Phase 1 §2 / Phase 2f §3 open-list → closed.
  - Add the TC-stale-attach as a new P1.
  - Merge "no native-required mode" and "no data_meta self-test" with the existing Phase 1 P1 §7 data_meta driver dependency entry — they're aspects of the same operational gap.
  - The latent prog_array_0 / default_action_0 pre-population would deliver Phase 2g's "make rollback safe" option (b) with zero cost; reference both phases when consolidating.
