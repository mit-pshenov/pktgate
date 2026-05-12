# 10 — `src/pipeline/generation_manager.cpp` (Phase 2g)

## What this module does

`GenerationManager` owns the per-generation BPF map population, the atomic `gen_config[0]` flip, and (per-generation) prog_array installation. It is the single deploy-time author of every double-buffered map. Calling order from `PipelineBuilder::deploy()` (`src/pipeline/pipeline_builder.cpp:60-74`): `prepare(objects, rules, default_action)` then `commit()`. `rollback()` is declared in the public API (`src/pipeline/generation_manager.hpp:29`) but **never invoked anywhere outside of unit-test mocks** — grep confirms only `tests/test_generation_logic.cpp` and `tests/test_concurrency.cpp` call `.rollback()`, and both use bespoke mocks (`tests/test_generation_logic.cpp:34`, `tests/test_concurrency.cpp:35`), not the real `GenerationManager`. The class is touched only from `main.cpp`'s single-threaded reload loop; the Prometheus exporter thread reads only `loader_.stats_map_fd()` (`src/metrics/prometheus_exporter.hpp:239`), never `gen_mgr`.

## Per-question findings

### Q1 — `rate_state_map` lifecycle (Phase 2d P1)

Confirmed: **`bpf_map_delete_elem` is never called against `rate_state_map`** from anywhere in the userspace tree. `grep -rn "rate_state\|bpf_map_delete_elem" src/` returns: `bpf_loader.{hpp,cpp}` only mention it for `REUSE_MAP` and `rate_state_fd()` (`src/loader/bpf_loader.cpp:106, :348-350`), and `map_manager.cpp:18,54,107` define generic delete primitives that no one applies to this fd. `generation_manager.cpp` never references `rate_state_fd()` nor any rate_state symbol. `rule_compiler.cpp:280` has a comment about it being PERCPU; that's the only other mention.

`rule_id` is operator-supplied (`src/config/config_parser.cpp:11` reads `j.at("rule_id")`); the compiler never reassigns it (`src/compiler/rule_compiler.cpp:121,208,267` propagate `rule.rule_id` verbatim). Therefore:

- If operator keeps `rule_id` stable across reloads (the natural style — operators edit configs in place), **the dominant failure mode is "rate change silently does not apply"**: bucket persists with old `rate_bps` until the daemon restarts (and even then, only because PERCPU_HASH is not pinned; if pinning is ever added, it survives daemon restart too).
- If operator reshuffles `rule_id` (e.g., regenerates from a template), **dead entries leak**. `MAX_RATE_ENTRIES = 4096` (`bpf/common.h`). After 4096 unique rule_ids the kernel returns -E2BIG on `BPF_ANY` insert; `do_rate_limit` ignores the return value (`bpf/layer4.bpf.c:32`), so `rs` stays NULL on the next-packet path, the if-rs guard fires (line 35 — re-checks lookup), and the entry never materialises → rate-limit silently passes everything.

Phase 2d P1 is confirmed end to end, no retraction. Add: lifecycle = unbounded growth across daemon lifetime, no GC primitive, no double-buffering, no design intent expressed anywhere.

### Q2 — Rollback shadow-clear (Phase 1 P1)

Confirmed verbatim: `rollback()` (`generation_manager.cpp:310-323`) does **only** the `gen_config[0]` flip and the in-memory `active_gen_.store(old_gen)` (lines 316-320). No `clear_shadow_maps(now_shadow)` call. No `lpm_keys_[]` touch.

Self-healing claim from Phase 1 §7: after a rollback, the next `prepare()` for the now-shadow generation calls `clear_shadow_maps(gen)` at line 236 — confirmed at `generation_manager.cpp:235-237`. The first thing prepare does. **So yes, self-heals on next reload**, exactly as Phase 1 said.

New observation that Phase 1 missed: **rollback is never invoked from production code**. Searched all of `src/` and `tools/`: only test mocks call it. So the P1 is latent twice over — first because the bug self-heals on next reload, second because the buggy path is never reached. Downgrade is warranted only if you also intend never to wire rollback in; otherwise the latent risk remains because **rollback to a never-deployed generation hits a worse bug** (see Q4 / Additional finding #1).

### Q3 — `clear_shadow_maps` partial-failure behaviour

`clear_shadow_maps` (`generation_manager.cpp:49-90`) is **abort-on-first-error**: every step is `if (!r) return std::unexpected(...)`. Eight sequential steps (5 L2 hash maps, 2 LPM tries, VRF hash, L4 hash). On step N failure, steps N+1..8 are skipped; shadow may carry stale entries in any of those maps.

LPM list pruning behaviour (`generation_manager.cpp:67-81`): if `delete_keys` returns error, **`lpm_keys_[gen].clear()` is NOT called** — the list still contains every key, including those `delete_keys` already deleted. Re-running delete_keys is safe because the kernel returns ENOENT for already-deleted keys and `delete_keys` (`src/loader/map_manager.cpp:108-114`) treats ENOENT as success (per-key, no error counted).

**The hash-map cleanup (`clear_hash_map`, `map_manager.cpp:23-72`) does NOT abort on first error** — it logs and continues (`errors++`, line 56), advances the cursor past the un-deletable key (line 58), and returns aggregate error at the end. **Inconsistent with `clear_shadow_maps`'s per-map abort-on-first-error**: the inner cleanup is best-effort, but the outer orchestrator gives up on the first map-level failure. Net behaviour: a single -EBUSY on one L2 map prevents the L4 map from being cleared, so the shadow can carry both old L4 rules and old VRF rules even though the LPM was already wiped.

State left behind is mostly **eventually consistent**: next prepare's clear-then-populate sequence retries everything. The one place this **isn't** self-healing is when `clear_shadow_maps` is called as the best-effort cleanup *inside* a failing prepare (`generation_manager.cpp:242, 248, 254, 260, 266, 272, 279`) — its return value is **discarded**. Prepare returns the original error; the shadow's true state is silently degraded. Combined with the LPM key-list non-cleared-on-error path above, the next prepare WILL try to delete the same keys again (ENOENT-safe) so functionally fine, but the loss of error visibility is a debuggability bug.

Verdict: **P2 (debuggability), self-heals in current usage**. Would become P1 if pinned bpffs maps were ever introduced (state survives daemon restart, no clear-on-startup).

### Q4 — prog_array atomicity at commit (Phase 2b P2)

Order inside `prepare()` (`generation_manager.cpp:229-285`):
1. `clear_shadow_maps(shadow_gen)` — line 236
2. `populate_l2_maps` — line 240
3. `populate_subnet_map` — line 246
4. `populate_subnet6_map` — line 252
5. `populate_vrf_map` — line 258
6. `populate_l4_map` — line 264
7. `set_default_action(shadow_gen, default_action)` — line 270
8. `install_programs(shadow_gen)` — line 277

`commit()` (`generation_manager.cpp:287-308`) is the **first** code to touch `gen_config`. So at the moment of the atomic flip:
- shadow maps are fully populated
- shadow default_action is set
- shadow prog_array is fully populated

**prog_array population is BEFORE the `gen_config[0]` update.** The L3-asymmetry-window from Phase 2b (matched-rule drop / no-match default) **cannot open via commit**. Confirmed: data-plane reads of `prog_array_{new_gen}[LAYER_4_IDX]` after the commit's atomic flip always see a populated slot.

However, **rollback re-opens the window for a never-deployed generation**. Concrete scenario:

- Initial state after `main.cpp:177` constructs GenerationManager: `active_gen_ = 0`, so `shadow_generation() = 1`.
- First `prepare()` populates **gen 1**, including `install_programs(1)`. `prog_array_0` is **never touched**.
- First `commit()` flips `gen_config[0] = 1`. Traffic uses gen 1 maps + prog_array_1. OK.
- If `rollback()` were now called: flips `gen_config[0] = 0`. **Data plane reads `prog_array_0[*]` which has been zero/empty since program load**. `entry.bpf.c:49-52` tail-calls `prog_array_0[LAYER_2_IDX]` → fails → falls through to `STAT_INC(STAT_DROP_ENTRY_TAIL)` and `XDP_DROP`. **All packets drop until the next successful prepare(0) → commit().**
- Plus: `default_action_0[0]` was never written by userspace, so kernel-zero-init = `ACT_DROP = 0` (`bpf/common.h:38`). Even if prog_array were OK, default would silently be DROP rather than the operator's configured default.

This is a **rollback-to-never-deployed-gen-0** failure mode that Phase 1 §7 didn't articulate. Since rollback is dead code today, it's latent — but the *invariant* that "rollback restores a known-good state" is false on the first reload. The fix is one of: pre-populate prog_array_0 with the loaded program FDs at loader startup; or make `rollback()` refuse to flip to a generation whose prog_array has never been installed; or make rollback unreachable (delete the dead method and document).

Verdict: prog_array atomicity contract holds for commit; **fails on rollback to first-time-shadow**. Promote rollback finding to **P1** (was P1 in Phase 1, but for a different and softer reason).

### Q5 — Drain (`usleep(100ms)`)

Confirmed at `generation_manager.cpp:300-307`: literal `usleep(100000);` with a 7-line comment. **No conditional. No acknowledgement-based drain.** Phase 1 §3 stands. The drain is inside `commit()`, AFTER the `gen_config[0]` update and AFTER `active_gen_.store(new_gen)` — so the userspace's notion of "active" is the new gen, but it then sleeps before returning to the caller. Note: under a kernel-thread NMI / extreme load the bound is not actually 100 ms — XDP per-packet runtime is microseconds, but the scheduler can preempt the userspace thread for longer than that elsewhere. As-implemented this gives the data plane a 100 ms wall-clock window to drain. Not correctness-violating in steady state, but the "drain" framing is a calendar promise not a synchronisation primitive.

### Q6 — Locking / thread-safety

`GenerationManager` is touched from one writer thread (the main loop in `main.cpp` doing `do_reload`). There is **no mutex** anywhere in the class — `active_gen_` is `std::atomic<uint32_t>` (`generation_manager.hpp:52`) which provides ordering for the readers. The `lpm_keys_[2]` arrays and the `loader_&` are accessed without any synchronisation, but only the reload thread touches them. The Prometheus exporter runs in its own thread (`src/metrics/prometheus_exporter.hpp:184`) but only reads `loader_.stats_map_fd()` — never touches `gen_mgr`. SIGUSR1 stats dump (`main.cpp:267-270`) is in the same main-loop thread; safe. The SIGHUP/inotify reload guard at `main.cpp:34-38` is a `static bool reloading` — single-threaded, so the guard is sufficient.

Verdict: **no concurrent access**, no locking needed. The atomic on `active_gen_` is for readers that don't currently exist (defensive; harmless).

### Q7 — Error propagation in prepare

Each step in prepare returns `std::expected<void, std::string>`. On error from `populate_*` or `set_default_action`, the code calls `clear_shadow_maps(gen)` as best-effort cleanup and returns the original error (e.g., lines 240-244). The cleanup error is **discarded** — `clear_shadow_maps`'s result is captured into an unnamed temporary on lines 242, 248, 254, 260, 266, 272, 279, and only the populate error propagates upward. If `clear_shadow_maps` itself fails the operator never knows; the prepare error is the populate error, not "we also couldn't clean up".

If `install_programs` (line 277) fails after maps were already populated, cleanup is called (line 279). But `clear_shadow_maps` does NOT clear prog_array — the prog_array installs that DID succeed (e.g., LAYER_2_IDX populated, LAYER_3_IDX failed) stay populated in the shadow. Next prepare's `install_programs` overwrites with `BPF_ANY`, so self-heals. (`prog_array` entries point at FDs that don't change across reloads — the loader loads programs once at startup. So a "stale" prog_array entry is by definition equal to the entry the next install would write.)

If the very first `clear_shadow_maps(gen)` at the top of prepare fails (line 237), prepare returns immediately without populate-or-cleanup. Active is intact. Next reload's clear retries.

### Q8 — `lpm_keys_[2]` lifecycle

Populated:
- `populate_subnet_map` (`generation_manager.cpp:142-145`) — per successful `bpf_map_update_elem`, push the key bytes into `lpm_keys_[gen]`. Per-element granularity; if `update_elem` fails partway, the keys for successful inserts ARE in the list (good — they need to be deleted on cleanup).
- `populate_subnet6_map` (`generation_manager.cpp:156-159`) — symmetric for `lpm6_keys_[gen]`.

Read by `clear_shadow_maps` (`generation_manager.cpp:68-81`) — uses the stored byte vectors as keys to `bpf_map_delete_elem` via `delete_keys`.

Cleared: **only on successful `delete_keys`** (`generation_manager.cpp:72, 80`). On `delete_keys` error, the list is preserved — next clear retries (safe per ENOENT handling).

Re-prepare-same-generation case (e.g., commit fails so prepare retries with same shadow): the next prepare's first action is `clear_shadow_maps(gen)` (line 236) which iterates the existing `lpm_keys_[gen]`, deletes each, clears the list. Then populate pushes new keys. **Correct.**

But there's a subtle issue: `populate_subnet_map` and `populate_subnet6_map` **append** to the list (`emplace_back`). If `clear_shadow_maps` ran successfully (list cleared) and populate then errored mid-way, the list has just the successful inserts — good. If `clear_shadow_maps` failed (list not cleared), and then populate ran anyway (it would not, prepare aborts on clear failure at line 237) … so this case is impossible. OK.

**However**: the "best-effort cleanup" paths at lines 242, 248, 254, 260, 266, 272, 279 swallow the cleanup error. If cleanup fails after populate_subnet_map ran successfully, the LPM list has the freshly-populated keys; next prepare's clear retries (ENOENT-safe). Eventually consistent. No real bug.

### Q9 — Other maps beyond rules

- **`stats_map`** (`bpf/maps.h:200-205`): shared, NOT double-buffered, PERCPU_ARRAY. `GenerationManager` **never touches it** — neither writes nor clears. Stats accumulate across deploys for the daemon's whole lifetime. Reset only on daemon restart (kernel re-initialises on map create). Consistent with Phase 1 (Prometheus exposes them; no reset). Not a finding.
- **`gen_config`** (`bpf/maps.h:11-16`): single ARRAY, max_entries=1. Written **only** by `commit()` (line 293-294) and `rollback()` (line 316-317). Never cleared. Initial kernel value is 0. So on first `commit()` (which writes new_gen = shadow = 1), the data plane goes from "all packets drop because prog_array_0 is empty" to "use gen 1 maps". **But XDP is attached AFTER the first deploy** (`main.cpp:186` deploy → `main.cpp:193` attach), so traffic never sees the empty gen 0 state. Lucky-by-construction.
- **`default_action_0/1`** (`bpf/maps.h:184-196`): single-element ARRAY each. Written only by `set_default_action` (`generation_manager.cpp:211-226`) which is called once per prepare on the SHADOW generation. **`default_action_0` is never written if the first deploy populates gen 1 (which it does because `active_gen_=0` → shadow=1)**. Its kernel-init value is 0, which equals `ACT_DROP`. This is the rollback-to-virgin-gen-0 trap described in Q4. Not a finding for current code (rollback unused), but the latent danger is real.
- **`rate_state_map`**: see Q1.
- **`prog_array_{0,1}`**: see Q4. Written only in `install_programs`. The unused index `LAYER_3_IDX=1`'s entry is also written despite L2's tail-call to L3 going through `prog_array[LAYER_3_IDX]` — never cleared.

### Q10 — `set_default_action` placement

Called at `generation_manager.cpp:270`, between `populate_l4_map` (line 264) and `install_programs` (line 277). So:

- Order within prepare: rules first, then default, then programs. Default is set on shadow → no visible effect until commit flips.
- Commit's atomic gen_config update happens after all of the above. The data plane reads `default_action_{new_gen}` only after commit's flip. **No window where the new gen is active but its default is stale.**
- For the L4-fallback "no rule matched" path (`bpf/layer4.bpf.c:85-88`): reads `default_action_{meta->generation}[0]`. Since `meta->generation` is read from `gen_config` at `entry.bpf.c:46`, and `gen_config` is flipped atomically by commit, the (generation, default_action) pair is consistent.

Verdict: correct ordering. No new finding.

### Q11 — Surprises

1. **`install_programs` uses `BPF_ANY`**, not `BPF_NOEXIST`. Idempotent given FD stability across reloads, but if a future change ever reloaded programs at runtime, the prog_array would temporarily hold stale FDs until install_programs ran. Not a bug today.
2. **`set_default_action` defaults unrecognised `config::Action` values to `ACT_DROP`** (`generation_manager.cpp:220`). Includes `Action::Redirect`, `Action::Mirror`, `Action::Tag`, `Action::RateLimit` — all of which the validator should never let through to the top-level `default_behavior` but if it did, fail-closed is reasonable. Minor.
3. **`populate_l4_map` batch fallback** (`generation_manager.cpp:193-208`): on batch error of any kind (not just "not supported"), falls through to sequential. If the batch failed because of E2BIG (map full), sequential will hit the same E2BIG on the (cnt)-th entry, leaving the L4 map partially populated. Best-effort cleanup at `:266` will then run, hash-iterate the L4 map, and delete what's there. Works.
4. **No verification that `loader_.X_fd(gen)` returns ≥ 0 in `populate_*`** — e.g., `populate_subnet_map:136` does `int fd = loader_.subnet_rules_fd(gen);` without checking the return. If the loader is in a broken state (FD < 0), `bpf_map_update_elem(-1, ...)` returns -EBADF and we get a generic "subnet_rules insert (rule N): Bad file descriptor" error. Diagnosable but late. Could be checked at the top of each populate. P2.
5. **`install_programs` does check** `fd < 0` for each prog FD (lines 26, 33, 39) and for `pa_fd` (line 18). Inconsistent style with populate_* but defensible — install is the path most likely to be called early before all programs are loaded.
6. **`shadow_generation() = active_gen_ ^ 1`** (`generation_manager.hpp:32`). Always opposite of active. So consecutive failed prepares always retry on the same shadow — correct.
7. **`active_gen_` is set BEFORE the `usleep(100ms)`** (`commit():297`, sleep at `:306`). Userspace's `active_generation()` getter returns the new gen during the drain window. If any reader were to use this to decide map-touching behaviour during the drain (e.g., a stats reader filtering by gen) it would touch the new gen prematurely. Today, nothing reads gen this way. Defensive cleanup: set after drain. P2.

## Additional findings

1. **`rollback()` is dead code in production**, and the first call path (rolling back to never-deployed gen 0) hits two latent traps simultaneously: empty prog_array_0 (all packets drop via `STAT_DROP_ENTRY_TAIL` from `entry.bpf.c:55`) and zero-initialised `default_action_0[0]` (= `ACT_DROP`). The Phase 1 P1 "rollback doesn't clear shadow" is correct but understates the issue: rollback as currently implemented is also unsafe to *use*. Either delete the method, or fix all three trapdoors.
2. **No size-cap enforcement at deploy time** for any of the per-map populates. Compiler doesn't check (Phase 2a P1); GenerationManager doesn't either — relies on kernel returning -E2BIG. Generic error message; user has no idea which map filled.
3. **Error messages drop the failing-map context** for hash-map clears: `clear_shadow_maps` prefixes with the map name (`"clear l2_src_mac:"` etc.) but the underlying `clear_hash_map` aggregates "N delete(s) failed out of M" without naming which entries. Hard to debug "why is one entry stuck".
4. **No structured logging of `lpm_keys_[gen].size()` on either populate or clear** — operator has no telemetry on shadow LPM key cardinality across deploys. Cosmetic.

## Lifecycle diagram (text)

```
=== DAEMON STARTUP (main.cpp:177-204) ===
[GenMgr ctor]   active_gen_ = 0;  shadow = 1
                lpm_keys_[0,1] empty;  lpm6_keys_[0,1] empty
[loader.load()] all maps created by kernel:
                  gen_config[0]      = 0      (kernel zero-init)
                  default_action_0/1 = 0,0    (kernel zero-init → ACT_DROP!)
                  prog_array_0/1     = -1/-1  (no programs installed)
                  all other maps     = empty

=== FIRST DEPLOY (PipelineBuilder::deploy → prepare → commit) ===
prepare(shadow=1):
  clear_shadow_maps(1)      — no-op (everything already empty)
  populate_l2_maps(1)       — fills l2_*_1 maps
  populate_subnet_map(1)    — fills subnet_rules_1, lpm_keys_[1] += {keys}
  populate_subnet6_map(1)   — fills subnet6_rules_1, lpm6_keys_[1] += {keys}
  populate_vrf_map(1)       — fills vrf_rules_1
  populate_l4_map(1)        — fills l4_rules_1 (batch_update then fallback)
  set_default_action(1, X)  — writes default_action_1[0] = X
  install_programs(1)       — writes prog_array_1[L2,L3,L4] = (FDs)
commit():
  gen_config[0] = 1         ← single atomic write
  active_gen_.store(1)
  usleep(100000)            ← static 100ms wall-clock drain, no ack
attach XDP                  ← only NOW does traffic see anything
state: gen 0 is virgin; gen 1 is fully populated and active

=== SECOND DEPLOY (some time later, via SIGHUP or inotify) ===
prepare(shadow=0):
  clear_shadow_maps(0)      — empty maps, lpm_keys_[0] empty → no work
  populate_*  (0)           — fills gen-0 maps; appends to lpm{,6}_keys_[0]
  set_default_action(0, Y)  — writes default_action_0[0] (FIRST time ever)
  install_programs(0)       — writes prog_array_0[*]      (FIRST time ever)
commit():
  gen_config[0] = 0
  usleep(100000)
state: both generations populated; gen 0 active

=== THIRD DEPLOY ===
prepare(shadow=1):
  clear_shadow_maps(1)      — clears l2/vrf/l4 by iterate-and-delete,
                              clears LPM via delete_keys(lpm_keys_[1]),
                              lpm_keys_[1].clear() on success
  populate_* (1)            — re-fills gen-1
  install_programs(1)       — overwrites prog_array_1[*] (BPF_ANY, idempotent)
commit():
  gen_config[0] = 1; usleep(100000)

=== ROLLBACK (only ever from tests; dead code in production) ===
rollback():
  old_gen = active_gen_ ^ 1
  gen_config[0] = old_gen   ← flips back
  active_gen_.store(old_gen)
  (NO clear_shadow_maps call; NO lpm_keys clear)
  (no usleep — the "drain" semantics are skipped on rollback)
state: now-shadow gen retains whatever it had at last successful prepare
       (cruft; self-heals on next successful prepare)

=== ROLLBACK TRAP (latent — would fire if rollback were ever called
       between the FIRST commit and the SECOND prepare) ===
gen_config[0] = 0 (the virgin gen)
  → entry.bpf.c: gen=0 → bpf_tail_call(&prog_array_0, LAYER_2_IDX) → FAILS
  → STAT_DROP_ENTRY_TAIL fires; all packets dropped
  → default_action_0[0] = 0 = ACT_DROP anyway (kernel zero-init)
```

## Findings (graded)

```
- [P1 RECONFIRMED] rate_state_map is shared and never garbage-collected
  Where: bpf/maps.h:219-224 (PERCPU_HASH, single instance);
         no bpf_map_delete_elem against rate_state_fd anywhere in src/
  What: Confirmed by exhaustive grep. Phase 2d P1 stands.
  Suggested action: as in 05_layer4.md — make double-buffered, or have
        userspace track active rule_ids and delete on commit/rollback.

- [P1 PROMOTED — broader than Phase 1 §7] Rollback is unsafe and dead-code
  Where: src/pipeline/generation_manager.cpp:310-323 — rollback();
         only callers are tests/test_generation_logic.cpp:75 and
         tests/test_concurrency.cpp:72 against mocks (not the real
         GenerationManager)
  What: Three independent traps:
        1. Doesn't clear demoted shadow's contents (Phase 1 §7 — self-heals
           on next prepare).
        2. Rolling back to the never-deployed initial gen 0 lands on
           empty prog_array_0 (all packets DROP via STAT_DROP_ENTRY_TAIL
           in entry.bpf.c:55) AND zero-initialised default_action_0[0]
           (= ACT_DROP regardless of operator config).
        3. No drain — rollback skips the usleep(100ms) that commit has,
           even though the same in-flight-packet hazard exists.
  Why it matters: rollback() is in the public API as if it were a tool of
        last resort, but invoking it on the typical deploy timeline is
        worse than not having it. The first-deploy/first-rollback path is
        catastrophic (all packets drop until next prepare succeeds).
  Suggested action: pick one — (a) delete rollback() entirely; or
        (b) make it safe: pre-populate prog_array_0 with the prog FDs at
        loader startup, write default_action_0[0] at loader startup, add
        clear_shadow_maps(now_shadow) + usleep(100000) to rollback's body,
        and document the recovery contract.

- [P2] clear_shadow_maps aborts on first error, leaving multiple
  shadow maps in mixed state
  Where: src/pipeline/generation_manager.cpp:49-90 — every step is
         "if (!r) return ..."; 7 subsequent steps are skipped on error 1
  What: Self-heals on next prepare's first call to clear_shadow_maps,
        because each step is independent and idempotent. But during the
        partial-failure window the shadow has a stale subset of maps.
        Inconsistent with the inner clear_hash_map which is best-effort.
  Suggested action: refactor to collect all per-map errors and return
        them aggregated; let every map at least attempt clearing.

- [P2] Best-effort cleanup error is discarded inside prepare's failure paths
  Where: src/pipeline/generation_manager.cpp:242, 248, 254, 260, 266, 272, 279
  What: `clear_shadow_maps(gen); // best-effort cleanup` (comment is correct;
        the return value is bound to a temporary and dropped). Operator
        never sees if cleanup itself failed; logged neither. Combined with
        the abort-on-first-error pattern above, a partial-cleanup-after-
        partial-populate is invisible until something else breaks.
  Suggested action: at minimum, LOG_WRN on cleanup-error; ideally chain
        the two errors into the returned message.

- [P2] No FD validation in populate_l2_maps / populate_subnet*_map /
  populate_vrf_map / populate_l4_map / set_default_action
  Where: src/pipeline/generation_manager.cpp:103-121, :136, :152, :166, :181, :213
  What: Calls loader_.X_fd(gen) without checking return ≥ 0. install_programs
        does check (lines 18, 26-27, 33-34, 39-40); the rest don't.
  Suggested action: add `if (fd < 0) return std::unexpected(...)` guards;
        improves diagnostics if loader is in a partial state.

- [P2] Drain (`usleep(100ms)`) is calendar time, not synchronisation
  Where: src/pipeline/generation_manager.cpp:300-307 (commit only;
         rollback skips it entirely)
  What: No acknowledgement-based wait — neither a per-CPU "old generation
        completed" counter nor a `synchronize_rcu`-like equivalent. Under
        kernel preemption / NUMA scheduling jitter, 100ms is not a hard
        upper bound on in-flight packets. Phase 1 §3 stands.
  Suggested action: deferred per Phase 1 — long-term consider a per-CPU
        "last seen generation" counter that userspace polls until all CPUs
        report the new gen before returning from commit.

- [P2] active_gen_.store happens before the 100ms drain
  Where: src/pipeline/generation_manager.cpp:297 vs :306
  What: A hypothetical future reader of `active_generation()` would see
        the new gen during the drain window. Today nothing reads it that
        way, so latent. Move the store after the usleep.

- [P2] No size-cap enforcement: relies on kernel -E2BIG to detect overflow
  Where: all populate_* functions
  What: Same observation Phase 2a made for the compiler — generation_manager
        is the second place this could be caught. As-is, operator sees a
        generic "X insert (rule N): No space left on device" mid-deploy.
        Compile-time caps (Phase 2a P1) are the better fix.

- [P2] clear_hash_map error message loses per-entry context
  Where: src/loader/map_manager.cpp:67-69
  What: Aggregates "N delete(s) failed out of M" without naming a key.
        Combined with the abort-on-first-map in clear_shadow_maps, the
        operator gets one error per reload showing only the first failing
        map's aggregate count.
```

## Test-audit notes

- **`rate_state_map` lifecycle**: see 05_layer4.md test-audit entry. No userspace test exists that asserts "rate-limit change applies on reload". The `generation_manager.cpp` half is "there is no delete call" — a unit test grepping the class for `rate_state` (or a static-analysis rule) would have caught this trivially.
- **Rollback to virgin gen 0 trap**: `tests/test_generation_logic.cpp` exercises rollback against a mock that has no notion of prog_array or default_action_*. The real-BPF half is uncovered — there is no integration test that does deploy → rollback → assert packets still flow. Test class: **wrong layer** — abstract state-machine test mocks away exactly the parts where the bug lives. Same shape as the TEST_AUDIT meta-pattern.
- **`clear_shadow_maps` partial-failure**: no fault-injection test exercises `bpf_map_delete_elem` returning EBUSY mid-clear. `tests/test_fault_injection.cpp` (per recon) operates on JSON/parser fault injection, not map-level. Test class: **absent**.
- **Best-effort cleanup error swallowing**: same as above. No test that asserts cleanup errors propagate to logs.
- **Drain (100ms)**: no test measures whether 100ms is sufficient. Out of scope — would need a NIC-attached benchmark.

## Open issues / pickup for later phases

- **Phase 2h (bpf_loader)**: confirm what loader does about `prog_array_0/1` and `default_action_0/1` at load time — does anything pre-populate them, or are they exactly zero-init by kernel? Verify the rollback trap from a different angle.
- **Phase 2i (config_parser/validator)**: rule_id stability — Phase 2d suggested it determines which `rate_state_map` failure mode dominates. The validator could (but doesn't) reject reuse of a rule_id across reloads to push the operator toward stability. Out of scope here.
- **`tools/validate_config` (Phase 2j)**: does not exercise `GenerationManager` (no BPF context). Out of scope.
- **For consolidation**: the Phase 1 P1 "rollback doesn't clear shadow" should be merged with the new finding "rollback to virgin gen 0 drops all traffic" into a single P1 entry — they're aspects of the same broken contract.
