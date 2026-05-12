# 15 — Tests phase

Premise: every Phase-2 P0 passed CI green. This phase delivers a rank-ordered plan to fix that, not a backlog. CI shape first, then tests for the P0s, then the rest.

## 1. CI shape audit

### Workflows present

Two YAML files only: `.github/workflows/ci.yml`, `.github/workflows/fuzz.yml`.

#### `ci.yml`

- Triggers: `push` and `pull_request` on `main` (ci.yml:3-7).
- Job `build-and-test`: 4-way matrix (Debug, Debug+ASan, Debug+UBSan, Release). On `ubuntu-24.04`.
- Test invocation (ci.yml:61-65):
  ```
  ctest --test-dir build -L unit --output-on-failure
  ctest --test-dir build -L integration --output-on-failure
  ```
- Job `coverage`: builds with `-DCOVERAGE=ON`, runs `ctest -E bpf_dataplane` (ci.yml:91). This **explicitly excludes** the BPF dataplane label even from the coverage run, which is the only ctest call in the file that doesn't filter by label.
- The `functional_tests/` directory is **never referenced** anywhere in `ci.yml`.

#### `fuzz.yml`

- PR smoke: 60s × 3 harnesses (fuzz.yml:23-58), on every PR. Targets: `fuzz_config_parser`, `fuzz_net_types`, `fuzz_roundtrip`.
- Overnight: 3600s × 3 harnesses, cron `0 2 * * 1-5` (fuzz.yml:5).
- No data-plane fuzzer (none exists in `fuzz/`).

### ctest labels

`CMakeLists.txt:292-308`. Three labels exist:

| Label | Tests | Run in CI? |
|-------|-------|-----------|
| `unit` (CMakeLists.txt:299-304) | config_parser, object_compiler, generation_logic, net_types, config_validation, rule_compiler_edge, config_validator, byte_layout, packet_builder, ipv6, fault_injection, prometheus | yes |
| `integration` (CMakeLists.txt:305-307) | pipeline_integration, roundtrip, stress, concurrency | yes |
| `bpf;privileged` (CMakeLists.txt:293-296) | bpf_dataplane (58 `TEST(...)` cases inc. `test_l2_qinq_not_parsed`, `test_l4_ipv6_ext_header_chain`, `test_l4_ipv6_fragment_after_ext`) | **NO** |

Tests **without any label** (so `ctest -L unit` skips them, but a bare `ctest` would pick them up): none — all non-bpf tests are explicitly under one of the two labels.

### Verdict on Phase 3 §5

| Claim | Status |
|-------|--------|
| "Only `unit` and `integration` ctest labels run" | **CONFIRMED** (ci.yml:62, 65). |
| "Entire `functional_tests/*.py` suite runs nowhere automatically" | **CONFIRMED**. The string `functional_tests` does not appear in `.github/workflows/`. The only runner is `functional_tests/run.sh`, invoked manually with `sudo`. |
| "Every Phase-2 P0 passed CI green" | **CONFIRMED mechanically**. P0s land in the BPF dataplane (IPv6 ACT_TAG corruption, L4 ext-header chain ≥5 bypass) or the `validate_config` tool (not built by CMake, so not run) or the parser (dst_ip P0 — unit-test gap). None of these surfaces are exercised by `ctest -L unit -L integration`. |
| "Fuzz harnesses wired to CI" | **CONFIRMED** for `fuzz_config_parser`, `fuzz_net_types`, `fuzz_roundtrip`. **PR smoke + nightly cron**. But no data-plane fuzzer exists. |

Bonus finding: even the `coverage` job (ci.yml:91) **opts out** of bpf_dataplane via `-E bpf_dataplane`. Coverage numbers exclude the most security-sensitive code in the repo.

### Required CI shape changes (concrete)

1. Add a `bpf-dataplane` job to `ci.yml`. Runs on `ubuntu-24.04` (privileged runners not required — `BPF_PROG_TEST_RUN` works in the GitHub runner kernel; needs `CAP_BPF`/sudo via the default `runner` user with passwordless sudo). Build, then `sudo ctest --test-dir build -L bpf --output-on-failure`.
2. Add a `functional` job. Runs `sudo bash functional_tests/run.sh` (already a documented entrypoint, `run.sh:6`). Network-namespace setup is done by `functional_tests/conftest.py:78-122` and requires root (`ip netns`, `ip link`).
3. Drop `-E bpf_dataplane` from the coverage step (ci.yml:91) so coverage reflects reality.
4. Make the new jobs **block PR merge** the same way `build-and-test` does. Anything less and the next round of P0s ships the same way.

---

## 2. Action plan (rank-ordered)

### Step 1 — Fix CI shape (do this first; everything else is moot otherwise)

Edits to `.github/workflows/ci.yml`:

```yaml
  bpf-dataplane:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
      - name: Install dependencies   # same block as build-and-test
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y --no-install-recommends \
            clang-18 llvm-18 libbpf-dev libelf-dev zlib1g-dev nlohmann-json3-dev
          # bpftool prep elided — same as build-and-test
      - name: Configure & build
        run: cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j$(nproc)
      - name: Dataplane tests
        run: sudo ctest --test-dir build -L bpf --output-on-failure

  functional:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
      - name: Install dependencies
        run: |
          # … same as bpf-dataplane …
          sudo apt-get install -y --no-install-recommends python3-pytest python3-scapy tcpdump iproute2
      - name: Build pktgate_ctl
        run: cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j$(nproc) --target pktgate_ctl
      - name: Functional tests
        run: sudo bash functional_tests/run.sh
```

Also edit `ci.yml:91`: drop the `-E bpf_dataplane` filter. Optional: change to `sudo ctest --test-dir build --output-on-failure` so coverage covers all labels.

CMake-side: no edit required. The `bpf;privileged` label already exists. The functional suite is pytest, runs via `run.sh`, no ctest entry needed.

Expected ctest invocation that runs everything:
```
sudo ctest --test-dir build --output-on-failure
sudo bash functional_tests/run.sh
```

### Step 2 — Tests for P0 findings

For each P0 from `08_CHECKPOINT.md` (10 entries). Some merge.

#### P0-1: No bps counter (`02_architecture.md §7`)

- **Test:** `test_bytes_counter_increments_proportional_to_payload` — unit + dataplane.
- **Location:** `tests/test_prometheus.cpp` (unit, asserts the metric descriptor exists); `tests/bpf/test_bpf_dataplane.cpp` (dataplane, runs `PROG_TEST_RUN` with 64-byte vs 1500-byte packets, asserts bytes counter delta matches).
- **Class:** unit + dataplane.
- **Root/veth:** dataplane needs root (`BPF_PROG_TEST_RUN`).
- **Strengthen existing?** No — counter doesn't exist yet. Test gated on the feature landing.

#### P0-2: CoS / VLAN PCP rewrite advertised but unimplemented

- **Test:** `test_tc_ingress_pcp_rewrite_emits_tagged_frame`.
- **Location:** `tests/bpf/test_bpf_dataplane.cpp` (TC ingress path). Also a functional test `test_dscp_tag.py::test_cos_rewrite_in_vlan_tag` once feature lands.
- **Class:** dataplane + functional.
- **Root/veth:** functional needs veth + root.
- **Strengthen existing?** `functional_tests/test_dscp_tag.py` (3 tests) only checks DSCP for IPv4 — extend to cover the VLAN PCP nibble.

#### P0-3: No fail-safe / watchdog

- **Test:** `test_watchdog_replays_last_known_good_after_crash` — functional.
- **Location:** new file `functional_tests/test_zz_watchdog.py`.
- **Class:** functional. Kills `pktgate_ctl` mid-load; asserts service-recovery restores ruleset within N seconds.
- **Root/veth:** root.
- **Strengthen existing?** No — feature doesn't exist; this is a deferred-design test.

#### P0-4: `dst_ip` becomes catch-all wildcard (THE flagship case)

This is the biggest gap. Three layers of test missing:

- **Test 1 (validator unit):** `test_l3_no_match_field_rejected` — mirror of the existing `test_l2_no_match_field_rejected` (`tests/test_config_validator.cpp:418`). Asserts an L3 rule with no `src_ip` / `src_ip6` is rejected with "must specify a match field".
- **Test 2 (compiler unit):** `test_compile_l3_rule_with_only_dst_ip_rejected` — in `tests/test_rule_compiler_edge.cpp`. Tries to compile a rule with `match.dst_ip` only; asserts compiler returns error (the validator should already reject, but the compiler should defend in depth).
- **Test 3 (roundtrip):** `test_roundtrip_dst_ip_only_does_not_produce_wildcard_lpm` — in `tests/test_roundtrip.cpp`. Loads a config with `dst_ip` only; compiles; inspects the `subnet_rules_0` map entries; asserts no `{prefixlen=0, addr=0}` entry exists.
- **Test 4 (dataplane):** `test_l3_dst_ip_only_does_not_drop_all` — in `tests/bpf/test_bpf_dataplane.cpp`. Populates `subnet_rules_0` from a `dst_ip`-only config; sends a packet to a different dst; asserts NOT-DROP.
- **Test 5 (functional):** `test_l3_negative_match` — in `functional_tests/test_l3_subnet.py`. Asserts that a config rule for src_ip X does not drop packets for src_ip Y.
- **Class:** unit (×2), integration (×1), dataplane (×1), functional (×1).
- **Root/veth:** dataplane root, functional root+veth.
- **Strengthen existing?** Test 1 is the cheapest single win and mirrors a test that already exists for the sibling layer. **Highest-leverage single test in the entire plan.**

#### P0-5: IPv6 ext-header chain ≥5 bypasses ALL L4 filtering

- **Test 1 (dataplane):** `test_l4_ipv6_ext_chain_5_drops_with_dedicated_counter` — `tests/bpf/test_bpf_dataplane.cpp`. Builds packet with 5 HBH headers; asserts `XDP_DROP` and `STAT_DROP_L4_V6_EXT_DEPTH` increment.
- **Test 2 (dataplane parametric):** `test_l4_ipv6_ext_chain_depth_parametric` — chain depths 1, 4, 5, 8. Cross-product with action {ALLOW rule, DROP rule, rate-limit rule, no rule}.
- **Test 3 (functional):** `test_l3_ipv6.py::TestIPv6ExtensionHeaders::test_chain_depth_5_dropped` — extend the existing class.
- **Class:** dataplane (×2), functional (×1).
- **Root/veth:** root.
- **Strengthen existing?** `test_l4_ipv6_ext_header_chain` (test_bpf_dataplane.cpp:1413) tests depth-2 happy path. **Parameterise it** rather than adding a new test — same builder code, varied depth.

#### P0-6: IPv6 ACT_TAG silently corrupts the packet

- **Test 1 (dataplane):** `test_tc_ingress_ipv6_tag_preserves_source_address` — `tests/bpf/test_bpf_dataplane.cpp`. Builds IPv6 packet with `pkt_meta.action_flags = ACT_TAG`; runs TC ingress; asserts source-address bytes 8-23 are unchanged byte-for-byte.
- **Test 2 (functional):** `functional_tests/test_dscp_tag.py::test_ipv6_tag_action_no_corruption` — sends IPv6, captures egress, scapy-parses source address, asserts ==.
- **Class:** dataplane + functional.
- **Strengthen existing?** `test_dscp_tag.py` (3 tests, all IPv4). Add an IPv6 class.

#### P0-7: Wrong-layer match fields silently accepted by validator

- **Test:** `test_validator_rejects_l3_rule_with_l4_only_fields` and siblings.
- **Location:** `tests/test_config_validator.cpp`. Three concrete cases:
  - L3 rule with `dst_port` → reject ("dst_port is an L4-only field").
  - L4 rule with `src_mac` → reject.
  - L2 rule with `src_ip` → reject.
- **Class:** unit.
- **Strengthen existing?** No — the validator's whitelist needs to expand first; tests follow.

#### P0-8: `validate_config` returns OK on configs that destroy the network

- **Test 1 (build):** add `validate_config` to `CMakeLists.txt` as a target; CI builds it. The absence of the binary is the symptom; this alone closes the "fresh build" half of the bug.
- **Test 2 (behaviour):** `tests/test_validate_config_tool.py` (new) or a bash test fixture: invokes `validate_config` on a corpus of intentionally-bad configs (`tests/fixtures/bad_configs/dst_ip_only.json`, `wrong_layer_field.json`, `wildcard_subnet.json`); asserts non-zero exit for each.
- **Class:** integration (drives the binary).
- **Strengthen existing?** Nothing exists. This is a tool-level test gap.

#### P0-9: IPv6 as a class

Covered by P0-5, P0-6 above plus the structural changes in `14_cross_cutting.md §1`. Once `pkt_meta.ip_family` is plumbed, add:

- **Test:** `test_pkt_meta_ip_family_set_at_l3_for_all_paths` — dataplane. Loops over {v4, v6}, asserts the family bit is what L3 set when TC ingress reads it.
- **Class:** dataplane.

#### P0-10: systemd CAP_SYS_ADMIN over-grant

- **Test:** `tests/systemd_unit_test.sh` (new). Invokes `systemd-analyze security pktgate.service`; asserts score in target range; greps for the literal `CAP_SYS_ADMIN` and asserts absence; greps for `NoNewPrivileges=yes`.
- **Class:** integration (build-system / packaging).
- **Strengthen existing?** No existing systemd test of any kind.

### Step 3 — Tests for P1 findings (abbreviated)

| P1 | Test sketch | File | Class |
|----|-------------|------|-------|
| P1-6 `data_meta` driver-dependent | `test_xdp_to_tc_data_meta_roundtrip` — startup self-test; sends sentinel, asserts TC reads it back. | new `tests/integration/test_data_meta_handoff.cpp` | integration |
| P1-7 ARCHITECTURE drift | `test_arch_doc_map_count_matches_source` — grep `maps.h` for `SEC(".maps")` macros, compare with count in ARCHITECTURE.md table. | `tests/test_docs_drift.sh` | integration |
| P1-8 Rollback shadow-clear | `test_generation_rollback_clears_demoted` — in `tests/test_generation_logic.cpp` (already exists) — add a case that after a rollback the demoted shadow map is empty. | strengthen `tests/test_generation_logic.cpp` | unit |
| P1-9 v6 frag bypass HBH→Frag on L3-terminal ALLOW | `test_l3_ipv6_terminal_allow_with_hbh_then_frag_dropped` — functional. | `functional_tests/test_l3_ipv6.py` (extend `TestIPv6FragmentAfterExtHeaders`) | functional |
| P1-10 L2 compound primary-by-lex collision | `test_compound_l2_rules_shared_first_field_compile` — both rules sharing `ethertype=IPv4` differ in `vlan_id`. | `tests/test_rule_compiler_edge.cpp` | unit |
| P1-11 No compile-time per-map size limits | `test_compile_exceeds_max_subnet_entries_rejected` — load 4097-entry subnet config; assert compiler rejects. | `tests/test_rule_compiler_edge.cpp` | unit |
| P1-12 Rate divisor `num_possible_cpus` | `test_rate_limit_effective_throughput_within_tolerance` — functional; configure 100Mbps, measure ≥85 Mbps. | strengthen `functional_tests/test_zz_rate_limit.py` (currently only tests "limit fires") | functional |
| P1-13 L2 does 5 lookups | Latency test, but a more pragmatic asserter: `test_l2_lookups_count_in_bpf_map_stats` — read kernel `bpf_program_info` to count map accesses. | `tests/bpf/test_bpf_dataplane.cpp` | dataplane |
| P1-14 L2 compound `{src_mac, dst_mac}` drops one | `test_compound_src_dst_mac_both_match` — dataplane; configure rule with both, send packet matching both, assert hit. | `tests/bpf/test_bpf_dataplane.cpp` | dataplane |
| P1-15 QinQ test-as-contract | (handled in Step 4) | | |
| P1-16 rate_state_map across generations | `test_rate_limit_reload_changes_effective_rate` — functional; configure 100→1Gbps reload, measure both. | strengthen `functional_tests/test_zz_rate_limit.py` | functional |
| P1-17 STAT_TC_NOOP conflated | (see P1-6 self-test — also distinguishes the two causes) | | |
| P1-18 ACT_MIRROR with `mirror_ifindex==0` silent skip | `test_mirror_with_zero_ifindex_rejected_at_validation` — unit; configure rule, expect validator failure. | `tests/test_config_validator.cpp` | unit |
| P1-19 config-schema.json not wired | `test_validator_rejects_schema_violation` — unit; pass a config that schema says is invalid (e.g., missing required key); assert reject. | new tests in `tests/test_config_validator.cpp` | unit |
| P1-20 No file-size guard on config load | `test_oversized_config_rejected` — unit + functional; >50MB config file, parser must reject without OOM. | `tests/test_config_parser.cpp` + functional reload via inotify | unit + functional |
| P1-21 CI runs only unit+integration | (Step 1) | | |
| P1-22 NoNewPrivileges=no | (P0-10 systemd-analyze test covers) | | |
| P1-23 No seccomp filter | (P0-10 systemd-analyze covers) | | |
| P1-24 libbpf no version floor in CMake | `test_cmake_rejects_old_libbpf` — integration; configure with libbpf 1.0 stub, assert configure fails. | `tests/cmake_version_pin_test.sh` | integration |

### Step 4 — Test-as-contract remediations

#### Case A: `test_l2_qinq_not_parsed` (`tests/bpf/test_bpf_dataplane.cpp:1048`)

- **What it asserts:** Sends a QinQ frame (outer ethertype 0x88a8 + inner 0x8100). Asserts `XDP_DROP`. Comment block explicitly states the rationale: "QinQ not parsed → L3 → non-IPv4 → DROP".
- **Design-decision trail:** Searched git/comments/ARCHITECTURE.md — **no commit message, no ADR, no TODO** documenting the choice. Owner-side memory only.
- **Recommendation:** **Rewrite to expect correct behaviour and let it fail.** This is a carrier-Gi-critical bug (`08_CHECKPOINT.md` P1-15: "carrier links commonly stack S-Tag + C-Tag"). Replace the assertion with `assert(res.retval == XDP_PASS_to_L3 with vlan_id parsed)` and add an `xfail`/`skip("known: QinQ unsupported; tracked in #ISSUE")` marker until implementation lands. Keeping the test passing in its current form **actively blocks** the fix.
- **Alternative if rewrite is rejected:** keep the test, but rename to `test_l2_qinq_documented_unsupported`, and require a linked TODO in `ARCHITECTURE.md §Known limitations`. Without one of these two, the test is a liability.

#### Case B: `test_l2_ethertype_invalid_hex_chars` (`tests/test_config_validator.cpp:717`)

- **What it asserts:** `ethertype = "0xGGGG"` passes validation. The test's own comment (lines 718-721) explicitly describes the assertion as locking in a `stoul` quirk: "This test documents current (buggy) behavior."
- **Design-decision trail:** the inline comment **is** the trail. No issue/TODO.
- **Recommendation:** **Rewrite.** This is unambiguous: the comment self-describes as buggy. Change to `assert(!result.has_value() && has_error(... "invalid ethertype hex chars"))` and fix `parse_ethertype` to reject non-hex characters in `0xNNNN` strings. Cost: small (one parser branch). The test should fail until the parser is fixed, then pass; this is the **correct** direction of the test-as-contract anti-pattern.

### Step 5 — Structural / P2

The P2 list in `08_CHECKPOINT.md` is mostly stat-naming and dead-code items. Test sketches in this rank-ordering:

- **Scenarios test fixture:** add a single test `test_all_scenarios_compile_without_wildcard` (`tests/test_roundtrip.cpp` or new) that iterates `scenarios/*.json` and `scenarios_v2/*.json`, runs the full parse→validate→compile pipeline, asserts no `{prefixlen=0}` LPM keys, asserts compile success. **One test, broad coverage.**
- **`STAT_PASS_L3` double-fire on mirror-terminal:** `test_pass_l3_fires_exactly_once_on_mirror` — dataplane.
- **`STAT_DROP_NO_META` overload:** distinguished only after fixing the stat; test follows feature.
- **`tcp_flags` on UDP rule silently never matches:** `test_validator_rejects_tcp_flags_on_udp_rule` — unit.
- **`pkt_meta.redirect_ifindex` dead:** code-pruning task; no test.
- **Tail-call asymmetry (Phase 2b P2):** `test_l3_tail_call_asymmetry_matched_vs_no_match` — dataplane; populate `prog_array` partially and verify both arms drop with dedicated counters.
- **Data-plane fuzzer (`fuzz_bpf_dataplane.cpp`):** new harness. Build packets via libfuzzer, run through `PROG_TEST_RUN` against a fixed reasonable config; assert program doesn't crash, doesn't return undefined verdicts. (Won't find the existing P0s automatically — see §3 below — but will find next-class verifier-exit / OOB-read regressions.)
- **Per-rule observability:** `test_per_rule_counter_visibility` — functional; load 100 rules, scrape `/metrics`, assert 100 series.

---

## 3. Test infrastructure observations

### Speed

- `tests/test_stress.cpp` and `tests/test_concurrency.cpp` are in the `integration` label. The latter is the only sleep-tolerant test (uses `std::barrier::arrive_and_wait`, `tests/test_concurrency.cpp:175` — deterministic). No `sleep_for` / `usleep` in unit or integration tests.
- `tests/bpf/test_bpf_dataplane.cpp` runs `bpf_prog_test_run_opts` with `repeat=1` by default — instant; safe for every PR.
- Functional tests use `time.sleep(1.5)` after `pktgate_ctl` start (`conftest.py:253`) and `time.sleep(1.0)` after inotify reload (`conftest.py:264`). Wall-clock cost of the full suite is on the order of minutes, not seconds — borderline for "every-PR" CI, fine for a separate job. Should run on every PR with `pytest -x --timeout=60`.

### Determinism

- Dataplane tests are deterministic by construction (`BPF_PROG_TEST_RUN` is synchronous).
- Functional tests use real veth + scapy + tcpdump — can flake on a loaded runner. `--immediate-mode` (`conftest.py:357`) helps; the 0.5s pre-capture sleep (`conftest.py:398`) is the most likely flake source. **Mitigation:** retry-once on failure with `pytest-rerunfailures`, but not before fixing real timing races first.
- Rate-limit functional tests are inherently statistical; treat as flaky. Use sufficiently large windows (≥1s) and tolerance bands (≥10%).

### Isolation

- ctest tests share no state — each is a separate process.
- The dataplane tests share **one BPF loader** across all `TEST(...)` cases (single `loader` global referenced at lines 312, 328, 352, etc.). State leaks across tests via persistent BPF maps. Tests handle this by `MM::delete_elem` at end (line 1045 example). **Pattern is fragile** — a test that fails before its cleanup leaks state to all subsequent tests. Recommendation: per-test reset of all maps, not per-call cleanup.
- Functional tests share one `pktgate` fixture at session scope (`conftest.py:289`). Same fragility, magnified — once `pktgate` crashes or detaches XDP, all subsequent functional tests see corrupted state.

### Mocking strategy

- `tests/test_pipeline_integration.cpp:30-45` defines `MockMapEntry` / `MockMap` / `g_l2_maps` / `g_subnet_rules` — pure-userspace mock of the BPF map layer. Good: this is the right pattern.
- All other unit tests test pure userspace code (compiler, parser, validator, net_types) with no BPF dependency.
- `tests/bpf/test_bpf_dataplane.cpp` hits **real** `bpf(2)` syscalls via `PROG_TEST_RUN`. There is no mock between userspace and the kernel for BPF dataplane tests — by design.
- **Gap:** no test mocks `libbpf` itself. So the `bpf_loader.cpp` error handling is testable only via real kernel responses (mostly happy-path). For fault-injection of `libbpf` errors, see `tests/test_fault_injection.cpp` (88 LOC unit, generic) — does **not** currently inject `bpf(2)` failures. Strengthening this is a P2 unit task.

---

## 4. Properties-based opportunities

Three concrete properties worth implementing as Hypothesis-style or table-driven tests (mapped to existing findings, not theoretical):

1. **"Every successfully-validated config compiles without producing a wildcard LPM key."** Generator: random L3 rules with one of the existing match fields, random CIDRs at random prefix lengths ≥ 1. Invariant: no entry in `subnet_rules_0` has `prefixlen == 0`. Catches the dst_ip P0 by construction, plus any future "field accepted, becomes wildcard" sibling.

2. **"For every L3 rule with `has_next_layer=0` and any IPv6 ext-header sequence of length ≤ 8, behaviour matches the layer's documented intent (DROP for fragments, ALLOW/DROP per rule otherwise)."** Generator: random ext-header sequences, fixed L3-terminal rule. Invariant: same verdict regardless of HBH/DestOpt padding count. Catches both Phase 2b and Phase 2d IPv6 bugs in one harness.

3. **"For any valid config, `validate_config` and `pktgate_ctl --check` give the same verdict."** Once `validate_config` is rebuilt and runs the compile step. Catches "tool lies about behaviour" silently.

These three replace ~40 individually written tests; the cost is the generator infrastructure (~150 LOC of helper) and willingness to commit to a property-test framework (rapidcheck or libfuzzer with structured inputs).

---

## 5. Project-level test culture recommendation

The two test-as-contract cases (`test_l2_qinq_not_parsed`, `test_l2_ethertype_invalid_hex_chars`) are not isolated lapses — they are the same anti-pattern as the dst_ip P0's *absent* negative test: the codebase treats "passes today" as the desired contract. The QinQ case actively pins the bug; the ethertype case explicitly admits in its own comment ("This test documents current (buggy) behavior") that it does. Both shipped through code review. With two instances, this is a culture problem, not a one-off.

**Three concrete mitigations**, ranked by cost:

1. **PR-template question:** "Does this PR add a test that asserts an error return, an empty/zero result, or `assert(!result.has_value())` from a code path that the reviewer would expect to succeed? If yes, link the design decision in `ARCHITECTURE.md` or an issue." Free, partial, but creates the conversation.
2. **Static check / CI grep:** flag any test source containing `// BUG`, `// buggy`, `// known: ` near an `assert`/`EXPECT` call without an adjacent linked tracking marker (`// TODO(#NNN)`, `// SEE ARCH:section`). Mechanical, low false-positive rate, ten lines of grep in CI. Would have flagged `test_l2_ethertype_invalid_hex_chars` immediately.
3. **`ARCHITECTURE.md §Known limitations` section:** a single audited place for "X is unsupported; here's why; here's the cost-to-fix". Tests-as-contract must cite an entry there. Without this, the next maintainer cannot tell deferred-by-design from latent-bug.

The deeper move is to invert the burden: tests assert intended behaviour; if implementation lags, tests fail with a clear `xfail("tracked in #NN")` marker. **A failing-but-tracked test is more honest than a passing-but-locked-in-bug test** — the first invites a fix, the second blocks it.

---

## 6. What this phase produces for the final report

pktgate's test surface (570+ test points) gives false confidence on three independent axes: (1) CI runs only `unit` + `integration` ctest labels — the entire `bpf_dataplane` label and the whole `functional_tests/*.py` pytest suite never run automatically, which is the mechanical reason every Phase-2 P0 passed CI green; (2) coverage is happy-path with no negative-match or adversarial cases — the dst_ip catch-all P0 had six plausible test sites and zero actual coverage, and the IPv6 ext-header bugs sit behind `for(i<4)` walks that no test exercises at depth ≥5; (3) two tests (`test_l2_qinq_not_parsed`, `test_l2_ethertype_invalid_hex_chars`) actively cement bugs as contract, the second one labelling itself "buggy" in a comment. Repair order is non-negotiable: fix CI shape first (wire `bpf` + a new `functional` job, drop the `-E bpf_dataplane` filter on coverage), then close the dst_ip P0 with a five-test cross-layer harness mirrored on the existing L2 sibling test, then the IPv6 adversarial matrix, then validate_config behaviour, then the test-as-contract rewrites. The situation is **repairable, not from-scratch**: the test infrastructure (BPF_PROG_TEST_RUN harness, veth conftest, three fuzz harnesses, mock BPF map layer for integration) is sound — what's missing is the CI wiring and a culture of negative-match assertions.
