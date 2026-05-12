# TEST_AUDIT — running list

Running ledger of "the bug is severe; the tests didn't catch it." Each Phase-2+ finding gets one entry. Becomes the input to the later tests-phase: for each row, decide what kind of test would have caught it, and audit whether that test exists in a watered-down form.

## Why this matters

pktgate has **570+ test points** (per recon): 466 unit/integration via ctest, 104 functional via pytest, 3 fuzz harnesses. Multiple findings so far would have been caught by a competent test of the relevant behaviour. The fact that they weren't is itself a finding — and a more serious one than any single bug, because it means the test surface gives false confidence to anyone touching this code next (the owner included, returning to it after a pause).

The pattern matters more than the individual misses. Note when a finding represents:
- **wrong test exists** (passes when it shouldn't) — worst class, false safety
- **test absent** (no coverage at all) — fixable, less misleading
- **test wrong layer** (e.g. unit test confirms compile, but no functional test confirms behaviour at packet level)

## Findings ledger

### [Phase 2a] P0 — `dst_ip` becomes catch-all wildcard

Where: `src/compiler/rule_compiler.cpp:206-243` + `src/config/config_validator.cpp:82-111`.
Symptom: `{match:{dst_ip:"10/8"}, action:drop}` drops ALL IPv4 traffic.

Expected to catch this:
- A unit test in `tests/test_rule_compiler_edge.cpp` that asserts "L3 rule with only `dst_ip` → compiler rejects, OR produces non-wildcard entry"
- A unit test in `tests/test_config_validator.cpp` that asserts "L3 rule with no recognised match field → validator rejects" (mirror of the L2 test, which presumably exists since L2 has the guard)
- A functional test in `functional_tests/test_l3_*` that sends a packet **not** matching the operator's intended dst, and asserts it **passes** (negative-match test)
- A roundtrip test (`tests/test_roundtrip.cpp`) that takes a `dst_ip`-only config, compiles it, and checks that the compiled map entries do **not** include a `0.0.0.0/0` LPM key

Test gap class: likely **test absent** for the negative case at validator/compiler level, and **test wrong layer** because functional tests probably check "rule matches traffic it should" not "rule does **not** match traffic it shouldn't".

To verify in the tests-phase.

---

### [Phase 2a] P1 — Rate-limit divisor uses `num_possible_cpus`

Where: `src/compiler/rule_compiler.cpp:286-291`.
Symptom: configured 10 Gbps rate becomes ~40 Mbps on a stock kernel (NR_CPUS=8192).

Expected to catch this:
- A functional test that configures rate-limit at N Mbps and measures effective throughput across multiple packet sizes — asserting effective rate is within, say, 10% of N
- `functional_tests/test_zz_rate_limit.py` (per recon) — must currently only assert "rate-limit fires", not "rate-limit accuracy is within tolerance"

Test gap class: **test wrong rigor**. Test exists but checks "the feature is triggered" not "the feature does what the value says".

---

### [Phase 2a] P1 — L2 compound rules: primary by lexical order, collisions force dummy fields

Where: `src/compiler/rule_compiler.cpp:130-144`.
Symptom: two rules `{ethertype:IPv4, vlan_id:10}` and `{ethertype:IPv4, vlan_id:20}` cannot coexist; second is collision-rejected.

Expected to catch this:
- A unit test in `tests/test_rule_compiler_edge.cpp` covering compound rules with shared lexically-first field but different secondary fields, asserting **both** rules compile successfully
- Configuration in `scenarios/02_vlan_segmentation.json` or `scenarios/09_datacenter_qos.json` (any scenario using multiple VLANs with same ethertype) — should fail to compile if that scenario was ever actually loaded by a test (it isn't — `scenarios_v2/` confirmed gap-analysis-only per owner notes; `scenarios/` similarly never CI-loaded per Phase 1)

Test gap class: **test absent** + **scenarios not exercised by CI** (a meta-gap captured in Phase 1 §6).

---

### [Phase 2b] P0 confirmation — LPM wildcard reaches BPF and matches every packet

Where: `bpf/layer3.bpf.c:257-266` (v4), `:205-215` (v6). Same root cause as Phase 2a entry; this is the data-plane half.

Expected to catch this end-to-end:
- A `BPF_PROG_TEST_RUN` test in `tests/bpf/test_bpf_dataplane.cpp` that populates `subnet_rules_0/1` with a `{prefixlen=0, addr=0}` entry and asserts the L3 program returns DROP/PASS as configured for an arbitrary source IP — would have surfaced the wildcard semantics immediately
- A functional test in `functional_tests/test_l3_*` that loads a config with **only** `dst_ip` and asserts that traffic to other destinations **passes** (negative-match coverage) — would have caught the outage scenario at the highest level

Test gap class: **test absent** across all three levels (unit, integration, functional). Six different test files exist that should plausibly have caught this; none did. Strong signal that "happy-path coverage only" is the prevailing pattern.

---

### [Phase 2b] P2 — IPv6 fragment-drop bypassable via Hop-by-Hop → Fragment chain on L3-terminal ALLOW rules

Where: `bpf/layer3.bpf.c:198` checks only immediate `ip6h->nexthdr == 44`; `layer4.bpf.c:151-178` does walk ext headers, but only fires if the packet reaches L4.

Expected to catch this:
- A functional test in `functional_tests/test_l3_ipv6.py` sending an IPv6 packet with `nexthdr=0 (HopByHop)` then `nexthdr=44 (Fragment)`, matched by an L3 ALLOW rule with `has_next_layer=0`, and asserting the packet is dropped — would have surfaced the gap
- `test_l3_ipv6.py` per recon has 10 tests focused on ext-headers + fragments; one of them is presumably the direct-nexthdr-44 case and passes. The "fragment behind ext-header on L3-terminal" case is the missing variant.

Test gap class: **test wrong rigor / adversarial coverage missing**. Tests cover the documented expected case but not adversarial encoding of the same semantic. Standard pattern for security-relevant code.

---

### [Phase 2d] P0 SECURITY — IPv6 ext-header chain ≥5 bypasses ALL L4 filtering

Where: `bpf/layer4.bpf.c:151-185` — `#pragma unroll for (int i = 0; i < 4; i++)`. Adversary crafts 5+ Hop-by-Hop/Destination-Option headers; loop exits with `nhdr` still an ext-header type; falls into non-TCP/UDP arm; consults default action. Port rules and rate-limit silently bypassed.

Expected to catch this:
- A `BPF_PROG_TEST_RUN` test that crafts an IPv6 packet with 5+ Hop-by-Hop headers and asserts that a configured L4 rule still applies (or that the packet is dropped with a dedicated counter). Trivial to write, would have flagged immediately.
- A functional test in `functional_tests/test_l3_ipv6.py` using scapy to build the same packet shape, asserting behaviour against a configured rate-limit or DROP rule.
- An adversarial packet fuzzer (which the project does not have for the data plane — current fuzz targets are JSON parser / net_types only, per recon).

Test gap class: **adversarial coverage missing across the board**. Combined with the Phase 2b L3 fragment-behind-ext-header finding, this is now a **pattern**: every IPv6 ext-header handling site in pktgate has happy-path tests at chain depth ≤3, none at the adversarial depth that defeats the bound. **This is the most important meta-finding from the test audit so far** — IPv6 ext-header logic is the project's largest security-relevant surface, and the entire test suite is silent on it.

---

### [Phase 2d] P1 — rate_state_map lifecycle (shared across generations, never GC'd)

Where: `bpf/maps.h:217-224` (single non-double-buffered PERCPU_HASH); `src/pipeline/generation_manager.cpp` (no `bpf_map_delete_elem` against this map, per Phase 2d note — to be confirmed in 2c).

Symptom: a rate-limit reload either silently doesn't take effect (rule_id stable) or leaks entries until `MAX_RATE_ENTRIES=4096` is exhausted (rule_id reshuffled), at which point rate-limit silently passes everything.

Expected to catch this:
- A reload/lifecycle functional test: configure 100 Mbps → measure → reload to 1 Gbps → measure again → assert effective rate matches new value. `test_zz_rate_limit.py` per recon tests rate-limit "in principle" but evidently not across reloads.
- A stress test that issues 5000 reload cycles with rule_id reshuffling and asserts that rate-limit still functions after entry exhaustion.

Test gap class: **reload-and-stress coverage absent**. The "deploy once, observe behaviour" test pattern dominates; the "what happens when state accumulates" pattern is absent.

---

### [Phase 2f] P0 — IPv6 ACT_TAG silently corrupts the packet (source-address bytes overwritten)

Where: `bpf/tc_ingress.bpf.c` DSCP-rewrite path. Hard-codes IPv4 byte offsets (byte 15 of L3 header for TOS, offset 24 of L2 frame for checksum update). No IP-family gate. L4 (`layer4.bpf.c:260-262`) sets `ACT_TAG` regardless of family; TC then writes IPv4-shaped bytes into an IPv6 packet:
- Byte 15 of IPv6 header = top nibble of TC, top nibble of FlowLabel → mangled
- `bpf_l3_csum_replace` at frame offset 24 → IPv6 bytes 2–3 of source address → silent address corruption

Expected to catch this:
- A functional test that configures a `tag` action on an IPv6 rule, sends an IPv6 packet, captures it on the egress veth, and asserts the source address and traffic-class bits are intact. `functional_tests/test_dscp_tag.py` (3 tests per recon) almost certainly tests IPv4 only.
- A `BPF_PROG_TEST_RUN` integration test of TC ingress with an IPv6 packet carrying `ACT_TAG` in `pkt_meta`, asserting that the output buffer matches the input except for sanctioned bytes.

Test gap class: **test wrong layer / wrong family** — IPv4 happy-path covered, IPv6 family entirely untested for this action. Continues the IPv6 pattern.

---

### Meta-pattern, updated after Phase 2f

**IPv6 is pktgate's most systematically broken surface.** Three IPv6-specific security/correctness bugs found across three different files:
1. `bpf/layer3.bpf.c` — Fragment-Header-behind-Hop-by-Hop bypass on terminal-allow rules (P1, Phase 2b)
2. `bpf/layer4.bpf.c` — 5+ ext-header chain bypasses all L4 rules and rate-limit (P0, Phase 2d)
3. `bpf/tc_ingress.bpf.c` — ACT_TAG path corrupts the IPv6 source address with no IP-family gate (P0, Phase 2f)

In every case, the IPv4 sibling logic is correct and tested; the IPv6 path is either added as an afterthought (L3/L4 duplication of v4) or simply omitted (TC). The test suite mirrors this gap: IPv6 happy paths exist (`test_l3_ipv6.py`), adversarial / cross-action coverage does not. Treat "IPv6 audit" as a phase-3 cross-cutting topic, not as ten individual bugs.

---

### [Phase 3] **THE META-FINDING** — CI runs only `unit` and `integration` ctest labels

Per Phase 3 review of CI configuration: `bpf_dataplane` ctest label and the entire `functional_tests/*.py` pytest suite **run nowhere automatically**. Combined with everything else in this ledger:

> **Every single P0 from Phase 2 passed CI green.**

The tests that *could* have caught the catastrophes exist, but they're not in the CI loop. This is the most important sentence in the whole review:

- Adding more tests doesn't help if those tests aren't in CI
- Strengthening existing tests doesn't help if those tests aren't in CI
- Even fixing the test-as-contract anti-pattern doesn't help if those tests aren't in CI

**Recommendation for the tests-phase:** CI shape must be fixed FIRST. Step 1: wire all ctest labels into the on-PR job. Step 2: add a separate functional-tests CI job (requires root or rootless veth, both feasible in GitHub Actions). Step 3: only THEN start adding tests for the findings in this ledger — otherwise the project remains in a state where adding tests creates false confidence (the tests pass locally on the developer's machine, the bugs ship anyway).

---

### [Phase 2j] P0 — `validate_config` tool is documented as pre-deploy gate but doesn't compile rules

Where: `tools/validate_config.cpp` runs only parser + validator, never `compile_rules`. CONFIG.md:40 calls it the pre-deploy validation step. A config triggering the dst_ip P0 (catch-all wildcard → drop all IPv4) prints `OK <file>` and exits 0. **The tool is actively misleading on exactly the catastrophic configs it should catch.**

Bonus structural gap: `validate_config.cpp` is **not in `CMakeLists.txt`**. The binary in `build/` is a stale Apr-9 leftover. CONFIG.md documents a tool that fresh builds don't produce — operators following the doc on a clean checkout get "command not found".

Expected to catch this:
- A test that builds `validate_config` from CMake (would fail at link time, exposing the missing target)
- A test that runs `validate_config` against a known-bad dst_ip-only config and asserts it returns non-zero
- An end-to-end test: `validate_config A.json && deploy A.json` against a tree of intentionally bad configs

Test gap class: **tool entirely untested**. No `tests/` or `functional_tests/` entry exercises this binary. Combined with the missing CMake target, the tool exists in a state of "documented but unverified" — the worst kind of operator-facing surface.

---

### [Phase 2i] P2 — `test_l2_ethertype_invalid_hex_chars` cements a parser quirk AS CONTRACT

Where: `tests/test_l2_ethertype_invalid_hex_chars` (per Phase 2i §12 findings) asserts the existing — and apparently quirky — ethertype hex-parser behaviour as the documented contract, mirroring `test_l2_qinq_not_parsed`.

**This is the second instance of the "test asserts the bug" pattern.** With QinQ that was an isolated incident; with two cases, it becomes a **project-level test-culture concern**:
- Negative assertions of broken-by-design behaviour exist in the test suite without any tracked TODO/issue capturing the design decision
- The pattern propagates: future maintainers who see two such tests will create a third without questioning the practice
- Code review (human or AI) cannot detect "this test locks in a defect" without external context

**Recommendation for the tests-phase:** treat tests-as-contract assertions as a category. Each such test needs (a) an ARCHITECTURE.md / TODO.md entry documenting the deferral and its reversibility, or (b) a removal. Static analysis to detect "tests that assert error returns / negative outcomes" without a linked design note would help.

---

### [Phase 2c] P1 — QinQ (0x88a8) not parsed; test ACTIVELY asserts the bug AS CONTRACT

Where: `bpf/layer2.bpf.c` (per Phase 2c) does not recognise 0x88a8 as an outer VLAN tag, so customer-VLAN under carrier-VLAN is invisible. `tests/bpf/test_bpf_dataplane.cpp:1048` (`test_l2_qinq_not_parsed`) asserts this behaviour as the expected contract.

This is **qualitatively different** from the other test-audit entries above: it isn't a test that didn't catch a bug — it's a test that **cements the bug as design**. Someone either (a) deliberately decided "QinQ unsupported, ship anyway", or (b) didn't have time to implement and froze the gap with an assertion-as-documentation. Either way the test now blocks the fix: anyone who implements QinQ will see this test fail and either revert the implementation or delete the test. Without a code archaeology trail (commit message, ARCHITECTURE.md note), the next maintainer has no signal which it is.

For a **carrier Gi-side filter** this is severe — carrier links commonly stack S-Tag (0x88a8) outer + C-Tag (0x8100) inner. Without 0x88a8 parsing, every customer-VLAN-aware filter rule (vlan_id matching) silently misses on QinQ traffic. The packet falls through to L3 with `eth->h_proto = 0x88a8`, which L3 then drops as `STAT_DROP_L3_NOT_IPV4`.

Expected to catch this (the meta-bug, not the QinQ behaviour itself):
- A code-review or CI rule that flags `test_l2_qinq_not_parsed`-style "negative assertion as contract" patterns with a required ARCHITECTURE.md justification
- A separate tracking issue/TODO recording the design decision and its reversibility

Test gap class: **test that locks in a known defect as the spec**. Most damaging variant — false confidence times two.

---

### [Phase 2b] P2 — L3 tail-call asymmetry on missing prog_array slot

Where: `bpf/layer3.bpf.c:99-107, :150-157` (matched-rule path: fail=DROP) vs `:284-290, :229-234` (no-match path: fail=apply default).

Expected to catch this:
- A `BPF_PROG_TEST_RUN` with the L4 slot of `prog_array_{0,1}` deliberately unpopulated, run twice: once with a packet that matches an L3 rule (assert: DROP, `STAT_DROP_L3_TAIL` incremented), once with a packet that misses all L3 rules (assert: behaves per default). Would surface the asymmetry. Probably not in `test_bpf_dataplane.cpp`.

Test gap class: **test absent** (negative-state coverage of the loader's atomicity invariant).

---

## How to use this file later

- The tests-phase reviewer reads this list, opens each cited test file, and confirms (a) whether the test exists, (b) what level of assertion strength it carries, (c) whether the test could be strengthened cheaply
- Patterns of "test exists but checks the wrong invariant" deserve a P1 of their own in the final report — they're worse than "no test" because they radiate false confidence
- The `scenarios/` and `scenarios_v2/` directories present a ready-made opportunity: each is a config the operator might write; the tests-phase should treat "every scenario in `scenarios/` loads cleanly and produces non-wildcard map entries" as a single contract worth one test
