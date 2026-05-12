# 12 — config_parser + config_validator (Phase 2i)

## What this module does

The module is the trust boundary between operator-supplied JSON and the rest of pktgate. Two stages:

1. **`config_parser.cpp` (163 LOC)** turns a JSON file/string into a `Config` struct via nlohmann_json. Per-field reads, optional fields, hand-rolled value-range checks for `vlan_id` and `pcp`, and a one-shot in-parser format-check on `tcp_flags`. Type mismatches surface as `json::type_error` and are translated to `std::unexpected("Parse error: …")` by a single `try/catch` in `parse_json` (`config_parser.cpp:63,136-138`). File-level JSON errors are translated by a second `try/catch` in `parse_config` / `parse_config_string` (`:149-151,158-160`). The parser has no file-size guard — `std::ifstream` + `json::parse` reads the whole file.

2. **`config_validator.cpp` (200 LOC)** runs semantic validation per layer, returning `std::vector<ValidationError>` accumulated across all problems (not fail-fast). Per layer: `validate_rule_ids` (uniqueness), `validate_l2_rules`, `validate_l3_rules`, `validate_l4_rules`. There is a global "interface required if any rule exists" check (`:185-189`). The config-schema.json at repo root is **not** wired into this code path — see Q7.

The data model lives in `config_model.hpp` (a header-only file; no `.cpp`). It also hosts `parse_action`, `dscp_from_name`, `parse_ethertype`, `parse_tcp_flags`, `parse_bandwidth`. Both parser and validator call these inline-header helpers — they throw `std::invalid_argument` / `std::overflow_error` on bad input. Validator wraps each call in `try {} catch (...)` to translate to a `ValidationError`. Parser does not always wrap them (see Q9 for the bandwidth overflow path).

## Per-question findings

### Q1 — L3 "must have a match field" guard (the P0 fix point)

Confirmed: **no guard exists.** `validate_l3_rules` (`config_validator.cpp:82-111`) iterates rules and only does action-checks (object ref, mirror target, redirect target_vrf, next_layer name). It never counts match fields. An L3 rule with no recognised match field (no `src_ip`, no `src_ip6`, no `vrf`) passes validation cleanly and reaches the compiler, where Phase 2a §Q1 documented that it becomes a wildcard `0.0.0.0/0` LPM entry.

The guard belongs **inside `validate_l3_rules` before line 90**, structured as a mirror of the L2 guard at `:40-48`:

```c
int match_count = 0;
if (r.match.src_ip)  ++match_count;
if (r.match.src_ip6) ++match_count;
if (r.match.vrf)     ++match_count;
if (match_count == 0)
    errs.push_back({ctx, "L3 rule must specify a match field (src_ip, src_ip6, or vrf)"});
```

Also confirmed: `dst_ip` and `dst_ip6` are **completely absent** from `validate_l3_rules`. The model carries them (`config_model.hpp:37,39`), the parser populates them (`config_parser.cpp:32,34`), and nothing else in the codebase reads them. They behave as if undeclared — except that the operator gets no error. The fix is to either (a) silently treat them as ignored fields **after** rejecting the no-match case (current proposal), or (b) explicitly reject `dst_ip`/`dst_ip6` until proper destination-LPM tries exist. (b) is strictly better for trust-boundary clarity — the validator is the only place that can stop a documented-but-unimplemented field from reaching deploy.

**L4 has a guard.** `validate_l4_rules` requires both `protocol` (`:121-122`) and `dst_port` (`:127-128`) explicitly. An L4 rule with no fields generates two errors and is rejected. This is the model L3 should follow.

### Q2 — Wrong-layer field drops (Phase 2a §Q7)

Confirmed: **no cross-field check exists.** The validator has no "fields applicable to this layer" table; each `validate_lN_rules` only reads the fields it cares about and silently ignores the rest. An operator placing `dst_port: "80"` in `pipeline.layer_3[0].match` gets no error from the validator; the compiler then drops the field (Phase 2a §Q7). Similarly, `vlan_id` on an L4 rule, `src_ip` on an L4 rule, `tcp_flags` on a UDP rule (Phase 2d P2 — partially caught: `:166-169` does require `protocol == TCP`), etc.

The `tcp_flags`-on-UDP case is the **only** wrong-protocol guard the file has, and it's actually correct (`:167-169` rejects `tcp_flags` with non-TCP protocol). Everything else — `src_mac` on L3, `vrf` on L4, `dst_port` on L2/L3, etc. — slips through.

Suggested implementation: a static per-layer "allowed match fields" `std::array<bool, N>` and a single sweep at the start of each `validate_lN_rules` that emits a `"field 'X' is not applicable to layer N"` error for each populated-but-not-allowed field. ~15 lines, no design changes.

### Q3 — L2 `match_count == 0` guard

Confirmed at **`config_validator.cpp:40-48`** (Phase 2a's cite of `:47-48` was slightly off — the count starts at `:40`, the emit is at `:47-48`). The check is exact:

```c
int match_count = 0;
if (r.match.src_mac)   ++match_count;
if (r.match.dst_mac)   ++match_count;
if (r.match.ethertype) ++match_count;
if (r.match.vlan_id)   ++match_count;
if (r.match.pcp)       ++match_count;
if (match_count == 0)
    errs.push_back({ctx, "L2 rule must specify a match field …"});
```

This is the template for the L3 fix. Note that `if (r.match.vlan_id)` and `if (r.match.pcp)` rely on `std::optional::operator bool` — `vlan_id = 0` (a *valid* default VLAN) and `pcp = 0` (a *valid* priority value) both count as "present" because the optional has a value, not because the value is non-zero. Good.

`tests/test_config_validator.cpp:418-427` (`test_l2_no_match_field_rejected`) exists. The L3 equivalent does not — `tests/test_config_validator.cpp` has zero tests for "L3 with no match field" or "L3 with only dst_ip". This is the test-audit miss already in `TEST_AUDIT.md`.

### Q4 — Object-reference validation: `object6:` in non-L3 rule

Confirmed (Phase 2a §Additional §3): the bespoke `object6:` check at `config_validator.cpp:93-100` is **inside `validate_l3_rules`** and **only checks `r.match.src_ip6`**. `r.match.dst_ip6` is not touched even when it carries an `object6:` ref. More importantly, the generic `check_object_ref` helper (`:7-17`) only handles the `object:` prefix (line 12: `if (!ref.starts_with("object:")) return;`), so it is structurally incapable of resolving `object6:foo` even if a caller passed it.

Concrete scenarios that escape validation and reach the compiler:

1. **`pipeline.layer_2` rule with `src_ip6: "object6:foo"`**: nothing in `validate_l2_rules` reads `src_ip6` at all. The validator passes. The L2 compiler (`rule_compiler.cpp` L2 loop) also ignores `src_ip6` (cross-field drop, Q2). Net effect: the operator's rule has a silent-drop field but compiles; the `object6:foo` ref is **never resolved**, which is harmless here because nothing reads it.
2. **`pipeline.layer_3` rule with `dst_ip6: "object6:foo"`**: `validate_l3_rules` only does the `object6:` check on `src_ip6`. `dst_ip6` with `object6:` slips through; `dst_ip6` is dropped at compile time anyway (Phase 2a §Q2). Harmless because of the parallel cross-field drop.
3. **Truly dangerous case**: an `object6:foo` ref in `src_ip6` of an L3 rule where `foo` doesn't exist in `objects.subnets6`. The validator's bespoke block at `:95-100` does catch this **if the ref starts with `object6:`**. So this single path is actually covered.

So the validator gap is narrower than Phase 2a §Additional §3 phrased it: an `object6:` ref **in a layer where the compiler ignores `src_ip6` anyway** doesn't crash the compiler (the field is never read). The original Phase 2a worry was "compiler throws on unknown object6"; in practice the compiler throws only when the layer-N compiler actually reads the field, which means only L3 reads `src_ip6` and that path is covered. **The remaining gap is structural, not operational**: `check_object_ref` is hard-wired to `"object:"` and only an ad-hoc patch resolves `"object6:"`. A clean fix is to extend `check_object_ref` to accept a prefix parameter and route subnets6 through it.

Also: there is **no** validator check that resolves `vrf` names against any registry — `vrf` is matched at runtime by ifindex, and Phase 2a noted that the L3 compiler converts `vrf` strings via `if_nametoindex()`. Unknown VRFs error at deploy, not at validate. Out of scope here.

### Q5 — port > 65535 path (TEST_PLAN.md claim)

Phase 1 §2 was right and TEST_PLAN.md is stale. Trace:

- **Literal port via JSON `dst_port: 70000` integer**: parser unconditionally reads `dst_port` as **string** (`config_parser.cpp:37`). An integer JSON value triggers nlohmann's `json::type_error` → caught at `:136-138`, returns `unexpected("Parse error: …")`. Blocked at parse.
- **Literal port via JSON `dst_port: "70000"` string**: parser stores raw string. Validator's `:133-141` literal-port path runs `std::stoi` → range check `> 65535` → emits `"port out of range"`. Test `test_l4_port_out_of_range` (`tests/test_config_validator.cpp:198-209`) covers this.
- **Port group: `port_groups: { "x": [70000] }`**: parser reads ports as `int` and validates `val < 0 || val > 65535` at `config_parser.cpp:97-100`. Throws `unexpected` at the parser level. Bound enforced **before** group expansion.
- **Port group: `port_groups: { "x": ["70000"] }` (string-encoded)**: parser's `.get<int>()` on a string raises `json::type_error` → caught → unexpected. Test `test_parse_port_as_string_in_array` covers this.
- **Negative port via group `[-1]`**: parser's `val < 0` check rejects. Test `test_parse_negative_port_in_group` exists but only asserts "no crash"; it doesn't actively check the rejection.
- **CIDR-port range syntax**: doesn't exist in the language; ports are scalars.

**TEST_PLAN.md "port > 65535 passes validation" is wrong** in the current code. Either it was true at some past point (recon §164 lists it as a known finding) and got fixed, or it was always speculative. Promote: removed from active P0 list.

The one nit: the validator's `std::stoi` (`:135`) accepts trailing garbage — `dst_port: "80abc"` will parse as 80 and pass validation, since `stoi` reads as many digits as possible and ignores the rest. Cosmetic; not a security gap.

### Q6 — JSON shape validation

Behaviour is acceptable but coarse. `parse_json` wraps the entire body in one `try {} catch (const std::exception&)` (`:63,136-138`). Any nlohmann throw — `type_error` (wrong field type), `out_of_range` (`.at("rule_id")` missing on a required key), `parse_error` (malformed) — is translated to `"Parse error: " + e.what()`. The outer `parse_config_string` / `parse_config` additionally catch `json::parse_error` separately and prefix it with `"JSON parse error: "`. There are no crashes — all paths go through the catch.

What the user gets, though, is **one** error message per file load: the first throw wins. Operators with multiple type errors only see the first. This is opposite to the validator design, which accumulates. Consistency improvement: have the parser collect type errors per rule the same way the validator does. Low priority.

Tests cover this fairly well: `test_parse_rule_id_as_string`, `test_parse_cos_as_string`, `test_deeply_nested_invalid` (`tests/test_config_parser.cpp`, `tests/test_config_validation.cpp`).

### Q7 — Schema validation (`config-schema.json`)

**Not wired in. Documentation-only.** Grep across the entire tree (excluding `bpf/vmlinux.h` and the schema itself):

```
CONFIG.md:36                    "Config is validated against config-schema.json"
scenarios/README.md:50          "Все конфиги соответствуют config-schema.json"
```

No `.cpp`, `.hpp`, `CMakeLists.txt`, `.cmake`, or build artefact references the schema. No `nlohmann::json_schema_validator` dependency in `CMakeLists.txt` (and the library isn't a listed dep — recon §131 lists only nlohmann_json itself). No CI step validates anything against it.

**This is a P1 structural finding.** The schema gives a *false* contract impression to anyone reading CONFIG.md: an operator who reads "Config is validated against config-schema.json" reasonably believes that field-presence rules in the schema (e.g., `rule_l2 "required": ["rule_id", "action", "match"]` → match is required for L2; or `rule_l3` not requiring match — which would directly capture the missing L3 guard!) are enforced. The validator does not enforce them; instead it has a hand-rolled subset of these rules.

Look at the schema's L2 definition (`config-schema.json:240`): `"required": ["rule_id", "action", "match"]` and `match` has `"minProperties": 1`. That is exactly the L2 "match_count >= 1" rule, expressed declaratively. The L3 definition does NOT require `match` and does NOT have `minProperties: 1`, which mirrors the validator bug — the schema also fails to constrain L3. So even if the schema were wired in, **it would not catch the L3 wildcard P0**.

Recommendations, in order of severity:
1. (P1) Either wire in `nlohmann/json-schema` (Apache 2.0, header-only, small) at the start of `parse_config_string` to fail-fast on shape mismatches, OR delete the schema and remove the CONFIG.md claim. Current state misleads.
2. (P0 for the L3 dst_ip story) Whether or not the schema is wired in, **add `minProperties: 1` to the L3 `match` definition** in `config-schema.json` — it costs nothing and aligns the schema with the (yet-to-be-added) L3 validator guard. Make sure the schema also moves `dst_ip`/`dst_ip6` to a "not yet implemented" comment until the data plane reads them.

### Q8 — Resource limits / file size

**No file size guard.** `parse_config` (`:141-152`) opens `std::ifstream` and feeds it to `nlohmann::json::parse`. A 1 GB JSON file is read all the way through. nlohmann's DOM is in-memory; for a 1 GB JSON the process easily allocates several GBs of RSS and may be OOM-killed.

`file_is_nonempty` in `src/main.cpp:115-119` only checks `st.st_size > 0`. No upper bound. An adversary with write access to the config path can DoS the daemon via a 10 GB sparse-then-dense file; inotify will trigger reload, `parse_config` will try to slurp the lot, the daemon will be killed by OOM-killer or hang.

Reload guards:
- The 150 ms inotify debounce (`src/main.cpp:65-93` per recon) doesn't help against size — a single 10 GB file is one debounced event.
- `do_reload` does not check size before parse (`src/main.cpp:31-62`).

**P1: add a size cap** at `do_reload` or `parse_config`. Reasonable default ~4 MiB; a single config with all 4096 rules × ~256 bytes/rule × 3 layers = ~3 MiB, so 4 MiB is generous. Anything larger should be rejected with `"Config file exceeds N MiB"`. Same guard belongs in `tools/validate_config.cpp` and the fuzz harness ought to bound the input size (libFuzzer accepts arbitrarily large blobs).

### Q9 — Bandwidth numeric overflow

The arithmetic guard is at `config_model.hpp:200-201`:

```c
if (multiplier > 1 && value > UINT64_MAX / multiplier)
    throw std::overflow_error("Bandwidth overflow: " + s);
```

This is **correct** for the four supported units (bps/Kbps/Mbps/Gbps). Test `test_rate_limit_bandwidth_overflow` (`tests/test_config_validator.cpp:291-303`) feeds `"99999999999Gbps"` and asserts a validation error.

**Tbps/Pbps are not in the language** (`config_model.hpp:194-198`); the units list is `bps|Kbps|Mbps|Gbps` (case-insensitive). `parse_bandwidth("10Tbps")` throws `"Unknown bandwidth unit: Tbps"`. Test `test_bandwidth_invalid_unit` covers this. So the question's `100 Pbps` / `1e25 Tbps` overflows can't be expressed — overflow is bounded by `value * 1e9` for Gbps, capped by `UINT64_MAX / 1e9 ≈ 1.84e10`. Numbers > ~18.4 Gbps (× 1e9) are caught by the overflow guard.

**Nit: `std::stoull` itself can throw `std::out_of_range` for values exceeding `uint64_t`** (e.g., `"99999999999999999999Gbps"`, 20 nines). Looking at `:190`: `uint64_t value = std::stoull(s.substr(0, pos));` — this is **not** wrapped, so it throws `out_of_range`. The validator's `try {} catch (...)` at `:159-162` catches it as a generic "invalid bandwidth". Operator sees `invalid bandwidth: …` instead of `Bandwidth overflow: …`. Minor message-quality issue; functionally safe.

**Nit 2: parser does not call `parse_bandwidth` at parse time** — only the validator does. So a parser-level config-load doesn't reject a bad bandwidth (parser stores the raw string at `:53`). Validator catches it on the next stage. This is fine but means `tools/validate_config` (which runs both) catches it; the parser alone doesn't. Aligns with the "parser is dumb, validator is strict" pattern; no action needed.

### Q10 — Object-store recursion / cycles

**Object references are flat.** Looking at the data model (`config_model.hpp:14-26`), `ObjectStore` is four `unordered_map<string, X>` where the values are `std::string` (subnets/subnets6), `vector<string>` (mac_groups), or `vector<uint16_t>` (port_groups). The values are **never object references** — they are literal CIDRs, MACs, or port numbers. There is no syntax for `subnets: { "a": "object:b" }` or `mac_groups: { "a": ["object:b"] }`.

The parser at `config_parser.cpp:74-105` reads these into the store **without** interpreting any `object:` prefix. The validator at `config_validator.cpp:7-17` and the compiler (Phase 2a §Q1) only do single-level resolution: rule → ObjectStore. No recursion.

So: **no cycle hazard, no depth limit needed**. The design is intentional and correct. Worth a one-line note in CONFIG.md, but no fix required.

### Q11 — Unicode / encoding

The parser hands raw strings to the model without sanitisation. `r.match.src_mac = m["src_mac"].get<std::string>()` accepts whatever bytes nlohmann hands back (nlohmann normalises JSON-escaped Unicode `\uXXXX` to UTF-8 bytes). The string then sits in the model. Effects:

- **MAC parsing** happens in `util/net_types.hpp` (per recon §40), called from the L2 compiler. A Unicode-garbage string fails the regex / parse and the compiler throws → caught at the generic catch (`rule_compiler.cpp:303-305`, Phase 2a §Additional §6) → translated to a single error string. No crash. Good.
- **IP parsing** uses `inet_pton` (per Phase 2a §Q6 endianness table). `inet_pton` returns 0 on non-numeric input. Translates to a constructor throw via `Ipv4Prefix::parse` / `Ipv6Prefix::parse`. Same catch path. Good.
- **Ethertype parsing** (`config_model.hpp:131-142`) uses `std::stoul` on the substring after `0x`. Documented quirk: `"0xGGGG"` → `stoul` consumes only `"0x"` and returns 0 silently, NOT throwing. Test `test_l2_ethertype_invalid_hex_chars` (`tests/test_config_validator.cpp:717-731`) **documents this as accepted behaviour** (it asserts `result.has_value()`). The comment in that test even says "BUG … This test documents current (buggy) behavior." This is another **test that cements a defect as contract**, parallel to `test_l2_qinq_not_parsed` (TEST_AUDIT.md). Effect: an operator writing `"ethertype": "0xZZZZ"` gets a successful validation that compiles to a rule matching ethertype 0x0000 — likely matches nothing in practice, but it's a silent misconfig.

**Nit: ethertype hex parser also lacks a leading-zero / non-empty check after `0x`.** `"0x"` parses to 0 by the same mechanism (test `test_l2_ethertype_incomplete_hex` documents this). Combined with the `0xGGGG` quirk, the validator silently accepts garbage hex strings as `ethertype=0`. Fix: use `std::from_chars` (no implicit prefix consumption) or validate the suffix is all-hex before `stoul`.

No buffer overflows or memory-corruption hazards from Unicode. Worst case is "silent wrong-value" via the hex quirk above.

### Q12 — Fuzz harness coverage

`fuzz/fuzz_config_parser.cpp` (35 LOC, read above): calls **only `parse_config_string`**. The validator is not exercised. The compiler is not exercised. The deploy path is not exercised.

Concrete consequence for the L3 dst_ip P0: the fuzz harness cannot surface it because the bug is a silent **semantic** failure (rule compiles, BPF entry inserted, traffic mis-handled). The fuzz harness only checks "parser doesn't crash on N bytes of input" — and the parser doesn't crash on `{"pipeline":{"layer_3":[{"rule_id":1,"action":"drop","match":{"dst_ip":"10/8"}}]}}`. There's no oracle that would say "this should have been rejected".

There is `fuzz/fuzz_roundtrip.cpp` (per recon §85-86); that one's a pipeline fuzz which **might** exercise compile-time. Out of scope here, but worth flagging in the fuzz-phase: "extend fuzz_config_parser to additionally call validate_config + compile_rules and report any unexpected-success cases against a corpus of known-bad seeds."

No file-size cap in the fuzz harness either; libFuzzer's default is 1 MB which limits real-world DoS via the harness, but a manual `afl-fuzz` invocation could hit the parser with arbitrary sizes.

### Q13 — Other surprises

1. **Validator runs even when parser was already strict** — duplicate `parse_tcp_flags` invocation at parser (`config_parser.cpp:40`) and validator (`config_validator.cpp:170`). The parser's call throws → caught at parser → operator sees `"Parse error: …"`. So validator-side check at `:170` is unreachable for the failure case. Cosmetic but means the validator's "invalid tcp_flags" error path is dead code unless a non-parser caller injects a bad value into the model. Not a bug; just inelegant.

2. **`validate_rule_ids` is per-layer; cross-layer collision is allowed.** Test `test_same_rule_id_different_layers_ok` confirms (`tests/test_config_validator.cpp:99-116`). This is consistent with the compiler's per-layer maps but means stat-counter labels (Prometheus) may have ambiguous `rule_id` labels across layers. Out of scope here; flagged in 02_architecture for the metrics phase.

3. **`device_info.capacity` is parsed but never validated** (`config_parser.cpp:68`). An operator can write `"capacity": "moose"` and the load succeeds. The string is dragged along but never used (grep `cfg.capacity` across `src/`: only `config_parser.cpp` writes it). Either delete the field or validate it via `parse_bandwidth`.

4. **`description` is unbounded** (`config_parser.cpp:12`). An operator can write a 100 MB description; combined with the absent file-size guard (Q8), this is a tiny DoS vector. Minor.

5. **No CIDR validation in the validator.** `r.match.src_ip = "999.999.999.999/40"` passes validation; the compiler's `Ipv4Prefix::parse` throws at deploy time. Validator should call `Ipv4Prefix::parse` (and IPv6 equivalent) eagerly so that bad CIDRs surface at validate, not deploy. The error path is the same end-user message either way, but `tools/validate_config` becomes a less reliable smoke-test without it: it currently green-lights configs that the deploy step will reject.

6. **Validator does not check `target_port` is a valid interface name** (`config_validator.cpp:71-72,102-103`). `target_port = "moose with spaces and 你好"` passes validation; `if_nametoindex` fails at deploy. Same comment as CIDR above — defer-to-deploy makes `validate_config` weaker than it appears.

7. **No check that the action emits action_params it requires.** `tag` action without any `dscp` and without `cos` validates — it becomes a no-op tag (the L4 compiler still sets ACT_TAG, the TC stage rewrites nothing). The validator only checks `dscp` *if present* (`:144-150`) and `cos` *if present* (`:151-152`); it doesn't require at least one. Mostly harmless but qualifies as silent semantic failure.

## Additional findings

- **`parse_tcp_flags` is called from the parser as a format check** (`config_parser.cpp:40`) but `parse_tcp_flags`'s return value is **discarded** (assigned to no variable). Parser only stores the raw string for the compiler to re-parse later. Compute is duplicated three times in a normal config (parser, validator, compiler). Minor.

- **`std::stoi` in port-literal validation uses default base 10** (`config_validator.cpp:135`). `dst_port: "0x50"` will parse as 0 (stoi stops at the `x`) → validates as port 0 → compiles → matches port 0. Not exploitable but inconsistent with ethertype-as-hex.

- **`device_info.interface` is required-if-rules-exist** but the check (`config_validator.cpp:185-189`) does not validate the string against `if_nametoindex` (mirrors Phase 2a comment §`target_port`). Deploy-side will fail. Probably fine here.

- **`Action::Drop` on an L2/L3 rule with `next_layer` set** is accepted by the validator. A "drop with next_layer:layer_4" is contradictory — the drop is terminal. The L2/L3 compilers presumably honour the drop action and ignore next_layer, but the operator's intent is undefined. Mild semantic-conflict, not flagged in validator.

- **Validator returns `std::expected<void, std::vector<ValidationError>>`** which is then unpacked at `pipeline_builder.cpp:22` and `tools/validate_config.cpp:24`. The shape is fine. `ValidationError` carries a `rule_context` string and a `message`; not enough for structured diagnostics (no rule_id, no field name). For an internal review-only daemon this is acceptable.

## Findings (graded)

```
- [P0 — closes Phase 2a P0] Validator does not enforce "L3 rule has at least one match field"
  Where: src/config/config_validator.cpp:82-111 (validate_l3_rules)
  What: The Phase 2a wildcard-LPM P0 has its root cause here. The validator passes any L3
        rule, even one with zero match fields (or only the unimplemented dst_ip/dst_ip6).
        The compiler then pushes a {prefixlen=0, addr=0} LPM entry that catches every packet.
  Why it matters: One operator typo "dst_ip" instead of "src_ip" — silent outage. The single
        most important Phase-2 fix.
  Suggested action: Insert a guard before line 90 mirroring the L2 guard at :40-48:
        count src_ip, src_ip6, vrf; emit error on 0. Also: either reject dst_ip/dst_ip6
        unconditionally (until destination LPM tries exist) or treat them as ignored after
        the count.

- [P0] Validator does not reject wrong-layer match fields
  Where: src/config/config_validator.cpp — entire file
  What: An L3 rule with `dst_port` set, an L4 rule with `vlan_id` set, an L2 rule with
        `src_ip` set, etc. — all pass validation, get silently dropped at compile time.
        The only wrong-layer check present is tcp_flags-on-non-TCP (:166-169).
  Why it matters: Same class as the dst_ip P0 — operator's stated intent diverges silently
        from runtime behaviour. The validator is the trust boundary; this is exactly the
        kind of error it exists to catch.
  Suggested action: Add a per-layer "allowed match fields" set; emit
        "field 'X' is not applicable to layer N" for any field in the model that is not
        in the layer's allowed set. ~15 LOC.

- [P1] config-schema.json is documented as the contract but is never wired in
  Where: config-schema.json (repo root); CONFIG.md:36; scenarios/README.md:50
  What: The schema is referenced as if it were enforced. No code path validates against
        it. nlohmann/json-schema is not a dependency. Operators reading CONFIG.md believe
        in a contract that doesn't exist. Additionally, the schema's own L3 rule
        definition lacks `minProperties: 1` and would not catch the L3 P0 even if wired in.
  Suggested action: Pick one — (a) wire in nlohmann/json-schema-validator at parse entry,
        fail-fast on shape mismatches; (b) delete the schema and the CONFIG.md claim.
        Whichever path, fix the L3 `match` definition to require `minProperties: 1` and
        annotate dst_ip/dst_ip6 as "accepted but ignored (unimplemented)".

- [P1] No file-size guard on config-file load
  Where: src/config/config_parser.cpp:141-152; src/main.cpp:31-62 (do_reload),
         src/main.cpp:115-119 (file_is_nonempty)
  What: parse_config slurps the whole file via std::ifstream → nlohmann::json::parse.
        An adversary with write access to the config path can force OOM by writing a
        huge JSON file; inotify will pick it up and trigger reload.
  Suggested action: Reject files larger than e.g. 4 MiB before invoking the parser; emit
        a clear error and skip the reload. Same guard for tools/validate_config and the
        fuzz harness (libFuzzer max-len bound).

- [P2] Test `test_l2_ethertype_invalid_hex_chars` cements a defect as contract
  Where: tests/test_config_validator.cpp:717-731; root cause in config_model.hpp:131-142
  What: stoul("0xGGGG", …, 16) consumes only the "0x" prefix and returns 0. The
        validator silently accepts the rule with ethertype=0x0000. The test asserts this
        as expected behaviour with a comment "BUG … This test documents current (buggy)
        behavior." Parallel to `test_l2_qinq_not_parsed` in `tests/bpf/`.
  Suggested action: Fix the hex parser (use std::from_chars or validate suffix is all
        hex). Update the test to assert rejection.

- [P2] Validator does not eagerly parse CIDRs / interface names
  Where: src/config/config_validator.cpp:90-100 (L3 src_ip / src_ip6 paths)
  What: A bogus CIDR string passes validation; compiler fails at deploy. `tools/validate_config`
        therefore gives green light for configs that won't deploy. Same for `target_port`
        (interface name).
  Suggested action: Eagerly call Ipv4Prefix::parse / Ipv6Prefix::parse on literal CIDRs
        in the validator, and check target_port via if_nametoindex (or document the
        limitation).

- [P2] Generic catch in parser yields one error per file load; validator collects multiple
  Where: src/config/config_parser.cpp:63,136-138
  What: First nlohmann throw wins; operator sees one error at a time. Validator design is
        accumulator-style; parser inconsistent.
  Suggested action: Restructure parse_rule loop to collect per-rule errors before the
        outer catch — or accept the inconsistency and document it.

- [P2] `device_info.capacity` is parsed but never validated
  Where: src/config/config_parser.cpp:68
  What: A bogus capacity string passes load. The field is unused elsewhere.
  Suggested action: Either validate via parse_bandwidth or remove the field.

- [P2] `description` field is unbounded
  Where: src/config/config_parser.cpp:12
  What: Combined with the missing file-size guard, an attacker can shape a malicious
        file with many huge `description` fields to spike RSS.
  Suggested action: cap at e.g. 1 KiB per field, emit a parse error on overflow.

- [P2] `object6:` ref handling is bespoke, only covers src_ip6 in L3
  Where: src/config/config_validator.cpp:93-100
  What: `check_object_ref` is hard-wired to the `object:` prefix; the `object6:` case
        is handled by an inline block that only checks one field, one layer. Not currently
        operationally harmful (other layers ignore src_ip6), but structurally fragile —
        a future field that also accepts object6: would need its own bespoke block.
  Suggested action: Generalise check_object_ref to accept a prefix parameter, and call
        it for dst_ip6 too (or, ideally, for all *_ip6 fields the layer reads).

- [P2] Fuzz harness `fuzz/fuzz_config_parser.cpp` exercises only the parser, not validator
  Where: fuzz/fuzz_config_parser.cpp
  What: Cannot surface semantic bugs (the dst_ip P0 is a silent-success case; harness
        has no oracle for "this should have been rejected"). No file-size cap either.
  Suggested action: Add `validate_config` call after parse and report any unexpected
        success; build a negative-corpus of "must be rejected" seeds. See tests-phase.

- [P2] Validator's `tcp_flags` re-parse path (:170-173) is dead code in practice
  Where: src/config/config_validator.cpp:170-173
  What: Parser already validates tcp_flags format via parse_tcp_flags at
        config_parser.cpp:40; bad strings never reach the validator.
  Suggested action: Either drop the duplicate or accept it as defense-in-depth (and
        document).

- [P2] Action `tag` without dscp or cos still validates
  Where: src/config/config_validator.cpp:144-153
  What: `tag` is no-op without parameters, but validator doesn't require at least one.
  Suggested action: Reject if neither dscp nor cos present.
```

## Test-audit notes

| Phase 2i finding | Test that should have caught | Current status |
|---|---|---|
| L3 "must have match field" missing | A `test_l3_no_match_field_rejected` mirroring `test_l2_no_match_field_rejected` at `tests/test_config_validator.cpp:418-427` | **absent**. The same six-test files Phase 2a flagged still have zero coverage |
| Wrong-layer field drop (dst_port on L3, etc.) | Negative tests in `tests/test_config_validator.cpp` per cross-field combo | **absent**. No "field X in layer Y is rejected" pattern anywhere in the suite |
| `dst_ip` accepted by validator | A `test_l3_dst_ip_rejected` (or `test_l3_dst_ip_silently_ignored` — depends on chosen behaviour) | **absent**. The fact that dst_ip is a documented match-field in CONFIG.md but is never tested for validator-side behaviour is the single largest test-audit miss |
| Schema not wired in | A pre-commit / CI step that runs scenarios/*.json against `nlohmann/json-schema-validator` | **absent** — no scenarios are loaded by CI at all (Phase 1 §6) |
| Ethertype hex parser quirk | `test_l2_ethertype_invalid_hex_chars` exists but **asserts the bug** | **wrong test exists** — Phase 2c-style cement-the-defect pattern. Updated TEST_AUDIT.md entry below |
| No file-size guard | A test that fixtures a 100 MB JSON and asserts rejection | **absent** |
| dst_ip6 with `object6:` in non-L3 | An `object6:` ref in `layer_3.match.dst_ip6` test | **absent** |

**New TEST_AUDIT.md entry to add** (also for the consolidated tests-phase):

> ### [Phase 2i] P2 — `test_l2_ethertype_invalid_hex_chars` cements ethertype hex-parser quirk
>
> Where: `tests/test_config_validator.cpp:717-731`. Root cause: `config_model.hpp:131-142` calls `std::stoul(s, nullptr, 16)` which silently consumes only the `0x` prefix on a non-hex suffix and returns 0.
>
> Test gap class: **test exists, asserts the bug as contract** — parallel to `test_l2_qinq_not_parsed`. The test even self-flags the bug in its comment but asserts the buggy result. Second confirmed instance of this anti-pattern; promote to a project-level concern.

## Open issues / pickup for later phases

- (Tests phase) Six different tests in `tests/test_config_validator.cpp` exist that exercise L2 match-field counting (`test_l2_no_match_field_rejected`, three `_compound_…` tests, `_src_dst_mac_rejected`, etc.). Add the L3 equivalents.
- (Tests phase) The two "test cements the bug" patterns — `test_l2_qinq_not_parsed` (Phase 2c) and `test_l2_ethertype_invalid_hex_chars` (Phase 2i) — are not isolated incidents but a project-level test-culture issue.
- (Schema decision) Owner choice: wire in json-schema-validator or delete the schema. Either is fine for review purposes; the current state (documented contract, no enforcement) is what makes this a P1.
- (Fuzz phase) Extend `fuzz_config_parser.cpp` to also call `validate_config` and `compile_rules`. Add a max input-size bound. Build a negative corpus.
- (Tools phase, 2j) `tools/validate_config` runs both parse and validate — but because the validator doesn't catch CIDR/interface-name/wrong-layer issues, the tool gives false-green on configs that will fail at deploy. The tools-phase review (Phase 2j per `08_CHECKPOINT.md`) should flag this divergence.
