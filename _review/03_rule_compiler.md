# 03 — rule_compiler.cpp (Phase 2a)

## What this module does

`rule_compiler.cpp` is the second-to-last step of the deploy-time control plane: it takes a validated `config::Pipeline` (three `vector<Rule>` for L2/L3/L4) plus an `ObjectStore` (named MAC/subnet/port groups) and lowers each high-level rule into one or more byte-level `CompiledL2Rule / CompiledL3Rule / CompiledL3v6Rule / CompiledL4Rule` entries that `GenerationManager` then bulk-inserts into the per-generation BPF maps (`src/pipeline/generation_manager.cpp:135-175`). Per-layer maps are `BPF_MAP_TYPE_HASH` (L2 src_mac/dst_mac/ethertype/vlan/pcp, L4 proto+port, L3 VRF) plus two `BPF_MAP_TYPE_LPM_TRIE` (L3 v4/v6 subnet). Everything the data plane reads per packet is keyed by the structures this file produces.

Object-reference dereferencing (`object:foo`, `object6:foo`) is open-coded here — `object_compiler.cpp` only flattens them once for the standalone object maps, but rule compilation re-resolves group names against `ObjectStore`. Port groups, MAC groups, and CIDR aliases all expand here, so this is where one config rule fans out into N map entries. After expansion, the file runs five inline duplicate-key checks (one per map type) and returns either `CompiledRules` or a single error string via `std::expected`.

The module is on the deploy path, not the per-packet path. But every choice it makes (which field becomes the primary key, whether dst_ip is honoured, whether port-group expansion is capped, what action goes into the value record) determines the *shape* of map lookups the BPF programs perform per packet. Errors here are not latency hazards directly; they are silent semantic failures at line-rate.

## Per-question findings

### Q1 — empty-match `continue` at line 144

It's `continue` to the **next L2 rule** in the `for (auto& rule : pipeline.layer_2)` loop (line 119), which is the safe branch: such a rule is silently dropped. Confirmed by the loop opening at `rule_compiler.cpp:119` and the comment-flagged statement `continue; // no match fields — validator should have caught this`. The L2 validator does enforce `match_count == 0` rejection at `config_validator.cpp:47-48`, so for L2 this is a defensive-only path.

**However the L3 path has the same disease without any guard.** `rule_compiler.cpp:206-243` has *no* `continue` for the no-match case: after the v6 branch (line 219, with its own `continue`), the v4 branch (line 232), and the VRF branch (line 237), execution falls through to `result.l3_rules.push_back(cr)` at line 242 **unconditionally**. A rule with only `dst_ip` set, or with no L3 match fields at all, produces a `CompiledL3Rule{}` whose `subnet_key.prefixlen = 0` and `subnet_key.addr = 0`. That key is `0.0.0.0/0` in `subnet_rules_0/1` (LPM trie), which **matches every IPv4 packet** (LPM longest-prefix on a trie with a prefixlen-0 entry returns that entry as the catch-all). It is also `is_vrf_rule = false`, so the VRF path doesn't fire.

The validator confirms it doesn't catch this: `config_validator.cpp:82-111` (`validate_l3_rules`) has zero "must have a match field" check — it only validates objects that *are* present. So an L3 rule with only `dst_ip` set passes validation, is compiled, gets pushed as a `0.0.0.0/0` LPM entry that the data plane interprets as "match any IPv4 packet → apply this rule's action".

**Escalation.** This is qualitatively worse than the dst_ip P0 already filed in `02_architecture.md §7`. The Phase 1 P0 said "dst_ip silently does nothing"; the truth is **dst_ip silently turns the rule into a catch-all that applies its action to every IPv4 packet**. Concrete failure: an operator writes `{"match":{"dst_ip":"10.0.0.0/8"},"action":"drop"}` expecting "drop traffic to 10.0.0.0/8" → instead the data plane drops every IPv4 packet on the wire as soon as that rule's `0.0.0.0/0` LPM entry is hit. Same fate for an L3 rule that mistakenly has no match fields at all. Add `dst_ip6` only → same: silently treated as a no-match v6 rule and falls through to `result.l3_rules.push_back(cr)` (also wrong; the v6 branch is gated only on `src_ip6` at line 219). This makes the existing P0 even more severe.

### Q2 — dst_ip / dst_ip6 trace

Confirmed. Counting `if (rule.match.<field>)` branches inside L3 compilation (`rule_compiler.cpp:206-243`):

| Field | Branch present | Effect |
|-------|----------------|--------|
| `src_ip6` | yes, line 219 | LPM v6 entry |
| `src_ip`  | yes, line 232 | LPM v4 entry |
| `vrf`     | yes, line 237 | VRF hash entry |
| `dst_ip`  | **absent** | Field read into model (`config_parser.cpp:32`), then dropped |
| `dst_ip6` | **absent** | Same |

Three branches that read the model, two documented match fields that the compiler never references. This matches the Phase 1 P0 finding (`02_architecture.md §7`), with the worsening from Q1 above.

### Q3 — L2 compound-rule primary-key selection

The choice is **hard-coded by lexical order**, not by selectivity. `rule_compiler.cpp:130-144` is a fixed if/else chain: `src_mac → dst_mac → vlan_id → ethertype → pcp`. The comment at line 131 even labels it "Determine primary field by selectivity" — but selectivity here is the author's *assumption* about which field is more selective, not a property of the operator's actual config. A rule `{"src_mac":"object:hot_thousand_macs","vlan_id":1}` puts src_mac on the primary path (1000 hash entries) even though the vlan filter cuts the candidate set to a single VLAN. A rule `{"ethertype":"IPv4","vlan_id":42}` makes ethertype primary (one entry in `l2_ethertype_*`, value 0x0800) — meaning **every IPv4 packet** does a hash hit, then has to fall through the `filter_mask` check at `bpf/layer2.bpf.c` to verify VLAN.

For the cross-cutting latency theme: the choice doesn't change the *number* of map lookups (always exactly one primary hash + zero secondary lookups; secondary checks are register compares on fields the entry program already parsed into `pkt_meta`). It does change the **hash hit rate on the hot map**. Putting ethertype primary on every rule that mentions IPv4 means `l2_ethertype_0/1` becomes a degenerate two-entry map (IPv4, IPv6) carrying enormous per-packet pressure; one entry per rule_id colliding into the same hash bucket via last-write-wins inside the BPF map is impossible because the compiler also runs duplicate-detection (`rule_compiler.cpp:337-344`) and rejects two rules with the same ethertype. **Net effect: the validator/compiler combo silently enforces "at most one rule per ethertype" / "at most one rule per VLAN" / "at most one rule per PCP" simply because they're hard-wired as primary by lexical order.** An operator writing two distinct compound rules `{ethertype:IPv4, vlan_id:10}` and `{ethertype:IPv4, vlan_id:20}` will see the second rule rejected with `L2 ethertype key collision` (line 341), forcing them to rewrite using `vlan_id` as primary instead — but only because PCP/ethertype/vlan_id appear in selectivity order *after* the MACs, so the only escape is to add a MAC. This is a usability footgun, not just a perf hint.

### Q4 — Port-group expansion

`resolve_object_ports` (`rule_compiler.cpp:80-94`) returns whatever vector the `ObjectStore` carries — it does not expand a range syntax. Going to `config_parser.cpp` and the validator: port groups are flat `std::vector<uint16_t>` (`config_model.hpp:25`), so any range expansion happens *before* this module, in the parser/object compiler. (Grep confirms no range expansion code in this file.) The compiler does loop over the resolved port list at lines 254-262, emitting one `CompiledL4Rule` per port.

**No cap is enforced.** `MAX_PORT_ENTRIES = 4096` (`bpf/common.h:24`) is the BPF map ceiling, but `rule_compiler.cpp` never compares `result.l4_rules.size()` against it. If the resolved port-group expansion (or the union of all L4 rules × ports) exceeds 4096, the compiler returns success and `GenerationManager::populate_l4_map` will hit `update_elem` failures with E2BIG once the map fills, returning a generic `"l4_rules insert (rule …): …"` error mid-batch. The shadow map ends up partially populated, the commit doesn't happen (PipelineBuilder returns the error), the next reload's `clear_shadow_maps` cleans it. So overflow is detected, but **not at compile time** and not with a clear "too many ports / rules" message. Same story for L2 (`MAX_MAC_ENTRIES = 4096`, `MAX_VLAN_ENTRIES = 4096`, `MAX_PCP_ENTRIES = 8`, `MAX_ETHERTYPE_ENTRIES = 64`) and L3 (`MAX_SUBNET_ENTRIES = 16384`) — no compile-time cap anywhere in this file.

`MAX_PCP_ENTRIES = 8` is interesting: there are only 8 possible PCP values, the cap is exact. Combined with the per-pcp duplicate check at line 356-362 the system is implicitly limited to 8 distinct PCP-primary rules.

Latency relevance: hash-bucket collision rate is determined by map size and load factor. Without compile-time enforcement, the operator can submit a config that compiles but fails at deploy time; not a per-packet hazard since deploy-time failures don't affect the active generation. But the friendliest place to catch this is here.

### Q5 — Collision detection

Algorithm: five separate `std::unordered_map<key, rule_id>` passes (L2-by-type, L4 by (proto,port), L3-IPv4 by 64-bit packed prefixlen|addr, L3-IPv6 by raw 20-byte string of `lpm_v6_key`, L3-VRF by ifindex). All linear in the compiled-rule count: **O(n)** with amortised O(1) hash inserts, *not* O(n²) as flagged in recon (`01_recon.md`'s "O(n²) collision checks"). Recon was wrong on this point.

For "hundreds to low thousands of rules" sizing, this is invisible on deploy time — a single `unordered_map` insert pass over ~10k entries runs in well under a millisecond. The recon finding can be downgraded.

One nit: the L3-IPv6 hash uses `std::string` constructed from raw bytes of `lpm_v6_key` (`rule_compiler.cpp:410-411`). This pulls 20 bytes through `std::string`'s small-string-optimisation path and heap-allocates if SSO is exceeded (typical libstdc++ SSO is 15 bytes; 20 > 15 so this allocates). For pure deploy-time code this is fine, but a `struct lpm_v6_key`-keyed `unordered_map` with a custom hash would be cheaper.

### Q6 — Endianness handling

| Field | Source (host/network) | Conversion at compile time | Stored | Verdict |
|-------|----------------------|---------------------------|--------|---------|
| `filter_ethertype` (l2_rule member) | parser produces host via `parse_ethertype` | `htons()` at `rule_compiler.cpp:150` | NBO | OK |
| Primary `ethertype_key.ethertype` | parser produces host | `htons()` at line 185 | NBO | OK (matches comment `bpf/common.h:89`) |
| `vlan_key.vlan_id` | parser u16 | none (line 191) | host | OK (matches comment `bpf/common.h:95`) |
| `filter_vlan_id` (l2_rule member) | parser u16 | none (line 154) | host | OK |
| `pcp_key.pcp` | parser u8 | none, widened to u32 | host (single byte) | OK |
| `port_key.port` / `l4_match_key.dst_port` | parser int | none (lines 265) | host | OK (matches `bpf/common.h:138`) |
| `lpm_v4_key.addr` | `Ipv4Prefix::addr_nbo()` (`util/net_types.hpp:68`) | conversion in net_types | NBO | OK (matches `bpf/common.h:57`) |
| `lpm_v6_key.addr` | `Ipv6Prefix::parse` returns raw 16-byte order from `inet_pton` | `std::memcpy` at line 227 | NBO | OK (matches `bpf/common.h:68`) |

No endianness bugs in this file. The pattern is "host order in keys whose comments say host order, NBO in keys whose comments say NBO, with `htons` exactly where conversion happens". Consistent with `bpf/layer{2,3,4}.bpf.c`'s read side as captured in `02_architecture.md §3`.

### Q7 — Cross-layer rules

Yes, supported. The flow:

- L2 → L3/L4: every L2 rule carries a `next_layer` field (`config_model.hpp:71`). `next_layer_to_idx` (`rule_compiler.cpp:72-77`) translates `"layer_3"` / `"layer_4"` to the `LAYER_3_IDX / LAYER_4_IDX` constant which is written into `l2_rule.next_layer` (line 123). The L2 BPF program tail-calls based on this byte (per `02_architecture.md §3.2`).
- L3 → L4: every L3 rule carries `has_next_layer` derived from `rule.next_layer.has_value() ? 1 : 0` at line 210. The L3 BPF program tail-calls L4 if set.

But — **a single rule does not span layers.** "Cross-layer" here means a *pipeline* of distinct rules, not one rule with both an L3 match and an L4 match. The model itself supports `src_ip + dst_port` on the same `MatchCriteria` struct (`config_model.hpp:36,42`), and the parser populates both, but the compiler routes by **which layer's vector the rule is in** (`pipeline.layer_2 / .layer_3 / .layer_4`). A rule placed in `pipeline.layer_3` with `dst_port` set has its `dst_port` field silently dropped — no compiler branch reads `dst_port` inside the L3 loop. Same pattern as the dst_ip bug. (The L4 loop similarly ignores `src_ip`, `vlan_id`, etc.) The "next_layer" mechanism is the only way to chain matches: write L3 rule that matches src_ip with `next_layer:"layer_4"`, then write the L4 rule(s) the operator wants L3-passed packets to go through.

This is not necessarily a bug — it's a coherent design — but it is **undocumented**: nothing in `config_model` or `config_validator.cpp` warns the operator that `dst_port` on an L3 rule is ignored. Add to the dst_ip P0 with a "and also: cross-field matches on the *wrong* layer are silently dropped".

### Q8 — Default action

**Not handled in rule_compiler.cpp at all.** Default action lives in `cfg.default_behavior` (`config_model.hpp:89`, top-level Config), and is passed straight from `PipelineBuilder::deploy` (`pipeline_builder.cpp:63`) to `GenerationManager::prepare(..., cfg.default_behavior)`. `GenerationManager::set_default_action` (`generation_manager.cpp:212-226`) writes a single `u32` into `default_action_0/1` (`bpf/maps.h:184-196`).

So defaults are **global**, not per-layer. The same value is read by `layer4.bpf.c:82-88` and (per Phase 1 grep) by `layer3.bpf.c:30-36`. This is consistent across the codebase and not a compiler concern. **One observation**: per `02_architecture.md §2`, `layer3.bpf.c` increments both `STAT_PASS_L3` and the action's own counter on the default path. That's a BPF-side issue, out of scope for this phase.

## Additional findings

1. **Per-CPU rate divisor is over-pessimistic.** `rule_compiler.cpp:286-291` divides `total_bps` by `libbpf_num_possible_cpus()` to set per-CPU rate. `num_possible_cpus` is "every CPU the kernel was built with", typically larger than online CPUs and orders larger than the RSS-active set on a real NIC (8-32 queues). On a 256-possible-CPU kernel running an 8-queue NIC, a "10 Gbps" rate-limit produces a per-CPU bucket of ~39 Mbps that only fires on 8 CPUs → effective ceiling ~312 Mbps. This is a quantitative correctness bug with a userspace fix.
2. **`cr.rule.cos` is written but never read on the data plane** for L4 (per Phase 1 finding §7 P0). The compiler diligently sets `cr.rule.cos = *rule.params.cos` (line 274); the TC ingress program ignores it. Compiler side is correct; downstream is the gap.
3. **Object-name re-resolution at compile time** (`rule_compiler.cpp:80-94` and `:55-69`) is by design but means an unknown object reference in a rule raises a generic `std::invalid_argument` that gets translated to a single "Rule compilation error: …" string at the catch (line 303-305). The validator should catch unknown refs (`config_validator.cpp:7-17` does for `mac_groups` and `subnets`) but the validator's `check_object_ref` only handles object-store *kind* "subnet" / "mac_group" / "port_group" — there is **no** validator check for `object6:` references inside `r.match.src_ip6` other than the bespoke block at `config_validator.cpp:93-100`. Unknown `object6:` in any rule that bypasses that path (e.g., placed in `pipeline.layer_2`) would reach the compiler. Minor.
4. **`emit_entry` lambda is called only with `primary`** (`rule_compiler.cpp:202`). The dead-code-ish pattern (a lambda that switches on `type` only to be called with one argument) is fine but signals the original design likely intended to emit multiple primary entries; the current single-primary-with-secondary-mask design renders the switch redundant. Cosmetic.
5. **L4 ports are not deduplicated across rules within the same protocol**, only checked for collision. So a rule using a port-group `{80, 443, 8080}` and a separate rule using port `80` will collide on (TCP, 80) and the second rule will be rejected. This is desired strict behaviour; just worth noting because port-groups make accidental collisions more likely. The error message names the first claimant but doesn't show which port group it came from (line 376-381) — the operator gets `"L4 key collision: TCP:80 claimed by rule 42 and rule 17"` and has to manually expand groups to debug.
6. **`compile_rules` has no upper bound on `try` block coverage**: any `std::exception` becomes one generic "Rule compilation error: <what>" message (line 303-305). The catch block discards which rule failed (no `rule_id` context in the message), unlike the L4 missing-protocol path (line 248-249) which names the rule. For deploy-time debuggability this is a P2 ergonomics gap.
7. **Empty `pipeline.layer_2 / layer_3 / layer_4` is valid.** `compile_rules` always succeeds on `Pipeline{}`; the only checks are the L4 protocol/dst_port asserts that fire only on present rules. Combined with `default_action` global, an "all-default" deploy works. Confirmed acceptable design.

## Latency impact summary

| Compiler choice | Per-packet cost on data plane |
|-----------------|-------------------------------|
| L2 primary by lexical order, not selectivity | One primary hash lookup (~25 ns) regardless of choice; secondary checks are register compares on already-parsed metadata, ~0 ns. So latency-neutral, but **hash-bucket pressure** shifts to whichever field is primary — a config that puts thousands of MAC entries on src_mac fans the hash; one that puts ethertype primary degenerates the ethertype map. Hot/cold cache behaviour shifts accordingly. |
| One CompiledL4Rule per port (group expansion) | One hash lookup per packet on (proto, dst_port). Cost is independent of how many rules the operator wrote because expansion happens at compile time. Good. |
| dst_ip silently becomes `0.0.0.0/0` LPM | **Catastrophic.** One LPM lookup yields a wildcard match → the rule's action applies to every IPv4 packet. Not a latency cost, a correctness disaster, but it is *also* a perf cost: the trie's prefixlen-0 entry adds one mandatory step to every LPM traversal that doesn't hit a more specific prefix. |
| dscp / cos / rate stored in `l4_rule` value | Action-specific fields are inlined in the rule value, so a single L4 hash hit returns everything needed. No extra lookup. Correct shape. |
| `is_vrf_rule` split into two physical maps (subnet LPM vs VRF hash) | L3 BPF program does one LPM lookup, falls back to one VRF hash lookup on miss → up to two map lookups per packet. Consistent with `02_architecture.md §3.3`. |
| TCP-flag mask stored in l4_rule | Free: read inline from the L4 hash hit, compared in registers. |
| Per-CPU rate divisor / `libbpf_num_possible_cpus` | Affects aggregate accuracy, not per-packet latency. Per-packet cost is one PERCPU_HASH lookup (~30 ns) regardless. |

The big-picture answer to the cross-cutting concern: this module's output already commits the pipeline to **at most one map lookup per layer per packet** (L2 primary + optional secondary register-compare; L3 LPM with fallback to VRF hash; L4 hash + optional inline rate/tcp-flag work). No compiler decision pushes work into the data plane that could be done at deploy time, **except** the lexical-order primary selection above. The compiler is good at the latency contract; it is bad at the correctness contract.

## Findings (graded)

```
- [P0 — ESCALATION] L3 rule with no recognised match field becomes a wildcard 0.0.0.0/0 LPM entry
  Where: src/compiler/rule_compiler.cpp:206-243 (no else for missing src_ip / src_ip6 / vrf);
         src/config/config_validator.cpp:82-111 (no "must have a match" check for L3)
  What: Falling out of all three branches with a default-constructed CompiledL3Rule pushes a
        prefixlen-0 / addr-0 LPM entry. In an LPM trie, that key matches every IPv4 packet.
        Triggers when an operator writes only dst_ip, or only dst_ip6 (the v6 branch is gated
        on src_ip6 alone — a dst_ip6-only rule falls through to result.l3_rules.push_back),
        or writes a malformed L3 rule with no fields at all.
  Why it matters: The Phase 1 dst_ip P0 (02_architecture.md §7) said "dst_ip silently does
        nothing". The truth is worse: dst_ip silently turns the rule into a catch-all that
        applies the rule's action to ALL IPv4 traffic. A `{match:{dst_ip:"10/8"}, action:drop}`
        drops everything. On a Gi-side filter this is one config typo away from outage.
  Suggested action: In rule_compiler.cpp:242, replace the unconditional push_back with
        `if (!cr.is_vrf_rule && cr.subnet_key.prefixlen == 0 && cr.subnet_key.addr == 0)
         throw std::invalid_argument("L3 rule "+id+" has no recognised match field");`
        Better: add a layer-3 "match_count == 0" guard in config_validator.cpp mirroring the
        L2 one at line 47. Same for dst_ip6 in the v6 path. Document that dst_ip/dst_ip6 are
        unsupported until proper dst-LPM tries are added.

- [P1] L2 compound rules: primary key chosen by lexical order, not config-level selectivity
  Where: src/compiler/rule_compiler.cpp:130-144
  What: Hard-coded src_mac > dst_mac > vlan_id > ethertype > pcp. An operator who writes
        two compound rules sharing the lexically-first field (e.g. two rules both starting
        with the same src_mac) gets the second one rejected as a collision; the only
        workaround is to manually pick a less-selective field as primary by writing the
        rule with that field as the only "primary candidate". Worst, two rules with shared
        ethertype but different VLANs cannot coexist unless the operator adds a dummy MAC.
  Why it matters: silent usability footgun; operator can't combine compound rules naturally.
  Suggested action: Either (a) per-rule "primary_match" hint in config and the compiler
        respects it, or (b) compute selectivity from the ObjectStore (mac_group size, port-
        group size) and pick least-cardinality primary.

- [P1] No compile-time enforcement of per-map size limits (4096 / 16384 / 8 / 64)
  Where: src/compiler/rule_compiler.cpp (entire); compared against bpf/common.h:21-29
  What: Compiler returns success even when the compiled output overflows MAX_PORT_ENTRIES,
        MAX_MAC_ENTRIES, MAX_SUBNET_ENTRIES, MAX_VLAN_ENTRIES, MAX_ETHERTYPE_ENTRIES,
        MAX_PCP_ENTRIES. Overflow is detected only when generation_manager.cpp calls
        update_elem and the kernel returns E2BIG. Error message names the failing rule but
        not "size limit hit" — operator gets generic "subnet_rules insert (rule N): EINVAL"
        or similar. Shadow map ends partially populated; clean-up happens on next reload.
  Why it matters: poor deploy-time diagnostics; a deploy that fails halfway leaves the next
        reload to clean up. Not a per-packet hazard.
  Suggested action: Reject up front with a clear message: "L4 compiled to N rules, max M".

- [P1] Per-rule rate-limit divisor uses libbpf_num_possible_cpus, not online/RSS-active CPUs
  Where: src/compiler/rule_compiler.cpp:286-291
  What: Divides total_bps by num_possible_cpus. On any kernel where NR_CPUS exceeds online
        CPU count (default Fedora/Ubuntu: NR_CPUS=8192) the per-CPU bucket is sized for a
        machine 1000× bigger than reality. Operator-configured 10 Gbps becomes effective
        ~40 Mbps with the rest of the budget on never-existing CPUs.
  Why it matters: rate-limit accuracy is already documented as "approximate" but this is
        not "approximate" — it's "wrong by 2-3 orders of magnitude on a stock kernel".
  Suggested action: Use libbpf_num_online_cpus or read /sys/devices/system/cpu/online.
        Better: read the NIC's active RX-queue count, since rate fires on RSS-distributed
        CPUs.

- [P2] Generic catch swallows per-rule context for non-L4 errors
  Where: src/compiler/rule_compiler.cpp:303-305
  What: catch (const std::exception& e) returns "Rule compilation error: <what>". The
        try block covers all three loops; an L2 or L3 unknown-object-reference exception
        loses the rule_id. L4 has explicit rule_id messages, L2/L3 don't.
  Suggested action: Wrap each rule iteration in a try, prefix the message with rule_id.

- [P2] Recon's "O(n²) collision check" finding is refuted
  Where: src/compiler/rule_compiler.cpp:307-436
  What: Five linear unordered_map passes, O(n) total. The recon flag is wrong; nothing to
        fix here, but the 99_REPORT should not carry the O(n²) item.
  Suggested action: Drop the item from the to-fix list when consolidating.

- [P2] L3-IPv6 collision check builds a 20-byte std::string per entry
  Where: src/compiler/rule_compiler.cpp:408-412
  What: 20 > libstdc++ SSO (15), so each insert heap-allocates. Deploy-time only, harmless
        for realistic rule counts but cheaper with a struct-keyed map.
  Suggested action: Use a pair<uint32_t, std::array<uint8_t,16>> key or a custom hash on
        lpm_v6_key directly.

- [P2] Cross-field matches placed in the wrong layer's vector are silently dropped
  Where: src/compiler/rule_compiler.cpp (entire) — no read of "wrong-layer" fields
  What: A rule placed in pipeline.layer_3 with dst_port set has dst_port ignored; same for
        src_mac on an L3 rule, vlan_id on an L4 rule, etc. Each layer's compile loop reads
        only the fields it cares about.
  Why it matters: layered on top of the L3 dst_ip P0, the operator's mental model of "I
        wrote a match, it'll match" diverges silently from reality.
  Suggested action: Validator should reject any layer-N rule that has fields the layer-N
        compiler doesn't read.
```

## Open issues for later phases

- **BPF-side LPM trie behaviour with prefixlen=0** — confirm in Phase 2b/c (`bpf/layer3.bpf.c`) that a `subnet_rules_*` entry with `prefixlen=0, addr=0` actually wins for arbitrary IPv4 saddrs (expected: yes, LPM trie semantics). This is the data-plane half of the P0 above.
- **Rate-limit per-CPU bucket initialisation** — line 286-291 sets `cr.rule.rate_bps` to a per-CPU share; `bpf/layer4.bpf.c:27-32` initialises the bucket on first hit with `rule->rate_bps / 8`. Phase 2d should verify the token-bucket math against the divisor choice, since divisor change here is half the rate-limit accuracy fix.
- **Validator coverage of `object6:` references** — `config_validator.cpp:93-100` only checks `src_ip6` and only inside `validate_l3_rules`. If a rule with `src_ip6: object6:foo` is placed in `pipeline.layer_2`, the compiler will hit `resolve_object_subnet6` and throw. Phase 2 of the validator review should add the layer-agnostic check.
- **`tools/validate_config`** — is it just `validate_config()` or does it also exercise `compile_rules`? If the latter, the dst_ip / wildcard-LPM bug would surface via the tool (operator could see it). If the former, the tool gives a false green for the bug. (Out of scope for Phase 2a; tag for the tools phase.)
- **Per-CPU rate `BPF_ANY` race** — already flagged in Phase 1 §8; compile-time choice of divisor doesn't change this but worth keeping linked.
