# 14 — Cross-cutting (Phase 3)

Holistic review of patterns and system-level properties that don't belong to any single Phase-2 module. Five topics. Findings new to this phase are graded at the end; Phase-2 findings are cited, not re-derived.

Source artifacts read directly for this phase: `systemd/pktgate.service`, `CMakeLists.txt`, `rpm/pktgate.spec`, `build/compile_commands.json`, `scripts/install.sh`, `.github/workflows/{ci,fuzz}.yml`, `src/metrics/prometheus_exporter.hpp`, `src/util/log.hpp`, `src/util/net_types.hpp`, `bpf/common.h`, `bpf/maps.h`, `bpf/layer{3,4}.bpf.c`, `bpf/tc_ingress.bpf.c`, `functional_tests/test_l3_ipv6.py`.

---

## 1. IPv6 as a class

### Root pattern

Three IPv6-specific defects across three different files, all instances of the same root error: **IPv4 logic is the source of truth, IPv6 is added as a second arm with shallow extension-header handling and no IP-family gate on the action paths**. Concretely:

- `bpf/layer3.bpf.c:198` — `if (ip6h->nexthdr == 44)` covers Fragment only when it is the **immediate** next header. Hop-by-Hop or Destination-Option preceding a Fragment hides the Fragment from L3; if the L3 rule is terminal-ALLOW (`has_next_layer=0`), L4's defensive Fragment drop at `layer4.bpf.c:175` never runs and the fragmented packet passes (P1, `04_layer3.md §7`).
- `bpf/layer4.bpf.c:154` — `#pragma unroll for (int i = 0; i < 4; i++)` only walks four extension headers. A chain of five HBH/DestOpt headers leaves `nhdr` as an ext-header value (0/43/60), the `if (proto == 6) ... else if (proto == 17)` arms don't match, and the program falls into `get_default_action(m)` — every configured L4 rule and the rate-limit are bypassed (P0 SECURITY, `05_layer4.md §7`).
- `bpf/tc_ingress.bpf.c` — DSCP rewrite hard-codes IPv4 byte offsets (`14+10` for the IP-header checksum word, byte 15 for ToS). `bpf/layer4.bpf.c:260-262` sets `ACT_TAG` unconditionally on any matching tag-action rule, no family check. An IPv6 packet hitting a tag rule gets its IPv6 source-address byte overwritten by `bpf_l3_csum_replace` (P0, `09_tc_ingress.md`).

The pattern is uniform: an `eth_proto == 0x86DD` arm is added to the existing IPv4 code, but cross-cutting helpers (the L4 ext-header walker, the TC DSCP rewriter) are not parameterised on family. No code in `bpf/*.c` checks `AF_INET vs AF_INET6` or `pkt_meta.l3_family` at the action-execution site. There is no `pkt_meta` family bit at all (`bpf/common.h:155-176`).

### Other unaudited IPv6 sites

A sweep of files **not** drilled in Phase 2 for IPv6-specific gaps:

- `bpf/maps.h:132-148` — `subnet6_rules_{0,1}` LPM tries exist and are sized identically to v4 (`MAX_SUBNET_ENTRIES`), which is correct. No v6-side issues found in map shape itself.
- `bpf/common.h:155-176` — `pkt_meta` carries `dscp`, `cos`, `action_flags`, `rule_id`, `generation`, but **no IP family bit**. Adding one is the cheapest enabler for an IP-family gate at TC ingress.
- `src/util/net_types.hpp:97-123` — `Ipv6Prefix::parse` is correct (uses `inet_pton(AF_INET6)`, prefix-len bound at 128). One small gap: no rejection of zone identifiers (`fe80::1%eth0`) — `inet_pton` will fail on these but the operator-facing error just says "Invalid IPv6 address", not "scope IDs unsupported".
- `src/config/config_validator.cpp:90-100` — validates `src_ip` against `objects.subnets` and `src_ip6` against `objects.subnets6` in separate branches. No cross-stack check: an L3 rule combining `src_ip` + `src_ip6` is accepted as two independent constraints rather than rejected as nonsensical (one packet cannot be both families). Promotes silently to "match either" semantics in the compiler. Minor — typical user error caught by the wrong-layer-fields P0 if dst_ip is involved, but pure-v4/v6 mixing slips through.
- `src/compiler/rule_compiler.cpp:219-235` — v4 path at line 219, v6 path at line 232 (`rule.match.src_ip6` → `subnet6_rules` LPM key). Sibling paths, but **no shared helper** — adding a `dst_ip` later would need two parallel additions. The compiler's structural fragility on family is itself an instance of the pattern.

### Structural fix

Three actions in priority order:

1. **Plumb an IP family bit through `pkt_meta`** (one bit in `action_flags` or a dedicated `l3_family` byte). L3 sets it on every path; L4 ext-header walk and TC DSCP rewrite gate on it. This is the cheapest fix that eliminates the entire class of "IPv4 byte offsets applied to IPv6" bugs.
2. **Replace the unrolled `for (i<4)` with a fixed-cost loop bounded by header byte length**. The verifier allows depth-bounded loops up to 8; even depth-bounded 8 doesn't fully solve the problem (an adversary can craft 9), so the correct semantic is: if the walk exits without finding a transport, **drop** with a dedicated counter (`STAT_DROP_L4_V6_EXT_DEPTH`), don't fall back to `get_default_action`. Failing-closed at the bound is the security-correct posture for an ext-header walk.
3. **A `BPF_V4_V6_DISPATCH(stmt_v4, stmt_v6)` macro** that wraps every site where v4 and v6 logic must coexist. Forces the next contributor to declare both arms at the call site. Stretch goal: a clang-tidy lint over the BPF tree that flags `0x0800` / `0x86DD` literals not inside the macro.

### Test coverage assessment

`functional_tests/test_l3_ipv6.py` has 10 tests in 3 classes: `TestIPv6FragmentDrop` (3 happy-path drops on immediate Fragment header), `TestIPv6ExtensionHeaders` (6 tests with **at most 2** ext headers, all happy-path PASS or single-port DROP), `TestIPv6FragmentAfterExtHeaders` (1 test with HopByHop+Fragment+TCP, asserts DROP **at L4** — happens to pass because the L3 rule isn't terminal in the test's config).

What's missing:
- No test that varies ext-header chain depth across 1, 4, 5, 8 — the depth-4 cliff in `layer4.bpf.c:154` is invisible.
- No test combining HopByHop→Fragment with an **L3-terminal ALLOW** rule (the exact Phase-2b condition).
- Zero tests for IPv6 + `tag` action (would surface the source-address corruption immediately).
- Zero tests for IPv6 + `mirror`, IPv6 + `redirect`, IPv6 + `rate-limit` — every cross-action × IPv6 cell of the matrix is empty.

The shape is "happy-path coverage of the IPv6 documented path", which is exactly the meta-pattern the test audit has named.

### Cross-cutting finding for IPv6

→ **P0 NEW (cross-cutting): IPv6 is the project's weakest dimension; audit and refactor as a class.** Three IPv6-specific bugs across three files share one root cause (no IP-family gate at action sites), are not caught by any test (test_l3_ipv6.py covers only happy paths), and exemplify a design hazard rather than three independent bugs. Treat the IPv6 surface as a single hardening phase rather than three individual fixes.

---

## 2. Security

### Capability surface — systemd unit (`systemd/pktgate.service`)

Read directly. The unit is **better than the recon notes suggested**: it grants four capabilities, not two:

```
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_PERFMON
```

Hardening directives **present**: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelModules=yes`, `ProtectKernelTunables=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `RestrictSUIDSGID=yes`, `RestrictRealtime=yes`, `RestrictNamespaces=yes`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=yes`, `LimitMEMLOCK=unlimited`.

Hardening directives **missing**:
- `NoNewPrivileges=no` — explicitly set to `no` with a comment claiming "AmbientCapabilities require privilege transition". This is **wrong**: AmbientCapabilities work with `NoNewPrivileges=yes` (the kernel only refuses caps on a SUID boundary). Setting `NoNewPrivileges=no` allows the daemon's children (e.g., a shell spawned by `system()`) to gain capabilities via SUID. The daemon doesn't call `system()` today, but the comment cements a misunderstanding that will defeat the next reviewer.
- `SystemCallFilter=` — entirely absent. CAP_SYS_ADMIN + no seccomp filter = nearly full kernel surface. A seccomp filter restricting to BPF, network, file I/O, and signal syscalls would meaningfully reduce post-exploit blast radius.
- `RestrictAddressFamilies=` — absent. Daemon needs AF_NETLINK, AF_INET, AF_INET6, AF_UNIX. Restricting would cut AF_PACKET, AF_RDS, AF_VSOCK, etc.
- `CAP_SYS_ADMIN` is over-granted. `CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON` is the documented minimum for XDP+TC on kernels ≥5.8. CAP_SYS_ADMIN is the kernel-wide "root" capability and includes mount, reboot, namespace ops, etc.; it's the single most attacker-valuable capability on the system. Likely a "copy from old example, never trimmed" artefact.
- `ReadWritePaths=/sys/fs/bpf` is correct, but `/etc/pktgate/` (the config dir watched by inotify) is **not** declared `ReadOnlyPaths`. With `ProtectSystem=strict`, `/etc` is read-only — fine — but it'd be more explicit to declare the contract.

### Supply chain

- `CMakeLists.txt:20` — `find_package(nlohmann_json 3.11 REQUIRED)`: lower bound only. No upper bound. nlohmann_json 3.12 (released after 3.11) is accepted; new ABI is the user's problem.
- `CMakeLists.txt:19` — `pkg_check_modules(LIBBPF REQUIRED libbpf)`: no version pin at all. Any libbpf, including 0.x, will satisfy `REQUIRED libbpf`. The RPM spec (`rpm/pktgate.spec:16,25`) requires `libbpf >= 1.1`, but the CMake build accepts older. Mismatch: install via RPM matches recon notes; build from source on Ubuntu 22.04 (libbpf 0.5) might silently compile.
- `CMakeLists.txt:23` — `find_program(CLANG NAMES clang-16 clang-17 clang-18 clang REQUIRED)`: prefers clang-16…18. CI uses clang-18 (`.github/workflows/ci.yml:35`) and clang-19 for fuzz (`fuzz.yml:33`). No upper bound check; future clang-20+ that changes BPF target behaviour would not be flagged.
- **No checksum / lockfile mechanism** for either dependency. `libbpf` and `nlohmann_json` are taken from the distro / system; reproducibility depends on the distro.
- **No CVE scan** anywhere in CI. `libbpf <1.1` had CVE-2022-3534 (heap OOB on malformed BTF). The lower-bound floor is appropriate but unenforced for the CMake path.

### Input boundary

- Config parser reads attacker-influenced JSON via inotify + SIGHUP. Phase 2i filed **no file-size guard** as P1 (`12_config_parser_validator.md`). A malicious /etc/pktgate writer (root, but: SELinux/AppArmor-confined account, or sidecar container with bind-mount) can produce a multi-gigabyte JSON; nlohmann's reader walks the whole file before the validator gets a chance.
- `config-schema.json` exists at repo root but isn't wired into the validator (P1, Phase 2i). It is documentation-only.
- The full wrong-layer-fields P0 (Phase 2i) is itself an input-boundary failure: the trust boundary is the validator, and it lets through configs that compile to silent semantic catastrophe.
- The dst_ip P0 (Phase 2a/2b) is the same class.

### Privilege escalation paths

The threat model where an attacker has **write access to `/etc/pktgate/config.json`** is realistic:
- Misconfigured Ansible / Saltstack: pktgate config dir owned by a deployment account, not root.
- Bind-mount from a less-privileged sidecar (rare on bare-metal Gi, but the project's "deploy as container" path isn't ruled out).
- Local privilege bug elsewhere on the host: an unrelated CVE that gives shell as a non-root user with `/etc/pktgate` ACL.

With write access, an attacker can:
1. **Drop all traffic**: write the dst_ip P0 wildcard config, traffic goes dark (DoS the Gi filter).
2. **Mirror to attacker-controlled interface**: add an L3 mirror rule with `target_port` pointing at a packet-capture interface. Full Gi traffic exfiltration; no rate limit on mirror; PII / IMSI / HTTP payloads all clone-redirected.
3. **Bypass legitimate deny rules** by writing a permissive default action.
4. **DoS the daemon** via the unbounded-file-size P1 → OOM on next inotify event.

Mitigation: `install.sh:36-39` installs the sample config as `mode 0644` owned by root, which is correct. There is **no SELinux policy** in the repo (`grep -r selinux` / `apparmor` / `*.te` returns nothing). The recommended posture is an SELinux/AppArmor profile that restricts `/etc/pktgate/*.json` writes to `root` with a labeled context.

### Capture-side privacy

Mirror via `bpf_clone_redirect` is **full-frame**: every byte of every matched packet duplicated to `mirror_ifindex`. On a Gi link:
- Subscriber HTTP requests with cookies, Authorization headers, URLs
- IMSI/IMEI in SIP headers (VoLTE)
- Unencrypted DNS queries
- Source/dest IPs (always)

are forwarded in clear. No rate limit, no truncation, no IP-anonymisation, no opt-in per subscriber tier, no lawful-intercept boundary. There is **no `--max-mirror-bytes`** truncation flag in `tc_ingress.bpf.c` (a `bpf_skb_change_tail` would cap to L4 headers only). On Gi this raises lawful-intercept compliance and operator-of-record privacy questions; `02_architecture.md §4` already flagged this and owner notes deferred it. Worth re-stating as a P1 in the consolidated report because the customer brief explicitly names this link.

---

## 3. Performance envelope (consolidated)

### End-to-end latency table

Six representative paths, derived from `08_CHECKPOINT.md`'s per-layer table. Values are 50th-percentile estimates on x86_64, native XDP, cache-warm, single core.

| # | Path | entry | L2 | L3 | L4 | TC | Total (ns) | 1 core (Mpps) |
|---|------|-------|----|----|----|----|-----------:|--------------:|
| 1 | Untagged TCP ALLOW (rule on src_mac match → L3 rule-hit ALLOW → L4 rule-hit ALLOW) | 50 | 50 | 65 | 50 | — | **215** | 4.65 |
| 2 | Untagged TCP, rate-limited (L4 token-bucket pass) | 50 | 50 | 65 | 90 | — | **255** | 3.92 |
| 3 | VLAN-tagged no-match → drop (L2 walks 5 maps, L3 default DROP) | 50 | 135 | 25 | — | — | **210** | 4.76 |
| 4 | VLAN-tagged TCP allow (L2 walks 5, L3 rule-hit, L4 rule-hit) | 50 | 135 | 65 | 50 | — | **300** | 3.33 |
| 5 | IPv6 + 2 ext headers, TCP allow + ACT_TAG → TC rewrite (currently corrupts the packet) | 55 | 50 | 80 | 75 | 60 | **320** | 3.12 |
| 6 | IPv4 mirror via TC clone_redirect (full pipeline → TC bpf_clone_redirect) | 50 | 50 | 70 | 50 | 120 | **340** | 2.94 |

Numbers exclude driver/NAPI/softirq cost (multiplier ~1.5–3× for real NIC-attached load, per `02_architecture.md §5`).

### 40 Gbps verdict

Per-packet budget at 1024 B mean frame: ~205 ns/pkt at 4.88 Mpps. Per-core capacity from the table:

- Path #1 (the operator-friendly common case): **215 ns** — **fits at line-rate on 1 core**, just barely. ~5% headroom evaporates under cache thrash.
- Path #3 (VLAN no-match, the carrier-Gi-typical bulk): **210 ns** — same envelope, same fragility.
- Path #4 (VLAN-tagged TCP allow): **300 ns** — **does not fit at 4.88 Mpps on 1 core**. 2 cores needed.
- Path #5 (IPv6 with TC tag): **320 ns** plus the correctness bug.
- Path #6 (mirror): **340 ns** — 2 cores needed.

**Design conclusion**: at 1024 B mean frame, **2–3 cores** with RSS spreading are required for sustained 40 Gbps on the worst representative path. The published "13.2 Mpps L2 drop" headline (`README.md:142`) describes path #3 *only* on the untagged-no-match shortest path and only via `BPF_PROG_TEST_RUN`. The design fails at:

- 64-byte line-rate (59.5 Mpps) — would need 12+ cores even on the fastest path; not the design's stated target.
- VLAN-heavy traffic on a single core.
- Any path involving TC clone-redirect on a single core.

### Ranked optimisations

Ordered by ns/pkt saved on the dominant path (#3 VLAN no-match) and effort/risk.

| Rank | Optimisation | Estimated saving (ns/pkt) | Effort | Risk |
|------|--------------|--------------------------:|--------|------|
| 1 | **L2 single-dispatch lookup**: pre-compute one composite key, one hash lookup, secondary filter_mask check. Removes 4 of 5 lookups on the no-match path. `06_layer2.md §13`. | **50–100** | M (compiler refactor) | M (collision-resolution policy) |
| 2 | **Pre-compute `eth_proto` + `l3_off` in entry's `pkt_meta`**, drop the L3 re-parse of Ethernet (and L4's re-parse via IP fetch). `02_architecture.md §P2 list`, `07_entry.md`. | **6–9** | S | L |
| 3 | **Replace `ktime_get_ns` in rate-limit with `bpf_jiffies64`** or batched once-per-NAPI-poll timestamp. `05_layer4.md §1` notes `ktime_get_ns` cost ~10–15 ns. | **10–15** | S | L (token-bucket precision drops to ms scale; acceptable for Mbps rates) |
| 4 | **Per-CPU bytes counter** paired with packet counter (also fixes P0 no-bps). Adds ~3 ns but enables saving below. | +3 (cost) | S | L |
| 5 | **Reduce `STAT_INC` call sites**: a long success path hits stats_map 3–4 times; coalesce to one increment per packet with a per-program counter array index. | **8–15** | M | L |
| 6 | **Move VLAN parse + `eth_proto_inner` to entry** so L2's no-match path avoids reading the VLAN tag bytes twice (entry & L2). | **3–5** | S | L |
| 7 | **Tail-call elimination** on the matched-rule-with-`next_layer=0` shortcut: skip the L4 program entry when L3 matched terminal-ALLOW. Phase 2b noted asymmetry on no-match. | **5–10** | M | M |
| 8 | **Inline `get_default_action` reads into entry-side cache** to avoid the late-stage map lookup on no-match paths. | **5–8** | S | L |

### "If all applied" target

Cumulative on path #3 (VLAN no-match → drop): 210 ns − (50…100 + 6…9 + 10…15 + 8…15 + 3…5 + 5…8) ≈ **80–125 ns/pkt**. That brings single-core capacity from ~4.76 Mpps to ~8–12 Mpps, restoring full headroom on 1 core for VLAN-tagged traffic and matching the published "13.2 Mpps" claim on the *no-match* path (not the matched-rule path it was claimed for).

Path #4 (VLAN + TCP allow): 300 ns − 100 (L2 redesign) − 10 (ktime not on this path) − 10 (other) ≈ **170–180 ns/pkt**, i.e. ~5.5 Mpps/core, fits 40 Gbps at 1024 B on 1 core.

The single largest payoff by far is item #1 (L2 single-dispatch). Everything else is incremental.

---

## 4. Observability

### Stat coverage

Verified by `grep -oE 'STAT_[A-Z0-9_]+ +=' bpf/common.h` vs `grep -hE 'STAT_INC\(STAT_[A-Z0-9_]+\)' bpf/*.c`: **all 40 defined stat slots are incremented from at least one site**. No dead enum entries.

But the *quality* of coverage is uneven (Phase 2 findings, recapped):
- **No bytes counter** (P0, `02_architecture.md §7`) — `bps` from the customer brief is unanswerable.
- `STAT_PASS_L3` double-fires on MIRROR-with-no-next-layer (`02_architecture.md §7` P2).
- `STAT_TC_NOOP` is overloaded: it means both "driver stripped data_meta" and "no deferred work today". Phase 1's `data_meta` invariant alarm becomes invisible (P1, `09_tc_ingress.md`).
- `STAT_DROP_L2_NO_MATCH` conflates "no rule matched" with "tail-call fall-through" (`06_layer2.md`).
- `STAT_DROP_NO_META` overloaded across program boundaries.

### Prometheus exporter — orphan time series check

Read directly (`src/metrics/prometheus_exporter.hpp:36-141`). The exporter exposes the **40 global counters** as Prometheus metrics with static labels (e.g., `pktgate_drop_total{layer="l3",reason="rule"}`). There are **no per-rule labels** — the recon note "exposes per-rule labels" is wrong. The list of metric descriptors `kMetrics[]` is compile-time fixed; `static_assert(sizeof(kMetrics)/sizeof(kMetrics[0]) == STAT__MAX)` guards against drift.

Consequence: **no orphan-time-series risk** (no rule cardinality in the metric model) but also **no per-rule observability**. An operator can see "L3 dropped 1M packets" but cannot see "rule 42 dropped 500k of them". For a Gi filter with ~hundreds of rules, this is a real operational gap. The customer brief asks for "per-rule counters" — the global counters don't satisfy it.

### Logs

`src/util/log.hpp` is 84 LOC, four levels (DEBUG/INFO/WARN/ERROR), prints to stderr/journal with `vfprintf` — no structure, no JSON, no trace IDs, no per-event context map. Use sites (43 total across `src/`): control-plane lifecycle events only — config reload, parse failures, BPF load/attach errors, inotify status. **No data-plane events** are logged from userspace (only via `bpf_printk` if `BPF_DEBUG` is on at compile time).

Gaps:
- **No per-rule log/audit action.** Phase 2b/2d flagged this; `scenarios_v2/` wanted `log` in 6 of 10 templates. Not implementable today.
- **No per-packet sampled trace.** A `--trace 5tuple=10.0.0.1:80` debugging mode would be operationally valuable for "why isn't rule X firing"; doesn't exist.
- **No runtime log level**. The level is the call-site macro choice; flipping debug on requires `-DBPF_DEBUG` at compile time + rebuild.
- **Hot-reload events are logged**, but a config-reload audit log (who/when/diff) is not.

### sFlow / IPFIX

Not implemented. Customer brief explicitly listed sFlow. Owner notes (`00_OWNER_NOTES.md §B`) deferred as "no hard requirements" — still file P2 because it's a brief-stated capability that's silently absent.

### Runtime tracing facility

`BPF_DEBUG` enables `bpf_printk` to the kernel trace pipe. That's the **entire** tracing facility. There is no:
- per-packet sampled tracepoint that operators can enable at runtime without rebuild
- ring-buffer dump of last-N decisions
- `pktgate_ctl --trace-rule 42` to inject prints for one specific rule
- structured "decision event" stream

For a Gi-side carrier filter, an operationally important question is "I configured rule 42 to drop port-9999; my customer says it's still passing — what does pktgate see?" Today, the operator's only tool is the global `STAT_DROP_L4_RULE` counter, which doesn't disaggregate by rule. Cross-referenced against the missing per-rule metrics, the observability story is **structurally** weak.

---

## 5. Build & supply chain

### CMake (`CMakeLists.txt`)

Read in full. Quality:

- `cmake_minimum_required(VERSION 3.25)` — appropriate; matches RPM `BuildRequires: cmake >= 3.25`.
- C++23, CXX_STANDARD_REQUIRED ON — appropriate for `std::expected` usage in fuzz/control plane.
- Hardening flags (`L9-15`): `-fstack-protector-strong` + `-D_FORTIFY_SOURCE=2`, **but only on Release builds and only when COVERAGE/SANITIZER are off**. Debug builds and sanitizer builds have no stack-protector and no _FORTIFY_SOURCE. CI runs three of four matrix variants in **Debug** with/without ASan/UBSan; the only hardened binary CI produces is `Release/no-sanitizer`. RPM `%build` runs Release, so the shipped binary is hardened — but local developer builds are not.
- **Missing**: `-fcf-protection=full` (CET), `-fstack-clash-protection`, `-Wformat -Wformat-security`, `-fPIE -pie` (executable is built as PIE by modern CMake defaults, but no explicit flag), RELRO linker flag (`-Wl,-z,relro,-z,now`).
- BPF compile invocation (`L66-79`): `-O2 -g -target bpf` + `-D__TARGET_ARCH_${arch}`. **Does not pass `-Wall -Wextra`** for BPF compilation; BPF clang warnings are suppressed. Phase 2 verifier-safety reviews are doing the work the compiler would do if warnings were enabled.
- Sanitizers (`L181-195`): ASan, TSan, UBSan supported via `-DSANITIZER=`. Correct flag set. CI runs ASan and UBSan but not TSan.
- Fuzz (`L320-345`): three fuzz harnesses (`fuzz_config_parser`, `fuzz_net_types`, `fuzz_roundtrip`). Note: **no fuzzer for the BPF data plane** (`PROG_TEST_RUN`-based packet fuzzer). The IPv6 ext-header bypasses are exactly the bug class a packet-fuzzer would have found.
- `find_package(nlohmann_json 3.11 REQUIRED)` — lower bound only, no upper.
- `pkg_check_modules(LIBBPF REQUIRED libbpf)` — **no version pin**. RPM has `>= 1.1`; CMake has nothing.
- `find_program(CLANG NAMES clang-16 clang-17 clang-18 clang REQUIRED)` — preference list, no version assertion. Build with clang-20 or system `clang` of unknown version silently accepted.

### Missing CMake targets

- `tools/validate_config.cpp` — **not in CMakeLists.txt** (Phase 2j P0). Fresh builds produce no `validate_config` binary; CONFIG.md documents a tool that doesn't get built.
- No install targets for `tools/` outputs. No install of `config-schema.json` to `/etc/pktgate/`. No install of `scenarios/*.json` (sample configs documented in README).
- `ARCHITECTURE.md`, `CONFIG.md`, `README.md` are not installed by `make install`; the RPM spec also doesn't install them (`%files` lists `pktgate_ctl`, the service, the configs — nothing else). The `Documentation=file:///opt/pktgate/ARCHITECTURE.md` URL in the unit file points to a path the install machinery never creates.

### Reproducibility

- `add_compile_options(-g)` for everything that builds — debug info embeds source paths. Not bit-reproducible across build hosts.
- No `SOURCE_DATE_EPOCH` honoured anywhere. `add_custom_command` for BPF compile bakes timestamps via the ELF section headers (clang doesn't honour SDE without explicit support).
- BPF object files include the absolute source path in `DW_AT_comp_dir` (consequence of `-g` and full paths). Two builds on different machines produce different `.bpf.o` files.

### RPM spec (`rpm/pktgate.spec`)

- Packages: `pktgate_ctl` binary, `pktgate.service`, `config.json`, `pktgate.conf`. Reasonable but **incomplete**:
  - `tools/validate_config` not packaged (because not built — circular with the CMake gap).
  - `ARCHITECTURE.md` / `CONFIG.md` not packaged. The `Documentation=` URL in the unit file would 404.
  - `scripts/uninstall.sh` not packaged — operator who installs via RPM has no rollback assistance.
  - `config-schema.json` not packaged.
- `License: GPL-2.0-only` — correct claim, but `%license bpf/entry.bpf.c` ships a source file as the licence document. Should be a proper `LICENSE` file at repo root (none exists; `find /home/user/filter -name LICENSE` would confirm).
- `%check` runs `ctest --exclude-regex 'bpf_dataplane'` — same gap as CI: BPF data-plane tests not run. The packager can't certify the dataplane.
- `%post` / `%preun` are idempotent and conventional.
- File permissions in `%files`: relies on default rpm `%defattr` (root:root, 644 for configs). Adequate.

### CI (`.github/workflows/{ci,fuzz}.yml`)

- `ci.yml`: 4-way matrix (Debug, Debug+ASan, Debug+UBSan, Release). Installs clang-18. Runs `ctest -L unit` and `ctest -L integration` only. **`bpf_dataplane` is not in either label** (`CMakeLists.txt:299-308` — it has its own labels `bpf;privileged`). The functional test suite (`functional_tests/*.py`) is **not run anywhere in CI**.
- `fuzz.yml`: PR-level smoke (60s × 3 harnesses), nightly campaign (3600s × 3). Three harnesses only — `config_parser`, `net_types`, `roundtrip`. No data-plane fuzzer.
- Cross-reference with Phase 2 findings: every P0 in the inventory (dst_ip, L4 ext-header chain, IPv6 ACT_TAG, wrong-layer fields, validate_config silent OK) **passed CI** because CI exercises the parser+validator+compile path with happy-path inputs and never runs against scenarios known to compile clean but fail at the data plane. PR fuzz couldn't find configs that compile clean but cause data-plane bugs — that's the test-culture problem.
- **No code-scan workflow** (CodeQL, Snyk, Trivy). No SBOM emission. No supply-chain attestation (SLSA).

### `build/` staleness

- `build/pktgate_ctl` — last modified **2026-04-09 19:13** (one month old at review date 2026-05-11).
- `build/validate_config` — **2026-04-09 09:04** — older still. This is the binary the Phase 2j review identified as "Apr-9 leftover from before validate_config was removed from CMake".
- The whole `build/` tree appears to be a snapshot from the same April-9 session, never `make clean`-ed. Suggests the development workflow doesn't include `clean` and the binaries on disk aren't representative of the current source. For a security-sensitive project this is a latent footgun: somebody running `./build/validate_config` today gets stale binary semantics.

### `compile_commands.json`

Verified directly (`grep '"file"' build/compile_commands.json | wc -l` → 27, `grep '\.bpf\.c' build/compile_commands.json` → empty).

- 27 entries, **all `.cpp` files**. **No BPF source** appears.
- Every entry uses `/usr/bin/c++ ... -std=gnu++23`. There is **no `-x c -target bpf`** anywhere.
- Consequence: clangd treats `bpf/*.bpf.c` as either unknown (no record) or, if the user has set up an editor wildcard fallback, as C++. The `__attribute__((section(".maps")))` macros and `vmlinux.h` BPF helpers will all show as errors in the editor. Anyone writing BPF code in clangd-backed IDEs is flying blind.
- Fix: generate `compile_commands.json` entries for the BPF custom command via `CMAKE_EXPORT_COMPILE_COMMANDS` + a wrapper script, or post-process to inject the BPF clang invocations.

---

## Cross-cutting findings (graded)

Only **new** findings or escalations from Phase 2. Phase 2 findings are cited where relevant.

```
- [P0 NEW, cross-cutting] IPv6 is the project's weakest dimension
  Where: bpf/{layer3,layer4,tc_ingress}.bpf.c — three sites, one root cause.
  What: No IP-family gate at action sites; ext-header walks are shallow
  (fail-open) and IPv4 byte offsets are blindly applied to IPv6 packets.
  Tests cover happy paths only (functional_tests/test_l3_ipv6.py 10/10
  happy-path).
  Why it matters: For a Gi-side filter, an adversary controlling the
  packet shape can bypass L4 (chain ≥5) and the operator can silently
  corrupt the packet (tag on IPv6). This is a class, not three bugs.
  Suggested action: (a) add IP-family bit to pkt_meta and gate TC DSCP
  rewrite and L4 ext-walker on it; (b) make L4 ext-walker fail-closed
  at the bound (drop with dedicated counter); (c) macro/dispatch wrapper
  to force both arms at every v4/v6 site; (d) IPv6 adversarial test
  matrix (depth × action × family).

- [P0 NEW] CAP_SYS_ADMIN over-granted in systemd unit
  Where: systemd/pktgate.service:43-44
  What: AmbientCapabilities and CapabilityBoundingSet both grant
  CAP_SYS_ADMIN. On kernels ≥5.8, XDP+TC operation requires only
  CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON. CAP_SYS_ADMIN is the kernel-
  wide root cap (mount, reboot, namespace ops, raw kernel memory in
  some configs). The single most attacker-valuable cap on the system.
  Why it matters: Post-exploit blast radius is the entire kernel
  surface, not the BPF subsystem. Reduces the value of the otherwise
  good hardening directives in the same unit.
  Suggested action: Drop CAP_SYS_ADMIN from Ambient + Bounding sets;
  retest on the target kernel; if a fallback path uses it, gate it
  behind a kernel-version check at startup.

- [P1 NEW] NoNewPrivileges=no is wrong AND the inline comment cements
  the misunderstanding
  Where: systemd/pktgate.service:22-23
  What: AmbientCapabilities are compatible with NoNewPrivileges=yes;
  the kernel restricts caps only across a SUID transition.
  Why it matters: Children of pktgate_ctl (none today, but the door is
  open) can gain caps via SUID binaries; defeats one of the cheapest
  hardening flags.
  Suggested action: Set NoNewPrivileges=yes; remove the misleading
  comment; verify on the target kernel.

- [P1 NEW] No seccomp filter (SystemCallFilter=) on a CAP_SYS_ADMIN+
  CAP_BPF process
  Where: systemd/pktgate.service — directive absent
  What: With CAP_BPF + CAP_SYS_ADMIN + no seccomp filter, the post-
  exploit syscall surface is enormous.
  Suggested action: Add SystemCallFilter=@system-service @bpf @network
  @file-system; explicitly subtract unused families
  (RestrictAddressFamilies=AF_NETLINK AF_INET AF_INET6 AF_UNIX).

- [P1 NEW] CMake libbpf has no version floor; nlohmann_json has no
  upper bound
  Where: CMakeLists.txt:19-20
  What: pkg_check_modules(LIBBPF REQUIRED libbpf) accepts libbpf 0.5
  (CVE-2022-3534-vulnerable). RPM spec enforces 1.1+ but CMake doesn't.
  Suggested action: pkg_check_modules(LIBBPF REQUIRED libbpf>=1.1) plus
  an upper bound on nlohmann_json once an incompatibility is known.

- [P1 NEW] `tools/validate_config.cpp` missing from CMake; build/
  binary is Apr-9 stale
  Where: CMakeLists.txt (absence); build/validate_config (file mtime
  2026-04-09 09:04)
  What: This is also the Phase 2j P0 entry but flagged here as a
  build-system cross-cutting issue. Fresh builds produce no
  validate_config; the binary in build/ is a stale leftover. Combined
  with the Phase 2j P0 (tool returns OK on configs that destroy the
  network) — operator following CONFIG.md on a fresh clone runs the
  stale binary or "command not found".
  Suggested action: Add as a CMake target now; on next deploy, the
  same fix that re-introduces compile-side validation lands.

- [P1 NEW] CI runs only `unit` and `integration` labels; bpf_dataplane
  and the entire pytest functional suite are not in any pipeline
  Where: .github/workflows/ci.yml:62-65 (label-restricted ctest);
  functional_tests/* (no workflow includes them)
  What: Every P0 in the Phase 2 inventory passed CI. The dst_ip
  catch-all wildcard, the IPv6 ACT_TAG corruption, the L4 ext-header
  chain ≥5 bypass, and the validate_config silent-OK are all caught
  by tests that don't run in CI (or don't exist).
  Suggested action: Add a CI job that runs bpf_dataplane in a
  privileged runner; add a functional-tests job using a network
  namespace + scapy; both can be slow/serial without blocking the
  fast PR path.

- [P1 NEW] Full-packet mirror has no truncation, no PII boundary; Gi-
  link privacy unaddressed
  Where: bpf/tc_ingress.bpf.c (bpf_clone_redirect); no truncation
  helper anywhere
  What: Already named in 02_architecture.md §4; rerated here because
  the customer brief explicitly applies to a Gi link carrying PII /
  IMSI / VoLTE / unencrypted HTTP. Owner notes deferred but the
  consolidation should re-list.
  Suggested action: Add `--max-mirror-bytes` cap; document the
  privacy contract; reject mirror actions in the validator unless
  the operator opts in via a config flag.

- [P1 NEW] No per-rule observability — neither metrics nor logs nor
  trace
  Where: src/metrics/prometheus_exporter.hpp (global counters only);
  src/util/log.hpp (control-plane events only); no rule-id-keyed map
  in bpf/maps.h
  What: Operator-facing "which rule passed/dropped which packets"
  is unanswerable. Phase 2 noted absence of `log` action; the wider
  story is that the entire observability surface is global, not
  per-rule.
  Suggested action: Add a `per_rule_stats` BPF_MAP_TYPE_PERCPU_HASH
  keyed by rule_id (carry rule_id in pkt_meta as we already do at L3);
  expose to Prometheus with `rule_id` label; add LRU eviction so map
  shape is bounded.

- [P2 NEW] compile_commands.json contains no BPF entries; clangd
  cannot index bpf/*.bpf.c
  Where: build/compile_commands.json — 27 entries, all .cpp, no
  `-x c -target bpf` anywhere
  What: clangd-driven editor diagnostics are wrong / absent for the
  BPF tree, which is the most security-sensitive code in the
  project. The next contributor working on a verifier-correctness
  fix has no IDE help.
  Suggested action: Inject the BPF clang invocations into
  compile_commands.json via a CMake post-build step or
  bear/compiledb-style wrapper.

- [P2 NEW] Hardening flags applied only to Release-no-sanitizer
  Where: CMakeLists.txt:10-15
  What: -fstack-protector-strong + -D_FORTIFY_SOURCE=2 only on
  Release builds with no sanitizer. Three of four CI matrix variants
  produce non-hardened binaries; local developer builds are
  non-hardened.
  Suggested action: Apply stack-protector and FORTIFY independently
  of build type when not in coverage. Move sanitizer detection to a
  finer-grained condition.

- [P2 NEW] BPF compile lacks -Wall/-Wextra
  Where: CMakeLists.txt:66-79
  What: BPF sources are compiled with -O2 -g only; verifier
  warnings and clang BPF target warnings are not emitted. The
  Phase 2 review found correctness issues the compiler would have
  flagged with -Wall.
  Suggested action: -Wall -Wno-unused-function for BPF.

- [P2 NEW] No data-plane fuzzer
  Where: fuzz/ (3 harnesses, all userspace)
  What: The IPv6 ext-header bypasses and the ACT_TAG corruption
  are exactly the bug class a `PROG_TEST_RUN`-based packet fuzzer
  finds in minutes.
  Suggested action: Add `fuzz_bpf_dataplane.cpp` that builds packets
  via libfuzzer, runs them through `BPF_PROG_TEST_RUN`, asserts the
  return code is consistent with the configured ruleset.

- [P2 NEW] sFlow / IPFIX absent (customer brief delta); LICENSE file
  absent at repo root (RPM ships a source file as the licence
  document); build/ is a month-stale snapshot. Three cosmetic items
  consolidated.
```

---

## Test-audit additions

For each new finding above, the missing test class:

| Finding | Missing test class |
|---------|-------------------|
| IPv6 cross-cutting P0 | **Adversarial × Action × Family matrix** of functional tests + data-plane fuzz harness. Per-action × {v4, v6} × {happy, ext-chain-5, ext-chain-8, fragment-behind-HBH, fragment-behind-DestOpt} cells. Today: 10 happy-path tests; needed: ~30. |
| CAP_SYS_ADMIN over-grant | systemd-unit-property test: assert `AmbientCapabilities` is the documented minimum set; CI runs `systemd-analyze security pktgate.service` and asserts score ≥ 5 / OK. |
| NoNewPrivileges=no | Same systemd unit-property test. |
| No seccomp | Same. |
| Library version floors | A CMake-side regression test: `find_package(libbpf 1.1 REQUIRED)`; CI install of libbpf 1.0 must fail at configure time. |
| validate_config CMake gap | A pytest that runs `cmake --build build --target validate_config`; must succeed. Plus a bash test: a known-bad dst_ip config exits non-zero. |
| CI label gap | Add `bpf_dataplane` + `functional` test labels; CI must run both. The "missing test category" is the test job itself. |
| Mirror PII | Functional test: configure a mirror action; assert the cloned packet length is ≤ configured truncation cap; assert a `--no-mirror` startup flag rejects configs with mirror. |
| Per-rule observability | A functional test that loads a 100-rule config and asserts `/metrics` exposes 100 distinct `rule_id` series; asserts removed rules' series disappear after reload (or are explicitly zero-marked). |
| compile_commands.json gap | A CI step: `jq '.[] | select(.file | endswith(".bpf.c"))' build/compile_commands.json | grep '"file"'` — count must equal 5 (number of `.bpf.c` files). |
| Hardening flags conditional | A binary-property test: `readelf -d build/pktgate_ctl` must show `FORTIFY` and `BIND_NOW` in every matrix variant; CI asserts. |
| BPF -Wall | Build-log assertion: BPF compile emits zero warnings. |
| Data-plane fuzzer | The harness itself is the test. |
| sFlow gap | n/a — capability gap, not a behaviour gap. |
| LICENSE | A CI step that asserts the presence of a top-level `LICENSE` file. |
| build/ staleness | Cosmetic; not a test concern. |

---

## Recommendations to feed into the final report

Rank-ordered structural moves (not individual fixes — the architecture-level direction the next maintenance cycle should pursue). The final report should be organised around these, with P0/P1/P2 findings cited per recommendation rather than as a flat list.

1. **Treat the IPv6 surface as one phase, not three bugs.** Add an `ip_family` byte to `pkt_meta`; lift v4/v6 dispatch to a macro every action site is required to use; make the L4 ext-header walker fail-closed at its bound with a dedicated counter; build an adversarial IPv6 test matrix. This single move closes the cross-cutting P0 above and three of the Phase 2 P0/P1 IPv6 findings.
2. **Turn the validator into a real pre-deploy gate.** The dst_ip P0, the wrong-layer-fields P0, and the validate_config silent-OK P0 all collapse into one fix: `validate_config` (a) gets a CMake target, (b) runs `compile_rules` not just parse+validate, (c) the validator enforces "every rule has at least one match field for its layer". The owner-facing contract becomes "if `validate_config` says OK, the config is safe to deploy". Today it lies.
3. **Lift the L2 dispatch to a single composite-key lookup.** This is the single largest perf win in the whole tree (50–100 ns/pkt on the dominant path). Worth a dedicated mini-phase because it touches the compiler's key-selection logic, the BPF L2 program, and the test suite's L2 layer in lockstep.
4. **Wire CI to actually exercise the data plane.** A privileged CI runner with `bpf_dataplane` + functional pytest suite. Today the CI passes every P0. Fix the CI shape before fixing more bugs, or the next round of bugs will land the same way.
5. **Build per-rule observability, end to end.** A per-rule BPF map keyed by `rule_id`, Prometheus labels, a `pktgate_ctl --trace-rule N` runtime trace. Subsumes the missing `log` action requested by 6 of 10 scenarios_v2 templates; closes the customer-brief "per-rule counters" gap; gives operators their first real diagnostic tool.
6. **Tighten the systemd / supply-chain story.** Drop CAP_SYS_ADMIN, fix NoNewPrivileges, add seccomp filter, pin libbpf ≥ 1.1 in CMake, install LICENSE, ship documentation. Each cheap individually; together they close the security and supply-chain block.
7. **Make `data_meta` driver-dependence explicit.** A startup self-test that sends a sentinel through `PROG_TEST_RUN`-and-back validates the invariant the entire XDP→TC handoff rests on. Disambiguates `STAT_TC_NOOP` in the process.
8. **Bytes counter pair + sFlow-or-IPFIX path.** Customer-brief deltas. Bytes counter is two days of work; sFlow is a phase. Either / both, by stated priority.

The executive narrative for the final report should be:

> pktgate's documented architecture is faithful in its load-bearing skeleton — atomic generation swap, dual-buffered maps, XDP→TC handoff, inotify-driven hot reload, fragment-drop hardening. The four most damaging classes of finding lie *between* modules, not within them: (1) IPv6 is the project's weakest dimension; (2) the operator-facing trust boundary leaks silently along three independent paths (`validate_config` lies, `dst_ip` becomes a wildcard, wrong-layer fields accepted); (3) the test culture rewards happy-path coverage and two tests cement bugs as contract; (4) CI runs none of the tests that would catch these. Fixing any one of the four in isolation leaves the project meaningfully unsafe; fixing all four is the unblock for resuming feature work.

What goes first in the report: the four classes above as a one-page executive summary, then the P0 list (8 from Phase 2 + 2 new from Phase 3 = 10), then per-class deep dives that cite individual findings as evidence, then the deferred-TODO list owner notes specified.
