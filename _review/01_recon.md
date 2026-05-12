# 01 — Recon

## Project in one paragraph

**pktgate** is a high-performance packet filter using eBPF/XDP and TC (traffic control) with JSON-driven configuration. It implements a layered pipeline: L2 Ethernet filtering (MAC, ethertype, VLAN), L3 IP filtering (LPM subnets, IPv4/IPv6 dual-stack), and L4 transport filtering (TCP/UDP ports with TCP flags). Actions include allow, drop, redirect (VRF), mirror (clone), tag (DSCP/CoS), and rate-limit. The control plane is C++23 with libbpf skeleton API, using double-buffered BPF maps for hitless config reload. Deployment via systemd with hardened capabilities, RPM packaging, and comprehensive test coverage (570+ test points). Currently on pause after completing 18 phases of development; last active mid-April 2026.

## Architecture summary

The system splits into **data plane** (5 BPF programs) and **control plane** (C++23).

**Data plane**: 4 XDP programs (entry, layer2, layer3, layer4) chain via tail calls into shared maps. Layer 2 uses 4 hash maps (src_mac, dst_mac, ethertype, vlan); Layer 3 uses LPM trie for IPv4/v6 subnets plus hash for VRF rules; Layer 4 uses hash for port+protocol matching. Packet metadata is passed via XDP `data_meta` area (zero map lookups between layers). A 5th TC ingress program handles mirror/DSCP rewrites deferred from XDP. Each program is independent, re-loadable.

**Control plane**: JSON config → **ConfigParser** → **ConfigValidator** (semantic checks: rule IDs unique, object refs valid, L2 constraints enforced) → **ObjectCompiler** (MACs hashed, subnets into LPM keys, ports expanded) → **RuleCompiler** (pipeline rules → BPF map entries, collision detection) → **GenerationManager** (double-buffered maps: prepare shadow, commit atomic, 100ms drain) → **PipelineBuilder** (orchestrator). Configuration reload via inotify (directory watch) + SIGHUP, with 150ms debounce to handle editor atomic saves. Errors don't affect the active pipeline.

**Generation swap**: Two generations (0, 1) alternate. Control plane fills shadow maps while active maps serve traffic, then atomically swaps via `gen_config[0]`. Kernel code checks generation at entry, reads corresponding maps. Guarantees zero packet loss and rollback capability.

## Directory map

```
src/                    (6.7 KLOC — control plane, userspace)
├── main.cpp (281)      — entry point, inotify/SIGHUP loop, signal handlers
├── config/             — JSON parsing & validation
│   ├── config_model.hpp/cpp (234 L)   — Config structs, Action enum
│   ├── config_parser.hpp/cpp (178 L)  — JSON → Config, object refs
│   └── config_validator.hpp/cpp (228 L) — semantic validation: rule_id uniq, CIDR validity
├── compiler/           — compile Config to BPF map entries
│   ├── object_compiler.hpp/cpp (116 L) — MAC hash, LPM trie keys, port lists
│   └── rule_compiler.cpp (441 L)       — L2/L3/L4 rule expansion, collisions
├── loader/             — libbpf skeleton API
│   ├── bpf_loader.hpp/cpp (453 L)      — load/attach/unload 5 BPF progs, map reuse
│   └── map_manager.hpp/cpp (161 L)     — batch_update, safe iteration
├── pipeline/           — deployment orchestration
│   ├── generation_manager.hpp/cpp (386 L) — double-buffer state, prepare/commit
│   ├── pipeline_builder.hpp/cpp (118 L)  — validator → compiler → deploy
│   ├── stats_reader.hpp (135 L)          — per-CPU counter aggregation
│   └── deploy_stats.hpp (69 L)           — timing instrumentation
├── metrics/            — Prometheus exporter
│   └── prometheus_exporter.hpp (293 L)   — HTTP /metrics endpoint, per-rule labels
└── util/               — helpers
    ├── net_types.hpp (132 L)             — MacAddr, Ipv4Prefix/Ipv6Prefix parse
    └── log.hpp (84 L)                    — lightweight structured logging

bpf/                    (1.2 KLOC — data plane, kernel)
├── entry.bpf.c (60)    — XDP entry: generation dispatch, metadata alloc, L2 tail_call
├── layer2.bpf.c (210)  — L2: hash lookups src_mac/dst_mac/ethertype/vlan
├── layer3.bpf.c (293)  — L3: LPM subnet lookup, VRF, redirect/mirror flags
├── layer4.bpf.c (278)  — L4: port matching, token bucket rate-limit, DSCP tagging
├── tc_ingress.bpf.c (110) — TC: bpf_clone_redirect mirror, TOS/VLAN rewrite
├── common.h (261)      — shared structs: mac_key, l2_rule, lpm_v4_key, pkt_meta, STAT_*
├── maps.h (226)        — all 21 BPF maps: double-buffered + shared (gen_config, stats, rate)
└── vmlinux.h (106K)    — BTF-generated kernel structs (not hand-edited)

tests/                  (15 files, ~466 unit/integration tests)
├── test_config_parser.cpp (41) — JSON parsing, DSCP names, bandwidth
├── test_config_validator.cpp (51) — semantic validation, ref cycles, bandwidth overflow
├── test_rule_compiler_edge.cpp (67) — collisions, L2 compound, port expansion
├── test_pipeline_integration.cpp (27) — E2E: parse → validate → compile → deploy
├── test_roundtrip.cpp (17)     — parse → compile → byte-level verify
├── test_stress.cpp (9)         — 1000 subnets, 4096 rules, 16K LPM keys
├── test_concurrency.cpp (13)   — multi-thread gen swap, atomic ops
├── test_ipv6.cpp (52)          — IPv6Prefix, dual-stack, lpm_v6_key layout
├── test_byte_layout.cpp (31)   — sizeof/offsetof BPF structs, endianness
├── test_packet_builder.cpp (17) — L2/L3/L4 frame construction
├── test_net_types.cpp (26)     — MacAddr/IP parsing, CIDR edge cases
├── test_config_validation.cpp (30) — config validation (negative cases)
├── test_fault_injection.cpp (13) — bit flip, truncation, bad JSON
├── test_prometheus.cpp (7)     — HTTP /metrics, concurrent scrapes
├── test_generation_logic.cpp (15) — gen swap state machine
└── bpf/test_bpf_dataplane.cpp (36) — BPF_PROG_TEST_RUN (root only)

functional_tests/       (13 pytest files, 104 tests, real veth traffic)
├── conftest.py         — veth pair setup, namespace fixtures
├── test_l2_mac.py (8)  — MAC allow/deny, broadcast
├── test_l3_subnet.py (15) — IPv4 LPM, CIDR multi-rule
├── test_l3_ipv6.py (10) — IPv6 ext headers, fragment detection
├── test_l4_ports.py (16) — TCP/UDP, port groups, protocol filter
├── test_dscp_tag.py (3) — DSCP rewrite via TC, TOS verification
├── test_pipeline.py (11) — cross-layer interaction
├── test_malformed.py (15) — truncated/invalid packets
└── test_zz_*.py (5+10) — lifecycle, reload, gen swap, rate-limit, mirror/redirect

fuzz/                   (3 libFuzzer/standalone harnesses)
├── fuzz_config_parser.cpp — JSON fuzz
├── fuzz_net_types.cpp     — MAC/IP parse fuzz
├── fuzz_roundtrip.cpp     — pipeline fuzz
└── corpus_*/ directories (2–5 seeds each)

scenarios/ & scenarios_v2/ (20 JSON config templates)
├── scenarios/ (10) — DDoS, VLAN, mirroring, PCI DSS, API rate, VRF, IPv6, IoT, QoS, port-scan
└── scenarios_v2/ (10) — carrier DDoS, SOC incident, zero-trust, Purdue model, DNS security, threat intel, FlowSpec, observability

tools/                  (1 utility)
└── validate_config.cpp — CLI to validate config without loading BPF

systemd/                (deployment)
├── pktgate.service    — hardened unit: ProtectSystem=strict, CAP_BPF+CAP_NET_ADMIN
└── pktgate.conf       — env overrides (metrics port, config path)

scripts/                (deployment helpers)
├── setup_env.sh       — install build deps (clang-16, libbpf-dev, bpftool, nlohmann-json)
├── install.sh         — cmake build + systemd install
├── uninstall.sh       — stop & remove (--purge for config)
└── build_rpm.sh       — rpmbuild wrapper

rpm/                    (1 spec)
└── pktgate.spec       — RPM metadata, build targets, %check = ctest

grafana/                (1 dashboard)
└── pktgate-dashboard.json — Prometheus dashboard template

demo/                   (veth setup scripts)
├── setup_veth.sh      — create ns_pktgate/ns_client veth pair
├── cleanup_veth.sh    — teardown
└── veth_config.json   — sample config for live demo

build/                  (CMake output, present)
└── compile_commands.json — clangd source (exists, recent: Apr 9)
```

## Build & dependencies

**CMake 3.25+** targets:
- **pktgate_ctl** — main binary
- **libpktgate_lib.a** — static library (tests link it)
- **17 test executables** (12 unit, 4 integration, 1 BPF dataplane)
- **bench_compile** — performance benchmark (manual)
- **3 fuzz targets** (libFuzzer or standalone)
- **bpf_programs** — 5 BPF .o files + 5 skeletons

**External deps**:
- `libbpf >= 1.1` (pkg-config), linking with `elf`, `z`
- `nlohmann_json >= 3.11`
- `clang-16` or later (for BPF compilation, auto-detected)
- `bpftool` (skeleton generation)

**Hardening flags** (Release builds):
- `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2` (except with coverage/sanitizer)
- `-Wall -Wextra`

**Options**:
- `-DBPF_DEBUG=ON` → enable `bpf_printk` in BPF code
- `-DCOVERAGE=ON` → lcov/genhtml coverage (disables hardening)
- `-DSANITIZER=asan|tsan|ubsan` → sanitizer flags (disables hardening)
- `-DFUZZ=ON` → build libFuzzer targets (clang-17+ required for std::expected)

**Notably clean**: No deprecated dependencies, no C++14 cruft, uses C++23 `std::expected` for error handling. BPF target arch auto-detected (x86, arm64, s390, riscv). Skeleton API reuses maps via `bpf_map__reuse_fd()`.

## Recent activity

Last 2 months (from Feb 11 to Apr 9):
- **L2 extended filtering** (dst_mac, ethertype, vlan_id) — full stack + 71 tests (Apr 5–9)
- **L2 compound rules** (AND logic, PCP matching) + TCP flags in L4 (Apr 9)
- **Fuzz CI pipeline** — smoke (PR) + overnight (cron) jobs (Mar 30, Apr 5–6)
- **Functional tests** — 104 pytest tests via scapy/veth (Mar 30, updated Apr 5)
- **Systemd/RPM hardening** — capability bounding, service unit (Mar 30)
- **Mirror/redirect e2e tests** — veth-based live tests (Mar 30)
- **Configuration docs** — CONFIG.md user reference, scenario templates (scenarios/ + scenarios_v2/, Apr 9)
- **CI fixes** — bpftool wrapper bypass, Node.js 24 upgrade, clang-19 for fuzzer (Mar–Apr)

All commits annotated; no dangling work. Last commit Apr 9 "CONFIG.md reference".

## Author-known debt

**Search result**: Zero explicit TODO/FIXME/XXX/HACK markers in code (even vmlinux.h exempted via pattern match). However, ARCHITECTURE.md documents 2 **unresolved design items**:

1. **Section 10, Q4 — "Mirror target" logical names**: `"target_port"` is currently ifindex-only. Logical names (e.g., "Eth-1/10") require external mapping — not implemented. Config parser accepts strings but `if_nametoindex()` is used; if name doesn't resolve, ruleset is rejected.

2. **Section 10, Q7 — "LPM_TRIE no iteration"**: `BPF_MAP_TYPE_LPM_TRIE` does not support `bpf_map_get_next_key()`. `GenerationManager` maintains in-memory `lpm_keys_[2]` list for shadow cleanup. On daemon crash, list is lost — **not critical** since maps are not pinned (recreated on restart), but becomes an issue if pinned maps (bpffs) are added for zero-downtime restarts. Possible mitigations documented:
   - (a) Recreate shadow LPM_TRIE on startup
   - (b) Replace LPM_TRIE with offline prefix expansion (HASH)
   - (c) Persist `lpm_keys_[]` to disk

3. **TEST_PLAN.md, Section 5** — "Known finding: port > 65535 passes validation" — validator should reject this but doesn't.

No other code comments document gaps.

## Proposed hot zones for Phase 2

**Ranked by risk/impact** (most scrutiny first):

1. **`bpf/layer3.bpf.c` (293 LOC)** — LPM trie handling, VRF rules, IPv6. LPM keys must be correct byte-layout (prefixlen + address, no padding). IPv6 fragment detection. Redirect/mirror flags passed via metadata. **Why**: Core filtering logic, shared BPF/userspace struct layout.

2. **`bpf/layer2.bpf.c` (210 LOC)** — 4 parallel hash lookups (src_mac, dst_mac, ethertype, vlan_id), compound rule AND logic, PCP matching. **Why**: New L2 extended feature (Apr 9), most recently changed; compound rule evaluation order matters.

3. **`src/compiler/rule_compiler.cpp` (441 LOC)** — port group expansion, key collision detection, layout verification. **Why**: O(n²) collision checks on large rule sets; incorrect layout detection breaks deployment.

4. **`bpf/entry.bpf.c` (60 LOC) + `src/pipeline/generation_manager.cpp` (325 LOC)** — generation dispatch, metadata allocation, double-buffered swap, atomic cutover. **Why**: Core safety mechanism; correctness here is binary.

5. **`src/config/config_parser.cpp` (163 LOC)** — JSON input parsing (untrusted). **Why**: First trust boundary; malformed JSON could cause DoS or parser crash.

6. **`bpf/layer4.bpf.c` (278 LOC)** — port matching, token bucket rate-limiter (per-CPU state, elapsed clamp), TCP flags filtering. **Why**: Rate-limiting correctness depends on CPU time tracking; token bucket can underflow.

7. **`bpf/common.h` (261 LOC)** — shared struct definitions, STAT_* enum. **Why**: Byte-level alignment; misaligned structs between BPF and C++ break silently.

8. **`bpf/tc_ingress.bpf.c` (110 LOC)** — mirror clone, DSCP rewrite, CoS VLAN push/pop. **Why**: Metadata-dependent, non-XDP helpers, less tested (functional tests pass but live conditions vary).

## Open questions for the human

1. **Logical port naming** — "Mirror target": Current config accepts `"target_port": "eth0"` (interface name). Does production use physical names (eth0/eth1) or logical names (Eth-1/10, lo0)? If logical, is there a mapping file or external system?

2. **LPM_TRIE persistence** — Are pinned BPF maps (bpffs) planned for zero-downtime restart? If yes, `lpm_keys_[]` loss on daemon crash becomes critical; which mitigation (a/b/c) is preferred?

3. **Untested scenarios** — The project has 10 scenario templates (scenarios/ + scenarios_v2/) but I didn't see integration tests that load them. Are these reference configs or are some used in CI? Should Phase 1 validate that all scenarios load without error?

4. **Rate-limit accuracy** — TC tests show rate-limit is approximate (CPU load dependent). Is "best effort" acceptable for production, or is precise shaping (via tc-htb / EDT) a requirement?

5. **IPv6 fragment handling** — Fragments are dropped at L3 with a counter. Is this intentional (security hardening) or a limitation? Should fragments be reassembled or logged separately?

## Summary statistics

- **Code**: 6.7 KLOC C++, 1.2 KLOC BPF (5 progs), 0.6 KLOC tools
- **Tests**: 570+ points (17 ctest + 104 functional + 3 fuzz)
- **Coverage**: unit, integration, dataplane, functional, fuzz (3 harnesses)
- **Branches**: main (active), afxdp (feature, not merged)
- **Build**: CMake 3.25, clang-16+, libbpf 1.1+, C++23
- **Deployment**: systemd unit, RPM spec, install/uninstall scripts
- **Docs**: README, ARCHITECTURE (45 KB), CONFIG, TEST_PLAN, 9 scenario sets
- **Status**: Pause-ready; 38 commits, 18 completed phases, clean state
