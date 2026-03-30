# pktgate — eBPF/XDP Packet Filter

High-performance packet filter with JSON-driven pipeline configuration.
Uses XDP for fast-path drop/redirect and TC ingress for mirror/DSCP rewrite.

## Features

- **L2 MAC filtering** — hash-based allow-list
- **L3 IPv4/IPv6 subnet filtering** — LPM trie with per-rule actions
- **L4 TCP/UDP port filtering** — protocol + port matching
- **Actions**: allow, drop, redirect (VRF), mirror (clone), tag (DSCP), rate-limit
- **Hitless config reload** — double-buffered maps with atomic generation swap
- **Hot reload** — inotify + SIGHUP, debounce, fail-safe (errors don't affect active pipeline)
- **IPv6 dual-stack** — separate LPM tries, extension header parsing, fragment detection
- **Prometheus metrics** — `/metrics` endpoint with per-counter labels
- **Systemd integration** — hardened service unit with capability bounding

## Architecture

```
NIC → [XDP entry] → tail_call → [L2 MAC] → [L3 IP/LPM] → [L4 port]
                                                 ↓
                                          [TC ingress: mirror + DSCP rewrite]
```

- **Data plane**: 5 BPF programs (4 XDP + 1 TC), tail call chaining, metadata via `data_meta`
- **Control plane**: C++23, libbpf skeleton API, double-buffered maps
- **Zero map lookups** between layers — packet metadata passed through XDP `data_meta` area

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design document.

## Build

### Dependencies

```bash
apt install -y clang-16 llvm-16 libbpf-dev bpftool \
    linux-headers-$(uname -r) libelf-dev zlib1g-dev \
    nlohmann-json3-dev
```

### Compile

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Options

| CMake option | Description |
|---|---|
| `-DBPF_DEBUG=ON` | Enable `bpf_printk` tracing in BPF programs |
| `-DCOVERAGE=ON` | Enable gcov/lcov code coverage |
| `-DSANITIZER=asan\|tsan\|ubsan` | Build with sanitizer |
| `-DFUZZ=ON` | Build libFuzzer fuzz targets |

## Usage

```bash
# Run directly
sudo ./build/pktgate_ctl [--json] [--debug] [--metrics-port 9090] config.json

# Systemd
sudo systemctl start pktgate
sudo systemctl reload pktgate        # SIGHUP → hot reload
kill -USR1 $(pidof pktgate_ctl)      # dump stats to journal
```

## Configuration

JSON config defines objects (MACs, subnets, port groups) and a layered pipeline:

```json
{
  "device_info": { "interface": "eth0", "capacity": "10Gbps" },
  "objects": {
    "subnets": { "trusted": "100.64.0.0/16" },
    "subnets6": { "trusted_v6": "2001:db8:cafe::/48" },
    "mac_groups": { "routers": ["00:11:22:33:44:55"] },
    "port_groups": { "web": [80, 443] }
  },
  "pipeline": {
    "layer_2": [{ "rule_id": 10, "match": {"src_mac": "object:routers"}, "action": "allow", "next_layer": "layer_3" }],
    "layer_3": [{ "rule_id": 100, "match": {"src_ip": "object:trusted"}, "action": "allow", "next_layer": "layer_4" }],
    "layer_4": [{ "rule_id": 1000, "match": {"protocol": "TCP", "dst_port": "object:web"}, "action": "allow" }]
  },
  "default_behavior": "drop"
}
```

See [sample2.json](sample2.json) for a complete example with all action types.

## Metrics

With `--metrics-port 9090`, Prometheus metrics are served at `http://host:9090/metrics`:

```
pktgate_packets_total
pktgate_drop_total{layer="l3",reason="rule"}
pktgate_pass_total{layer="l4"}
pktgate_action_total{action="mirror"}
pktgate_tc_total{action="tag"}
```

A Grafana dashboard is in `grafana/`.

## Testing

```bash
# Unit tests (387 tests, 16 suites)
ctest --test-dir build --output-on-failure

# Selective: unit only / integration only
ctest --test-dir build -L unit
ctest --test-dir build -L integration

# BPF data plane tests (requires root)
sudo ctest --test-dir build -L bpf

# Functional tests — real packets via veth namespaces (requires root)
sudo bash functional_tests/run.sh
```

## Performance

BPF_PROG_TEST_RUN benchmarks (1M packets):

| Path | ns/pkt | Mpps |
|---|---|---|
| L2 MAC drop | 76 | ~13.2 |
| L4 TCP:80 allow | 90 | ~11.1 |
| Full pipeline (L3 LPM + L4) | 165 | ~6.1 |

## License

GPL-2.0
