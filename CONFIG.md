# Configuration Reference

User-level reference for the pktgate JSON configuration format.
For architecture internals see [ARCHITECTURE.md](ARCHITECTURE.md).
For build and usage see [README.md](README.md).
For production scenario examples see [scenarios/](scenarios/README.md).

## Table of Contents

- [Overview](#overview)
- [Top-Level Structure](#top-level-structure)
- [Objects](#objects)
- [Pipeline](#pipeline)
  - [Layer 2 (Ethernet)](#layer-2-ethernet)
  - [Layer 3 (IP)](#layer-3-ip)
  - [Layer 4 (Transport)](#layer-4-transport)
- [Actions](#actions)
- [Match Fields Reference](#match-fields-reference)
- [TCP Flags](#tcp-flags)
- [DSCP Names](#dscp-names)
- [Limits](#limits)
- [Examples](#examples)

## Overview

pktgate configuration is a single JSON file that defines:

1. **Objects** -- reusable named groups (MACs, subnets, ports)
2. **Pipeline** -- ordered layers of match/action rules: L2 -> L3 -> L4
3. **Default behavior** -- what happens when no rule matches

Packets flow through the pipeline top to bottom. Each layer can terminate
(allow/drop) or forward to the next layer via `next_layer`. If no rule
matches in a layer, the `default_behavior` applies.

Config is validated against [config-schema.json](config-schema.json)
and can be checked without loading BPF programs:

```bash
./build/validate_config config.json
```

## Top-Level Structure

```json
{
  "device_info": { "interface": "eth0", "capacity": "10Gbps" },
  "objects":     { ... },
  "pipeline":    { "layer_2": [...], "layer_3": [...], "layer_4": [...] },
  "default_behavior": "drop"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `device_info.interface` | string | yes (if rules exist) | Network interface to attach XDP/TC programs |
| `device_info.capacity` | bandwidth | no | Link capacity for informational purposes |
| `objects` | object | no | Reusable named groups for use in rules |
| `pipeline` | object | yes | Rule layers (L2, L3, L4) |
| `default_behavior` | `"allow"` or `"drop"` | no | Fallback when no rule matches. Default: `"drop"` |

**Bandwidth format:** number + unit. Units: `Gbps`, `Mbps`, `Kbps`, `bps` (case-sensitive).
Examples: `"10Gbps"`, `"500Mbps"`, `"1000Kbps"`.

## Objects

Named groups that rules reference with the `object:` prefix (or `object6:` for IPv6).

```json
"objects": {
  "subnets":    { "trusted": "10.0.0.0/8", "blocked": "192.0.2.0/24" },
  "subnets6":   { "office_v6": "2001:db8:cafe::/48" },
  "mac_groups": { "routers": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"] },
  "port_groups": { "web": [80, 443, 8080], "dns": [53] }
}
```

| Object type | Value format | Referenced as |
|-------------|-------------|--------------|
| `subnets` | IPv4 CIDR (`"10.0.0.0/8"`) | `"object:name"` in `src_ip` / `dst_ip` |
| `subnets6` | IPv6 CIDR (`"2001:db8::/32"`) | `"object6:name"` in `src_ip6` / `dst_ip6` |
| `mac_groups` | Array of MAC addresses (`"AA:BB:CC:DD:EE:FF"`) | `"object:name"` in `src_mac` / `dst_mac` |
| `port_groups` | Array of ports 0-65535 (`[80, 443]`) | `"object:name"` in `dst_port` |

When a rule references a group, it expands at compile time. A rule matching
`"object:web"` with ports [80, 443, 8080] becomes three entries in the BPF map.

## Pipeline

Three ordered layers. Each rule has this general shape:

```json
{
  "rule_id": 100,
  "description": "optional human-readable note",
  "match": { ... },
  "action": "allow",
  "action_params": { ... },
  "next_layer": "layer_4"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rule_id` | uint32 | yes | Unique within the layer |
| `description` | string | no | Documentation only, ignored by pipeline |
| `match` | object | yes (L2, L4) | Fields to match against the packet |
| `action` | string | yes | What to do on match (see [Actions](#actions)) |
| `action_params` | object | depends on action | Parameters for mirror/redirect/tag/rate-limit |
| `next_layer` | string | no | Forward packet to `"layer_3"` or `"layer_4"` after this layer |

### Layer 2 (Ethernet)

Matches on Ethernet headers before any IP parsing.

**Match fields:**

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `src_mac` | MAC or object ref | `"AA:BB:CC:DD:EE:FF"`, `"object:routers"` | Source MAC address |
| `dst_mac` | MAC or object ref | `"object:servers"` | Destination MAC address |
| `ethertype` | name or hex | `"IPv4"`, `"IPv6"`, `"ARP"`, `"0x0800"` | EtherType field |
| `vlan_id` | integer 0-4095 | `100` | 802.1Q VLAN ID |
| `pcp` | integer 0-7 | `5` | 802.1p Priority Code Point |

**Constraints:**
- At least one match field required
- `src_mac` and `dst_mac` cannot be in the same rule
- `next_layer` can be `"layer_3"` or `"layer_4"`

**Compound rules:** Multiple fields in one rule use AND logic. When multiple
fields are present, the most selective one becomes the primary lookup key
(hash map), and the rest are checked as secondary filters after the primary
match.

Primary field precedence (highest first): `src_mac` > `dst_mac` > `vlan_id` > `ethertype` > `pcp`.

```json
{
  "rule_id": 10,
  "match": { "src_mac": "object:routers", "vlan_id": 100, "ethertype": "IPv4" },
  "action": "allow",
  "next_layer": "layer_3"
}
```

This rule: primary lookup by src_mac, then verify vlan_id=100 AND ethertype=IPv4.

### Layer 3 (IP)

Matches on IP source/destination using LPM (longest prefix match) or VRF.

**Match fields:**

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `src_ip` | IPv4 CIDR or object ref | `"10.0.0.0/8"`, `"object:trusted"` | Source IPv4 subnet |
| `dst_ip` | IPv4 CIDR or object ref | `"192.168.0.0/16"` | Destination IPv4 subnet |
| `src_ip6` | IPv6 CIDR or object6 ref | `"2001:db8::/32"`, `"object6:office"` | Source IPv6 subnet |
| `dst_ip6` | IPv6 CIDR or object6 ref | `"object6:blocked"` | Destination IPv6 subnet |
| `vrf` | string | `"guest_vrf"` | Match packets arriving on a VRF interface |

**Constraints:**
- `next_layer` can only be `"layer_4"`
- IPv6 fragments are dropped at L3 (fragment header detected)
- IPv4 non-first fragments are dropped at L3

**Notes:**
- IPv4 and IPv6 rules are separate LPM tries in BPF; both can coexist
- When no subnet matches, VRF rules act as a fallback before `default_behavior`

### Layer 4 (Transport)

Matches on transport protocol and destination port. Optionally filters on TCP flags.

**Match fields:**

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `protocol` | `"TCP"` or `"UDP"` | `"TCP"` | Transport protocol (required) |
| `dst_port` | port or object ref | `"80"`, `"object:web"` | Destination port (required) |
| `tcp_flags` | flag expression | `"SYN,!ACK"` | TCP flags filter (optional, TCP only) |

**Constraints:**
- Both `protocol` and `dst_port` are required
- `tcp_flags` requires `protocol` = `"TCP"`
- `next_layer` is not allowed at L4 (it is the last layer)

See [TCP Flags](#tcp-flags) for the flags syntax.

## Actions

| Action | Description | Required `action_params` |
|--------|-------------|-------------------------|
| `"allow"` | Pass the packet | -- |
| `"drop"` | Discard the packet | -- |
| `"mirror"` | Clone packet to a target interface, then continue processing | `target_port` (interface name) |
| `"redirect"` | Forward packet to a VRF | `target_vrf` (VRF name) |
| `"tag"` | Mark packet with DSCP and/or CoS for QoS, then pass | `dscp` and/or `cos` |
| `"rate-limit"` | Per-CPU token bucket; pass if under limit, drop if over | `bandwidth` |

**Action params:**

```json
"action_params": {
  "target_port": "Eth-1/10",
  "target_vrf": "captive_portal_vrf",
  "dscp": "EF",
  "cos": 5,
  "bandwidth": "1Gbps"
}
```

| Param | Type | Used by | Description |
|-------|------|---------|-------------|
| `target_port` | string | mirror | Interface name to clone packets to |
| `target_vrf` | string | redirect | VRF name to redirect packets into |
| `dscp` | DSCP name | tag | Differentiated Services Code Point (see [DSCP Names](#dscp-names)) |
| `cos` | integer 0-7 | tag | 802.1p Class of Service value |
| `bandwidth` | bandwidth string | rate-limit | Token bucket rate (e.g. `"500Mbps"`) |

**Rate limiting notes:**
- Uses per-CPU token buckets with 1-second burst
- The configured bandwidth is divided equally across CPUs
- Minimum effective rate: 1 bps per CPU

## Match Fields Reference

Quick reference of which fields are available in each layer:

| Field | L2 | L3 | L4 | Format |
|-------|:--:|:--:|:--:|--------|
| `src_mac` | x | | | `"AA:BB:CC:DD:EE:FF"` or `"object:name"` |
| `dst_mac` | x | | | same |
| `ethertype` | x | | | `"IPv4"`, `"IPv6"`, `"ARP"`, or `"0xNNNN"` |
| `vlan_id` | x | | | integer 0-4095 |
| `pcp` | x | | | integer 0-7 |
| `src_ip` | | x | | IPv4 CIDR or `"object:name"` |
| `dst_ip` | | x | | same |
| `src_ip6` | | x | | IPv6 CIDR or `"object6:name"` |
| `dst_ip6` | | x | | same |
| `vrf` | | x | | VRF name string |
| `protocol` | | | x | `"TCP"` or `"UDP"` |
| `dst_port` | | | x | port number or `"object:name"` |
| `tcp_flags` | | | x | flag expression (TCP only) |

## TCP Flags

Filter TCP packets by flag bits. Only valid when `protocol` is `"TCP"`.

**Syntax:** comma-separated flag names. Prefix `!` means the flag must NOT be set.

```
"tcp_flags": "SYN,!ACK"       -- SYN set AND ACK not set (new connection)
"tcp_flags": "SYN"             -- SYN set (ACK can be anything)
"tcp_flags": "SYN,ACK"         -- both SYN and ACK set (SYN-ACK)
"tcp_flags": "FIN,!RST"        -- graceful close, not reset
```

**Available flags:** `FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `ECE`, `CWR`

**Matching logic:**
- All flags listed without `!` must be set in the packet
- All flags listed with `!` must NOT be set in the packet
- Flags not mentioned are ignored (can be either set or unset)
- If a rule has no `tcp_flags`, it matches any TCP flags

**Omitting `tcp_flags`** matches all TCP packets regardless of flags.
This is the normal behavior for port-based rules that don't care about
connection state.

## DSCP Names

Standard names for the `dscp` action parameter:

| Class | Names | Values |
|-------|-------|--------|
| Best Effort | `BE`, `CS0` | 0 |
| Expedited Forwarding | `EF` | 46 |
| Assured Forwarding 1 | `AF11`, `AF12`, `AF13` | 10, 12, 14 |
| Assured Forwarding 2 | `AF21`, `AF22`, `AF23` | 18, 20, 22 |
| Assured Forwarding 3 | `AF31`, `AF32`, `AF33` | 26, 28, 30 |
| Assured Forwarding 4 | `AF41`, `AF42`, `AF43` | 34, 36, 38 |
| Class Selector | `CS1`..`CS7` | 8, 16, 24, 32, 40, 48, 56 |

## Limits

Maximum entries per map (BPF hard limits):

| Resource | Limit |
|----------|-------|
| Rules per layer | 4096 |
| MAC entries (src + dst combined) | 4096 |
| IPv4 subnet entries | 16384 |
| L4 port entries | 4096 |
| VRF entries | 256 |
| Rate limit buckets | 4096 |
| EtherType entries | 64 |
| VLAN entries | 4096 |
| PCP entries | 8 |

Object group expansion counts against these limits. A port_group with
100 ports referenced by one rule creates 100 BPF map entries.

## Examples

### Minimal: drop everything

```json
{
  "device_info": { "interface": "eth0" },
  "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [] },
  "default_behavior": "drop"
}
```

### DDoS protection with rate limiting

```json
{
  "device_info": { "interface": "eth0", "capacity": "10Gbps" },
  "objects": {
    "subnets": { "botnet": "198.51.100.0/24" },
    "port_groups": { "dns": [53] }
  },
  "pipeline": {
    "layer_2": [],
    "layer_3": [
      {
        "rule_id": 100,
        "match": { "src_ip": "object:botnet" },
        "action": "drop"
      },
      {
        "rule_id": 200,
        "match": { "src_ip": "0.0.0.0/0" },
        "action": "allow",
        "next_layer": "layer_4"
      }
    ],
    "layer_4": [
      {
        "rule_id": 1000,
        "match": { "protocol": "UDP", "dst_port": "object:dns" },
        "action": "rate-limit",
        "action_params": { "bandwidth": "100Mbps" }
      },
      {
        "rule_id": 1010,
        "match": { "protocol": "TCP", "dst_port": "80" },
        "action": "allow"
      }
    ]
  },
  "default_behavior": "drop"
}
```

### SYN flood protection with TCP flags

```json
{
  "rule_id": 2000,
  "match": {
    "protocol": "TCP",
    "dst_port": "80",
    "tcp_flags": "SYN,!ACK"
  },
  "action": "rate-limit",
  "action_params": { "bandwidth": "50Mbps" }
}
```

### L2 compound rule: MAC + VLAN + QoS

```json
{
  "rule_id": 10,
  "match": {
    "src_mac": "object:border_routers",
    "vlan_id": 100,
    "pcp": 5
  },
  "action": "allow",
  "next_layer": "layer_3"
}
```

### Full example with all action types

See [sample2.json](sample2.json) for a complete config using allow, drop,
mirror, redirect, tag, and rate-limit across all three layers.

### Production scenarios

See [scenarios/](scenarios/README.md) for 10 realistic deployment configs
covering DDoS protection, VLAN segmentation, PCI DSS compliance, VRF
multi-tenancy, and more.
