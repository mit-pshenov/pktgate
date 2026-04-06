#ifndef FILTER_BPF_MAPS_H
#define FILTER_BPF_MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"

/* ── Generation config ─────────────────────────────────────── */

/* Single-element array: index 0 → active generation (0 or 1) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} gen_config SEC(".maps");

/* ── Program arrays for tail calls (one per generation) ──── */

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_LAYERS);
    __type(key, __u32);
    __type(value, __u32);
} prog_array_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_LAYERS);
    __type(key, __u32);
    __type(value, __u32);
} prog_array_1 SEC(".maps");

/* ── Layer 2: source MAC rules (one per generation) ──────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAC_ENTRIES);
    __type(key, struct mac_key);
    __type(value, struct l2_rule);
} l2_src_mac_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAC_ENTRIES);
    __type(key, struct mac_key);
    __type(value, struct l2_rule);
} l2_src_mac_1 SEC(".maps");

/* ── Layer 2: destination MAC rules (one per generation) ──── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAC_ENTRIES);
    __type(key, struct mac_key);
    __type(value, struct l2_rule);
} l2_dst_mac_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAC_ENTRIES);
    __type(key, struct mac_key);
    __type(value, struct l2_rule);
} l2_dst_mac_1 SEC(".maps");

/* ── Layer 2: EtherType rules (one per generation) ────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ETHERTYPE_ENTRIES);
    __type(key, struct ethertype_key);
    __type(value, struct l2_rule);
} l2_ethertype_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ETHERTYPE_ENTRIES);
    __type(key, struct ethertype_key);
    __type(value, struct l2_rule);
} l2_ethertype_1 SEC(".maps");

/* ── Layer 2: VLAN ID rules (one per generation) ─────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VLAN_ENTRIES);
    __type(key, struct vlan_key);
    __type(value, struct l2_rule);
} l2_vlan_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VLAN_ENTRIES);
    __type(key, struct vlan_key);
    __type(value, struct l2_rule);
} l2_vlan_1 SEC(".maps");

/* ── Layer 3: Subnet LPM trie → rule index (one per gen) ── */

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_SUBNET_ENTRIES);
    __type(key, struct lpm_v4_key);
    __type(value, struct l3_rule);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} subnet_rules_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_SUBNET_ENTRIES);
    __type(key, struct lpm_v4_key);
    __type(value, struct l3_rule);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} subnet_rules_1 SEC(".maps");

/* ── Layer 3: IPv6 Subnet LPM trie → rule (one per gen) ──── */

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_SUBNET_ENTRIES);
    __type(key, struct lpm_v6_key);
    __type(value, struct l3_rule);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} subnet6_rules_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_SUBNET_ENTRIES);
    __type(key, struct lpm_v6_key);
    __type(value, struct l3_rule);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} subnet6_rules_1 SEC(".maps");

/* ── Layer 3: VRF → action (one per generation) ───────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VRF_ENTRIES);
    __type(key, struct vrf_key);
    __type(value, struct l3_rule);
} vrf_rules_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VRF_ENTRIES);
    __type(key, struct vrf_key);
    __type(value, struct l3_rule);
} vrf_rules_1 SEC(".maps");

/* ── Layer 4: protocol+port → rule (one per generation) ──── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORT_ENTRIES);
    __type(key, struct l4_match_key);
    __type(value, struct l4_rule);
} l4_rules_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORT_ENTRIES);
    __type(key, struct l4_match_key);
    __type(value, struct l4_rule);
} l4_rules_1 SEC(".maps");

/* ── Default action (one per generation) ──────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  /* enum filter_action */
} default_action_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} default_action_1 SEC(".maps");

/* ── Statistics counters (shared, not double-buffered) ─────── */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_STATS);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/*
 * STAT_INC — atomically increment a per-CPU stats counter.
 * Zero-cost on the hot path: single map lookup + increment.
 */
#define STAT_INC(stat_key_val) do {                    \
    __u32 _sk = (stat_key_val);                        \
    __u64 *_cnt = bpf_map_lookup_elem(&stats_map, &_sk); \
    if (_cnt) (*_cnt)++;                               \
} while (0)

/* ── Rate limiter state (shared, not double-buffered) ─────── */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);   /* rule_id */
    __type(value, struct rate_state);
} rate_state_map SEC(".maps");

#endif /* FILTER_BPF_MAPS_H */
