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

/* ── Layer 2: single composite map per generation ──────────── */
/* See _fixes/02_l2_single_dispatch.md. The five per-field maps
 * (src_mac/dst_mac/ethertype/vlan/pcp) were collapsed into one keyed by
 * l2_key, with filter_mask naming the populated fields. Per packet, BPF
 * iterates the active-mask array and projects the parsed fields through
 * each mask to compute the lookup key (bounded by MAX_L2_MASKS). */

/* MAX_L2_ENTRIES is defined in common.h so userspace capacity checks
 * (P1#10) can see it without including this BPF-only header. */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_L2_ENTRIES);
    __type(key, struct l2_key);
    __type(value, struct l2_rule);
} l2_rules_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_L2_ENTRIES);
    __type(key, struct l2_key);
    __type(value, struct l2_rule);
} l2_rules_1 SEC(".maps");

/* l2_active_masks_{0,1}: filter_mask values that appear in the deployed
 * ruleset, sorted descending by popcount (most-specific first), zero-
 * terminated. BPF iterates this array up to MAX_L2_MASKS. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_L2_MASKS);
    __type(key, __u32);
    __type(value, __u8);
} l2_active_masks_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_L2_MASKS);
    __type(key, __u32);
    __type(value, __u8);
} l2_active_masks_1 SEC(".maps");

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

/* ── Layer-present mask (one per generation) ───────────────── */
/* See LAYER_PRESENT_* bits in common.h. Layer applies default_behavior on
 * no-match iff its bit is set; otherwise it skips to the next layer. */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} layer_present_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} layer_present_1 SEC(".maps");

/* ── Statistics counters (shared, not double-buffered) ─────── */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_STATS);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/* Bytes counter, parallel keyspace to stats_map. Each terminal stat site
 * bumps both — callers reach for STAT_COUNT(key, len) rather than wiring
 * two macros every time. Customer-brief asks for "per-rule pps/bps"; this
 * gives bps at every rule-correlated stat slot. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_STATS);
    __type(key, __u32);
    __type(value, __u64);
} bytes_map SEC(".maps");

/*
 * STAT_INC — atomically increment a per-CPU packet counter.
 * Zero-cost on the hot path: single map lookup + increment.
 */
#define STAT_INC(stat_key_val) do {                    \
    __u32 _sk = (stat_key_val);                        \
    __u64 *_cnt = bpf_map_lookup_elem(&stats_map, &_sk); \
    if (_cnt) (*_cnt)++;                               \
} while (0)

/* STAT_ADD_BYTES — bump byte counter for the same stat slot. */
#define STAT_ADD_BYTES(stat_key_val, pkt_len) do {           \
    __u32 _bk = (stat_key_val);                              \
    __u64 *_b = bpf_map_lookup_elem(&bytes_map, &_bk);       \
    if (_b) (*_b) += (pkt_len);                              \
} while (0)

/* STAT_COUNT — common case: bump packets and bytes for one stat slot. */
#define STAT_COUNT(stat_key_val, pkt_len) do {               \
    STAT_INC(stat_key_val);                                   \
    STAT_ADD_BYTES(stat_key_val, pkt_len);                    \
} while (0)

/* ── Rate limiter state (shared, not double-buffered) ─────── */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, __u32);   /* rule_id */
    __type(value, struct rate_state);
} rate_state_map SEC(".maps");

#endif /* FILTER_BPF_MAPS_H */
