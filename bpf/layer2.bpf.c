// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "maps.h"

/*
 * Layer 2: Ethernet filtering.
 *
 * Checks five hash maps in fixed priority order:
 *   src_mac → dst_mac → ethertype → vlan_id → pcp
 * After primary lookup, secondary filter fields are checked (compound rules).
 * First full match wins — its action is executed.
 * No match → tail call to Layer 3 (backward compat).
 */

/* Check secondary filter fields on a matched rule.
 * Returns true if ALL secondary conditions pass (or filter_mask == 0). */
static __always_inline bool l2_filters_match(struct l2_rule *rule,
                                              __u16 eth_proto,
                                              __u16 vlan_id,
                                              __u8 pcp)
{
    __u8 mask = rule->filter_mask;
    if (!mask)
        return true;
    if ((mask & L2_FILTER_ETHERTYPE) && rule->filter_ethertype != eth_proto)
        return false;
    if ((mask & L2_FILTER_VLAN) && rule->filter_vlan_id != vlan_id)
        return false;
    if ((mask & L2_FILTER_PCP) && rule->filter_pcp != pcp)
        return false;
    return true;
}

static __always_inline int handle_l2_action(struct xdp_md *ctx,
                                            struct pkt_meta *meta,
                                            struct l2_rule *rule)
{
    switch (rule->action) {
    case ACT_ALLOW:
        break;

    case ACT_DROP:
        STAT_INC(STAT_DROP_L2_RULE);
        BPF_DBG("L2: rule %d → DROP", rule->rule_id);
        return XDP_DROP;

    case ACT_REDIRECT:
        if (rule->redirect_ifindex) {
            STAT_INC(STAT_REDIRECT);
            BPF_DBG("L2: rule %d → REDIRECT ifindex=%d",
                     rule->rule_id, rule->redirect_ifindex);
            return bpf_redirect(rule->redirect_ifindex, 0);
        }
        STAT_INC(STAT_DROP_L2_REDIRECT_FAIL);
        return XDP_DROP;

    case ACT_MIRROR:
        meta->action_flags |= (1 << ACT_MIRROR);
        meta->mirror_ifindex = rule->mirror_ifindex;
        STAT_INC(STAT_MIRROR);
        BPF_DBG("L2: rule %d → MIRROR ifindex=%d",
                 rule->rule_id, rule->mirror_ifindex);
        break;

    default:
        STAT_INC(STAT_DROP_L2_RULE);
        return XDP_DROP;
    }

    /* Proceed to next layer if configured */
    if (rule->next_layer == LAYER_3_IDX) {
        if (meta->generation == 0)
            bpf_tail_call(ctx, &prog_array_0, LAYER_3_IDX);
        else
            bpf_tail_call(ctx, &prog_array_1, LAYER_3_IDX);
        STAT_INC(STAT_DROP_L2_TAIL);
        return XDP_DROP;
    }

    if (rule->next_layer == LAYER_4_IDX) {
        if (meta->generation == 0)
            bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
        else
            bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);
        STAT_INC(STAT_DROP_L2_TAIL);
        return XDP_DROP;
    }

    /* Terminal action — no next layer */
    STAT_INC(STAT_PASS_L2);
    return XDP_PASS;
}

SEC("xdp")
int layer2_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Bounds check for Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        STAT_INC(STAT_DROP_L2_BOUNDS);
        return XDP_DROP;
    }

    /* Read generation from data_meta area */
    void *data_meta = (void *)(long)ctx->data_meta;
    struct pkt_meta *meta = data_meta;
    if ((void *)(meta + 1) > data) {
        STAT_INC(STAT_DROP_L2_NO_META);
        return XDP_DROP;
    }

    __u32 gen = meta->generation;
    struct l2_rule *rule;

    /* ── Parse EtherType, VLAN, PCP early — needed by all lookups for filters ── */
    __u16 eth_proto = eth->h_proto;  /* network byte order */
    __u16 vlan_id = 0;
    __u8  pcp = 0;
    bool  has_vlan = false;

    /* Parse 802.1Q if present — extract VLAN ID, PCP, and inner ethertype */
    if (eth_proto == bpf_htons(0x8100)) {
        /* Need 4 extra bytes for VLAN TCI + inner ethertype */
        if ((void *)((unsigned char *)eth + 14 + 4) > data_end) {
            STAT_INC(STAT_DROP_L2_BOUNDS);
            return XDP_DROP;
        }
        __u16 *vlan_tci = (__u16 *)((unsigned char *)eth + 14);
        __u16 tci_host = bpf_ntohs(*vlan_tci);
        vlan_id = tci_host & 0x0FFF;
        pcp = (tci_host >> 13) & 0x7;
        eth_proto = *(__u16 *)((unsigned char *)eth + 16);  /* inner ethertype, NBO */
        has_vlan = true;
    }

    /* ── 1. Source MAC lookup ──────────────────────────────── */
    struct mac_key src_key = {};
    __builtin_memcpy(src_key.addr, eth->h_source, 6);

    rule = (gen == 0) ? bpf_map_lookup_elem(&l2_src_mac_0, &src_key)
                      : bpf_map_lookup_elem(&l2_src_mac_1, &src_key);
    if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
        BPF_DBG("L2: src_mac match, rule %d", rule->rule_id);
        return handle_l2_action(ctx, meta, rule);
    }

    /* ── 2. Destination MAC lookup ─────────────────────────── */
    struct mac_key dst_key = {};
    __builtin_memcpy(dst_key.addr, eth->h_dest, 6);

    rule = (gen == 0) ? bpf_map_lookup_elem(&l2_dst_mac_0, &dst_key)
                      : bpf_map_lookup_elem(&l2_dst_mac_1, &dst_key);
    if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
        BPF_DBG("L2: dst_mac match, rule %d", rule->rule_id);
        return handle_l2_action(ctx, meta, rule);
    }

    /* ── 3. EtherType lookup ───────────────────────────────── */
    struct ethertype_key ekey = { .ethertype = eth_proto };

    rule = (gen == 0) ? bpf_map_lookup_elem(&l2_ethertype_0, &ekey)
                      : bpf_map_lookup_elem(&l2_ethertype_1, &ekey);
    if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
        BPF_DBG("L2: ethertype match 0x%x, rule %d",
                 bpf_ntohs(eth_proto), rule->rule_id);
        return handle_l2_action(ctx, meta, rule);
    }

    /* ── 4. VLAN ID lookup ─────────────────────────────────── */
    if (has_vlan) {
        struct vlan_key vkey = { .vlan_id = vlan_id };

        rule = (gen == 0) ? bpf_map_lookup_elem(&l2_vlan_0, &vkey)
                          : bpf_map_lookup_elem(&l2_vlan_1, &vkey);
        if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
            BPF_DBG("L2: vlan %d match, rule %d", vlan_id, rule->rule_id);
            return handle_l2_action(ctx, meta, rule);
        }
    }

    /* ── 5. PCP lookup (only for tagged frames) ───────────── */
    if (has_vlan) {
        struct pcp_key pkey = { .pcp = pcp };

        rule = (gen == 0) ? bpf_map_lookup_elem(&l2_pcp_0, &pkey)
                          : bpf_map_lookup_elem(&l2_pcp_1, &pkey);
        if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
            BPF_DBG("L2: pcp %d match, rule %d", pcp, rule->rule_id);
            return handle_l2_action(ctx, meta, rule);
        }
    }

    /* ── No match — proceed to Layer 3 (backward compat) ──── */
    if (gen == 0)
        bpf_tail_call(ctx, &prog_array_0, LAYER_3_IDX);
    else
        bpf_tail_call(ctx, &prog_array_1, LAYER_3_IDX);

    STAT_INC(STAT_DROP_L2_NO_MATCH);
    BPF_DBG("L2: no match and L3 tail call failed, gen=%d", gen);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
