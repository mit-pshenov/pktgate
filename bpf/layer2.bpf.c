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
 *
 * On no match:
 *   - If LAYER_PRESENT_L2 is set (this generation deployed at least one L2
 *     rule), apply the configured default_behavior. Operator intent says
 *     "rules exist, none matched → fall back to default".
 *   - Otherwise the L2 layer is effectively empty (e.g. an L3-only config),
 *     so we skip to Layer 3 without opinion.
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

/* Apply the configured default_behavior at L2 no-match.
 * Mirrors get_default_action() in layer3.bpf.c — the global default_action
 * map is shared across layers. */
static __always_inline int get_default_action_l2(struct pkt_meta *meta, __u32 pkt_len)
{
    __u32 key = 0;
    __u32 *def = (meta->generation == 0)
        ? bpf_map_lookup_elem(&default_action_0, &key)
        : bpf_map_lookup_elem(&default_action_1, &key);

    if (!def || *def == ACT_DROP) {
        STAT_COUNT(STAT_DROP_L2_NO_MATCH, pkt_len);
        return XDP_DROP;
    }
    STAT_COUNT(STAT_PASS_L2, pkt_len);
    return XDP_PASS;
}

static __always_inline int handle_l2_action(struct xdp_md *ctx,
                                            struct pkt_meta *meta,
                                            struct l2_rule *rule,
                                            __u32 pkt_len)
{
    switch (rule->action) {
    case ACT_ALLOW:
        break;

    case ACT_DROP:
        STAT_COUNT(STAT_DROP_L2_RULE, pkt_len);
        BPF_DBG("L2: rule %d → DROP", rule->rule_id);
        return XDP_DROP;

    case ACT_REDIRECT:
        if (rule->redirect_ifindex) {
            STAT_COUNT(STAT_REDIRECT, pkt_len);
            BPF_DBG("L2: rule %d → REDIRECT ifindex=%d",
                     rule->rule_id, rule->redirect_ifindex);
            return bpf_redirect(rule->redirect_ifindex, 0);
        }
        STAT_COUNT(STAT_DROP_L2_REDIRECT_FAIL, pkt_len);
        return XDP_DROP;

    case ACT_MIRROR:
        meta->action_flags |= (1 << ACT_MIRROR);
        meta->mirror_ifindex = rule->mirror_ifindex;
        STAT_COUNT(STAT_MIRROR, pkt_len);
        BPF_DBG("L2: rule %d → MIRROR ifindex=%d",
                 rule->rule_id, rule->mirror_ifindex);
        break;

    default:
        STAT_COUNT(STAT_DROP_L2_RULE, pkt_len);
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
    STAT_COUNT(STAT_PASS_L2, pkt_len);
    return XDP_PASS;
}

SEC("xdp")
int layer2_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = (__u32)((unsigned char *)data_end - (unsigned char *)data);

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
        return handle_l2_action(ctx, meta, rule, pkt_len);
    }

    /* ── 2. Destination MAC lookup ─────────────────────────── */
    struct mac_key dst_key = {};
    __builtin_memcpy(dst_key.addr, eth->h_dest, 6);

    rule = (gen == 0) ? bpf_map_lookup_elem(&l2_dst_mac_0, &dst_key)
                      : bpf_map_lookup_elem(&l2_dst_mac_1, &dst_key);
    if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
        BPF_DBG("L2: dst_mac match, rule %d", rule->rule_id);
        return handle_l2_action(ctx, meta, rule, pkt_len);
    }

    /* ── 3. EtherType lookup ───────────────────────────────── */
    struct ethertype_key ekey = { .ethertype = eth_proto };

    rule = (gen == 0) ? bpf_map_lookup_elem(&l2_ethertype_0, &ekey)
                      : bpf_map_lookup_elem(&l2_ethertype_1, &ekey);
    if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
        BPF_DBG("L2: ethertype match 0x%x, rule %d",
                 bpf_ntohs(eth_proto), rule->rule_id);
        return handle_l2_action(ctx, meta, rule, pkt_len);
    }

    /* ── 4. VLAN ID lookup ─────────────────────────────────── */
    if (has_vlan) {
        struct vlan_key vkey = { .vlan_id = vlan_id };

        rule = (gen == 0) ? bpf_map_lookup_elem(&l2_vlan_0, &vkey)
                          : bpf_map_lookup_elem(&l2_vlan_1, &vkey);
        if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
            BPF_DBG("L2: vlan %d match, rule %d", vlan_id, rule->rule_id);
            return handle_l2_action(ctx, meta, rule, pkt_len);
        }
    }

    /* ── 5. PCP lookup (only for tagged frames) ───────────── */
    if (has_vlan) {
        struct pcp_key pkey = { .pcp = pcp };

        rule = (gen == 0) ? bpf_map_lookup_elem(&l2_pcp_0, &pkey)
                          : bpf_map_lookup_elem(&l2_pcp_1, &pkey);
        if (rule && l2_filters_match(rule, eth_proto, vlan_id, pcp)) {
            BPF_DBG("L2: pcp %d match, rule %d", pcp, rule->rule_id);
            return handle_l2_action(ctx, meta, rule, pkt_len);
        }
    }

    /* ── No match ──────────────────────────────────────────── */
    __u32 lp_key = 0;
    __u8 *lp = (gen == 0) ? bpf_map_lookup_elem(&layer_present_0, &lp_key)
                          : bpf_map_lookup_elem(&layer_present_1, &lp_key);
    if (lp && (*lp & LAYER_PRESENT_L2)) {
        /* L2 has rules; none matched → apply default_behavior */
        BPF_DBG("L2: no match, applying default, gen=%d", gen);
        return get_default_action_l2(meta, pkt_len);
    }

    /* L2 is empty for this generation → skip to Layer 3 unchanged */
    if (gen == 0)
        bpf_tail_call(ctx, &prog_array_0, LAYER_3_IDX);
    else
        bpf_tail_call(ctx, &prog_array_1, LAYER_3_IDX);

    STAT_INC(STAT_DROP_L2_TAIL);
    BPF_DBG("L2: empty + L3 tail call failed, gen=%d", gen);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
