// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "maps.h"

/*
 * Layer 2: Ethernet filtering.
 *
 * Checks four hash maps in fixed priority order:
 *   src_mac → dst_mac → ethertype → vlan_id
 * First match wins — its action is executed.
 * No match → tail call to Layer 3 (backward compat).
 */

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

    /* ── 1. Source MAC lookup ──────────────────────────────── */
    struct mac_key src_key = {};
    __builtin_memcpy(src_key.addr, eth->h_source, 6);

    rule = (gen == 0) ? bpf_map_lookup_elem(&l2_src_mac_0, &src_key)
                      : bpf_map_lookup_elem(&l2_src_mac_1, &src_key);
    if (rule) {
        BPF_DBG("L2: src_mac match, rule %d", rule->rule_id);
        return handle_l2_action(ctx, meta, rule);
    }

    /* ── 2. Destination MAC lookup ─────────────────────────── */
    struct mac_key dst_key = {};
    __builtin_memcpy(dst_key.addr, eth->h_dest, 6);

    rule = (gen == 0) ? bpf_map_lookup_elem(&l2_dst_mac_0, &dst_key)
                      : bpf_map_lookup_elem(&l2_dst_mac_1, &dst_key);
    if (rule) {
        BPF_DBG("L2: dst_mac match, rule %d", rule->rule_id);
        return handle_l2_action(ctx, meta, rule);
    }

    /* ── 3. EtherType lookup ───────────────────────────────── */
    __u16 eth_proto = eth->h_proto;  /* network byte order */
    __u16 vlan_id = 0;

    /* Parse 802.1Q if present — use inner ethertype for matching */
    if (eth_proto == bpf_htons(0x8100)) {
        /* Need 4 extra bytes for VLAN TCI + inner ethertype */
        if ((void *)((unsigned char *)eth + 14 + 4) > data_end) {
            STAT_INC(STAT_DROP_L2_BOUNDS);
            return XDP_DROP;
        }
        __u16 *vlan_tci = (__u16 *)((unsigned char *)eth + 14);
        vlan_id = bpf_ntohs(*vlan_tci) & 0x0FFF;
        eth_proto = *(__u16 *)((unsigned char *)eth + 16);  /* inner ethertype, NBO */
    }

    struct ethertype_key ekey = { .ethertype = eth_proto };

    rule = (gen == 0) ? bpf_map_lookup_elem(&l2_ethertype_0, &ekey)
                      : bpf_map_lookup_elem(&l2_ethertype_1, &ekey);
    if (rule) {
        BPF_DBG("L2: ethertype match 0x%x, rule %d",
                 bpf_ntohs(eth_proto), rule->rule_id);
        return handle_l2_action(ctx, meta, rule);
    }

    /* ── 4. VLAN ID lookup ─────────────────────────────────── */
    if (vlan_id) {
        struct vlan_key vkey = { .vlan_id = vlan_id };

        rule = (gen == 0) ? bpf_map_lookup_elem(&l2_vlan_0, &vkey)
                          : bpf_map_lookup_elem(&l2_vlan_1, &vkey);
        if (rule) {
            BPF_DBG("L2: vlan %d match, rule %d", vlan_id, rule->rule_id);
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
