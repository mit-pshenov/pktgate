// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "maps.h"

/*
 * Layer 2: Ethernet filtering — single-dispatch design.
 *
 * Five per-field maps collapsed to one composite hash keyed by l2_key
 * (filter_mask + projected fields). Compiler emits one entry per (rule ×
 * resolved MAC); userspace also writes l2_active_masks_{gen}[0..N], the
 * filter_mask values that appear in this generation's ruleset. Per packet
 * we iterate that array (bounded by MAX_L2_MASKS), project the parsed
 * Ethernet fields through each mask to form the lookup key, and stop on
 * first hit.
 *
 * Iteration order is most-specific first (popcount desc) so a rule
 * {src_mac, dst_mac, vlan} wins over {src_mac} on a packet matching both.
 *
 * On no match:
 *   - LAYER_PRESENT_L2 set → apply default_behavior;
 *   - bit unset → skip to L3 unchanged (L3-only configs).
 */

struct l2_packet_fields {
    __u8  src_mac[6];
    __u8  dst_mac[6];
    __u16 ethertype;       /* network byte order, inner if QinQ-on-Q */
    __u16 vlan_id;         /* host byte order, 0 if untagged */
    __u8  pcp;             /* 0 if untagged */
};

/* Parse Ethernet + optional single 802.1Q tag. Returns 0 on success,
 * -1 on bounds failure. QinQ (0x88a8) explicitly out of scope — tracked
 * as P1 #4 follow-up. */
static __always_inline int parse_l2(struct xdp_md *ctx, struct l2_packet_fields *p)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __builtin_memcpy(p->src_mac, eth->h_source, 6);
    __builtin_memcpy(p->dst_mac, eth->h_dest,   6);
    p->ethertype = eth->h_proto;  /* NBO */
    p->vlan_id   = 0;
    p->pcp       = 0;

    if (eth->h_proto == bpf_htons(0x8100)) {
        if ((void *)((unsigned char *)eth + 14 + 4) > data_end)
            return -1;
        __u16 *tci_p = (__u16 *)((unsigned char *)eth + 14);
        __u16 tci    = bpf_ntohs(*tci_p);
        p->vlan_id   = tci & 0x0FFF;
        p->pcp       = (tci >> 13) & 0x7;
        p->ethertype = *(__u16 *)((unsigned char *)eth + 16);  /* inner ethertype, NBO */
    }
    return 0;
}

/* Apply the configured default_behavior at L2 no-match. */
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

/* Project parsed packet fields through a filter_mask into an l2_key. Fields
 * not selected by the mask stay zero (matches what the compiler emits, so
 * HASH lookup hits). */
static __always_inline void build_l2_key(struct l2_key *out, __u8 mask,
                                          const struct l2_packet_fields *p)
{
    __builtin_memset(out, 0, sizeof(*out));
    out->filter_mask = mask;
    if (mask & FILTER_MASK_PCP)       out->pcp       = p->pcp;
    if (mask & FILTER_MASK_ETHERTYPE) out->ethertype = p->ethertype;
    if (mask & FILTER_MASK_VLAN)      out->vlan_id   = p->vlan_id;
    if (mask & FILTER_MASK_SRCMAC)    __builtin_memcpy(out->src_mac, p->src_mac, 6);
    if (mask & FILTER_MASK_DSTMAC)    __builtin_memcpy(out->dst_mac, p->dst_mac, 6);
}

SEC("xdp")
int layer2_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = (__u32)((unsigned char *)data_end - (unsigned char *)data);

    /* Read generation from data_meta area */
    void *data_meta = (void *)(long)ctx->data_meta;
    struct pkt_meta *meta = data_meta;
    if ((void *)(meta + 1) > data) {
        STAT_INC(STAT_DROP_L2_NO_META);
        return XDP_DROP;
    }
    __u32 gen = meta->generation;

    /* Parse Ethernet once */
    struct l2_packet_fields p;
    if (parse_l2(ctx, &p) < 0) {
        STAT_INC(STAT_DROP_L2_BOUNDS);
        return XDP_DROP;
    }

    /* Iterate active masks, most-specific first. Bounded unroll. */
    #pragma unroll
    for (__u32 i = 0; i < MAX_L2_MASKS; i++) {
        __u32 mi = i;
        __u8 *mp = (gen == 0)
            ? bpf_map_lookup_elem(&l2_active_masks_0, &mi)
            : bpf_map_lookup_elem(&l2_active_masks_1, &mi);
        if (!mp || *mp == 0)
            break;  /* end of active mask set */

        struct l2_key key;
        build_l2_key(&key, *mp, &p);

        struct l2_rule *rule = (gen == 0)
            ? bpf_map_lookup_elem(&l2_rules_0, &key)
            : bpf_map_lookup_elem(&l2_rules_1, &key);
        if (rule) {
            BPF_DBG("L2: hit mask=0x%x rule=%d", *mp, rule->rule_id);
            return handle_l2_action(ctx, meta, rule, pkt_len);
        }
    }

    /* ── No match ──────────────────────────────────────────── */
    __u32 lp_key = 0;
    __u8 *lp = (gen == 0)
        ? bpf_map_lookup_elem(&layer_present_0, &lp_key)
        : bpf_map_lookup_elem(&layer_present_1, &lp_key);
    if (lp && (*lp & LAYER_PRESENT_L2)) {
        BPF_DBG("L2: no match, applying default, gen=%d", gen);
        return get_default_action_l2(meta, pkt_len);
    }

    /* L2 empty for this generation → skip to L3 */
    if (gen == 0)
        bpf_tail_call(ctx, &prog_array_0, LAYER_3_IDX);
    else
        bpf_tail_call(ctx, &prog_array_1, LAYER_3_IDX);

    STAT_INC(STAT_DROP_L2_TAIL);
    BPF_DBG("L2: empty + L3 tail call failed, gen=%d", gen);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
