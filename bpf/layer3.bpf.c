// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "maps.h"

/*
 * Layer 3: IP subnet and VRF filtering.
 *
 * 1. Parse IP header, lookup src_ip in LPM trie.
 * 2. If matched, execute the rule action:
 *    - ALLOW: pass to Layer 4
 *    - REDIRECT: redirect to another ifindex (VRF)
 *    - MIRROR: set deferred flag for TC, pass to Layer 4
 *    - DROP: drop
 * 3. If no subnet match, check VRF rules.
 * 4. If no match at all, proceed to Layer 4 (if present),
 *    otherwise apply default action.
 */

/*
 * Default-action helpers take `gen` by value, not `struct pkt_meta *meta`.
 * Reason: their only callers in the "no L4 program installed" tail are
 * reached AFTER a bpf_tail_call. The kernel ≥6.8 verifier marks
 * data_meta-derived pointers as scalar after that call, so reading
 * meta->generation across the boundary fails with
 *   "R8 invalid mem access 'scalar'"
 * Caching gen before the tail_call sidesteps that — the value lives in a
 * spilled stack slot the verifier still trusts.
 */
static __always_inline int get_default_action(__u32 gen, __u32 pkt_len)
{
    __u32 key = 0;
    __u32 *def = NULL;

    if (gen == 0)
        def = bpf_map_lookup_elem(&default_action_0, &key);
    else
        def = bpf_map_lookup_elem(&default_action_1, &key);

    if (!def || *def == ACT_DROP) {
        STAT_COUNT(STAT_DROP_L3_DEFAULT, pkt_len);
        return XDP_DROP;
    }
    STAT_COUNT(STAT_PASS_L3, pkt_len);
    return XDP_PASS;
}

static __always_inline int get_default_action_v6(__u32 gen, __u32 pkt_len)
{
    __u32 key = 0;
    __u32 *def = NULL;

    if (gen == 0)
        def = bpf_map_lookup_elem(&default_action_0, &key);
    else
        def = bpf_map_lookup_elem(&default_action_1, &key);

    if (!def || *def == ACT_DROP) {
        STAT_COUNT(STAT_DROP_L3_V6_DEFAULT, pkt_len);
        return XDP_DROP;
    }
    STAT_COUNT(STAT_PASS_L3_V6, pkt_len);
    return XDP_PASS;
}

static __always_inline int handle_l3_action(struct xdp_md *ctx,
                                            struct pkt_meta *meta,
                                            struct l3_rule *rule,
                                            __u32 pkt_len)
{
    switch (rule->action) {
    case ACT_ALLOW:
        break;

    case ACT_DROP:
        STAT_COUNT(STAT_DROP_L3_RULE, pkt_len);
        BPF_DBG("L3: rule %d → DROP", rule->rule_id);
        return XDP_DROP;

    case ACT_REDIRECT:
        if (rule->redirect_ifindex) {
            STAT_COUNT(STAT_REDIRECT, pkt_len);
            BPF_DBG("L3: rule %d → REDIRECT ifindex=%d", rule->rule_id, rule->redirect_ifindex);
            return bpf_redirect(rule->redirect_ifindex, 0);
        }
        STAT_COUNT(STAT_DROP_L3_REDIRECT_FAIL, pkt_len);
        BPF_DBG("L3: rule %d → REDIRECT with ifindex=0", rule->rule_id);
        return XDP_DROP;

    case ACT_MIRROR:
        /*
         * XDP cannot clone packets. Set a flag in metadata
         * for TC ingress to perform bpf_clone_redirect().
         * The packet continues through the pipeline.
         */
        meta->action_flags |= (1 << ACT_MIRROR);
        meta->mirror_ifindex = rule->mirror_ifindex;
        STAT_COUNT(STAT_MIRROR, pkt_len);
        BPF_DBG("L3: rule %d → MIRROR ifindex=%d", rule->rule_id, rule->mirror_ifindex);
        break;

    default:
        STAT_COUNT(STAT_DROP_L3_RULE, pkt_len);
        return XDP_DROP;
    }

    /* Proceed to Layer 4 if configured */
    if (rule->has_next_layer) {
        __u32 gen = meta->generation;  /* cache before tail_call invalidates meta */
        if (gen == 0)
            bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
        else
            bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);
        /* Tail call failed */
        STAT_INC(STAT_DROP_L3_TAIL);
        BPF_DBG("L3: tail call to L4 failed, gen=%d", gen);
        return XDP_DROP;
    }

    STAT_COUNT(STAT_PASS_L3, pkt_len);
    return XDP_PASS;
}

/* IPv6 variant — identical logic but uses v6-specific stat counters */
static __always_inline int handle_l3_action_v6(struct xdp_md *ctx,
                                               struct pkt_meta *meta,
                                               struct l3_rule *rule,
                                               __u32 pkt_len)
{
    switch (rule->action) {
    case ACT_ALLOW:
        break;

    case ACT_DROP:
        STAT_COUNT(STAT_DROP_L3_V6_RULE, pkt_len);
        BPF_DBG("L3v6: rule %d → DROP", rule->rule_id);
        return XDP_DROP;

    case ACT_REDIRECT:
        if (rule->redirect_ifindex) {
            STAT_COUNT(STAT_REDIRECT, pkt_len);
            BPF_DBG("L3v6: rule %d → REDIRECT ifindex=%d", rule->rule_id, rule->redirect_ifindex);
            return bpf_redirect(rule->redirect_ifindex, 0);
        }
        STAT_COUNT(STAT_DROP_L3_REDIRECT_FAIL, pkt_len);
        BPF_DBG("L3v6: rule %d → REDIRECT with ifindex=0", rule->rule_id);
        return XDP_DROP;

    case ACT_MIRROR:
        meta->action_flags |= (1 << ACT_MIRROR);
        meta->mirror_ifindex = rule->mirror_ifindex;
        STAT_COUNT(STAT_MIRROR, pkt_len);
        BPF_DBG("L3v6: rule %d → MIRROR ifindex=%d", rule->rule_id, rule->mirror_ifindex);
        break;

    default:
        STAT_COUNT(STAT_DROP_L3_V6_RULE, pkt_len);
        return XDP_DROP;
    }

    if (rule->has_next_layer) {
        __u32 gen = meta->generation;
        if (gen == 0)
            bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
        else
            bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);
        STAT_INC(STAT_DROP_L3_TAIL);
        BPF_DBG("L3v6: tail call to L4 failed, gen=%d", gen);
        return XDP_DROP;
    }

    STAT_COUNT(STAT_PASS_L3_V6, pkt_len);
    return XDP_PASS;
}

SEC("xdp")
int layer3_prog(struct xdp_md *ctx)
{
    unsigned char *data     = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
    __u32 pkt_len = (__u32)(data_end - data);

    /* Skip Ethernet header */
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((unsigned char *)(eth + 1) > data_end) {
        STAT_INC(STAT_DROP_L3_BOUNDS);
        return XDP_DROP;
    }

    /* Read metadata from data_meta area (common for v4/v6) */
    void *data_meta = (void *)(long)ctx->data_meta;
    struct pkt_meta *meta = data_meta;
    if ((void *)(meta + 1) > (void *)data) {
        STAT_INC(STAT_DROP_L3_NO_META);
        return XDP_DROP;
    }

    __u16 eth_proto = eth->h_proto;

    /* ── IPv6 path ─────────────────────────────────────────── */
    if (eth_proto == bpf_htons(0x86DD)) { /* ETH_P_IPV6 */
        meta->ip_family = IP_FAMILY_V6;

        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((unsigned char *)(ip6h + 1) > data_end) {
            STAT_INC(STAT_DROP_L3_BOUNDS);
            return XDP_DROP;
        }

        /*
         * Walk up to 4 extension headers looking for Fragment (44). Closes
         * P1#8: previously L3 only checked the immediate nexthdr, so a
         * Hop-by-Hop → Fragment chain hid the Fragment from L3 and let
         * non-first fragments reach L4 (or a terminal-ALLOW L3 rule).
         * Fail-closed on chains too deep — drops with STAT_DROP_L3_V6_EXT_DEPTH.
         */
        unsigned char *cursor = (unsigned char *)(ip6h + 1);
        __u8 nhdr = ip6h->nexthdr;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if (nhdr == 44) {
                STAT_INC(STAT_DROP_L3_V6_FRAGMENT);
                BPF_DBG("L3v6: fragment header detected at depth %d, dropping", i);
                return XDP_DROP;
            }
            if (nhdr != 0 && nhdr != 43 && nhdr != 60)
                break;
            if (cursor + 2 > data_end) {
                STAT_INC(STAT_DROP_L3_BOUNDS);
                return XDP_DROP;
            }
            __u8 next = *cursor;
            __u8 hlen = *(cursor + 1);
            __u32 ext_len = ((__u32)hlen + 1) * 8;
            cursor += ext_len;
            if (cursor > data_end) {
                STAT_INC(STAT_DROP_L3_BOUNDS);
                return XDP_DROP;
            }
            nhdr = next;
        }
        if (nhdr == 0 || nhdr == 43 || nhdr == 60) {
            STAT_INC(STAT_DROP_L3_V6_EXT_DEPTH);
            BPF_DBG("L3v6: ext-header chain >4, fail-closed drop");
            return XDP_DROP;
        }

        /* LPM trie lookup on IPv6 source address */
        struct lpm_v6_key lpm6_key = { .prefixlen = 128 };
        __builtin_memcpy(lpm6_key.addr, &ip6h->saddr, 16);

        struct l3_rule *rule6 = NULL;
        if (meta->generation == 0)
            rule6 = bpf_map_lookup_elem(&subnet6_rules_0, &lpm6_key);
        else
            rule6 = bpf_map_lookup_elem(&subnet6_rules_1, &lpm6_key);

        if (rule6)
            return handle_l3_action_v6(ctx, meta, rule6, pkt_len);

        /* dst_ip6 LPM — try the destination address against the dst map */
        struct lpm_v6_key lpm6_dkey = { .prefixlen = 128 };
        __builtin_memcpy(lpm6_dkey.addr, &ip6h->daddr, 16);

        struct l3_rule *drule6 = NULL;
        if (meta->generation == 0)
            drule6 = bpf_map_lookup_elem(&subnet6_rules_dst_0, &lpm6_dkey);
        else
            drule6 = bpf_map_lookup_elem(&subnet6_rules_dst_1, &lpm6_dkey);

        if (drule6)
            return handle_l3_action_v6(ctx, meta, drule6, pkt_len);

        /* VRF fallback */
        struct vrf_key vkey6 = { .ifindex = ctx->ingress_ifindex };
        struct l3_rule *vrule6 = NULL;
        if (meta->generation == 0)
            vrule6 = bpf_map_lookup_elem(&vrf_rules_0, &vkey6);
        else
            vrule6 = bpf_map_lookup_elem(&vrf_rules_1, &vkey6);

        if (vrule6)
            return handle_l3_action_v6(ctx, meta, vrule6, pkt_len);

        /*
         * No match — try Layer 4, fall back to default. Cache gen before
         * tail_call so the fall-through arm doesn't dereference an
         * invalidated meta (see get_default_action_v6 comment above).
         */
        __u32 gen = meta->generation;
        if (gen == 0)
            bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
        else
            bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);

        return get_default_action_v6(gen, pkt_len);
    }

    /* ── IPv4 path ─────────────────────────────────────────── */
    if (eth_proto != bpf_htons(0x0800)) { /* ETH_P_IP */
        STAT_INC(STAT_DROP_L3_NOT_IPV4);
        return XDP_DROP;
    }
    meta->ip_family = IP_FAMILY_V4;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((unsigned char *)(iph + 1) > data_end) {
        STAT_INC(STAT_DROP_L3_BOUNDS);
        return XDP_DROP;
    }

    /* Drop non-first IP fragments — they lack L4 headers */
    if (bpf_ntohs(iph->frag_off) & 0x1FFF) {
        STAT_INC(STAT_DROP_L3_FRAGMENT);
        BPF_DBG("L3: IP fragment (offset=%d), dropping", bpf_ntohs(iph->frag_off) & 0x1FFF);
        return XDP_DROP;
    }

    /* LPM trie lookup on source IP */
    struct lpm_v4_key lpm_key = {
        .prefixlen = 32,
        .addr      = iph->saddr,  /* already network byte order */
    };

    struct l3_rule *rule = NULL;
    if (meta->generation == 0)
        rule = bpf_map_lookup_elem(&subnet_rules_0, &lpm_key);
    else
        rule = bpf_map_lookup_elem(&subnet_rules_1, &lpm_key);

    if (rule)
        return handle_l3_action(ctx, meta, rule, pkt_len);

    /* dst_ip LPM — try the destination address against the dst map.
     * Source matches win over destination matches when both apply; this
     * matches operator intuition ("rule A is keyed on who sent it,
     * rule B is keyed on who it's going to, A fires first"). */
    struct lpm_v4_key lpm_dkey = {
        .prefixlen = 32,
        .addr      = iph->daddr,
    };

    struct l3_rule *drule = NULL;
    if (meta->generation == 0)
        drule = bpf_map_lookup_elem(&subnet_rules_dst_0, &lpm_dkey);
    else
        drule = bpf_map_lookup_elem(&subnet_rules_dst_1, &lpm_dkey);

    if (drule)
        return handle_l3_action(ctx, meta, drule, pkt_len);

    /* No subnet match — check VRF rules */
    struct vrf_key vkey = { .ifindex = ctx->ingress_ifindex };

    struct l3_rule *vrule = NULL;
    if (meta->generation == 0)
        vrule = bpf_map_lookup_elem(&vrf_rules_0, &vkey);
    else
        vrule = bpf_map_lookup_elem(&vrf_rules_1, &vkey);

    if (vrule)
        return handle_l3_action(ctx, meta, vrule, pkt_len);

    /*
     * No match — try Layer 4, fall back to default action. Cache gen
     * before tail_call (kernel ≥6.8 verifier invalidates meta after).
     */
    __u32 gen = meta->generation;
    if (gen == 0)
        bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
    else
        bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);

    /* Tail call failed (no L4 program) — apply default action */
    return get_default_action(gen, pkt_len);
}

char LICENSE[] SEC("license") = "GPL";
