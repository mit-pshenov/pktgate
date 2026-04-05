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

/* Intercept XDP_PASS when ACT_USERSPACE flag is set — redirect to AF_XDP. */
static __always_inline int maybe_redirect_xsk(struct xdp_md *ctx,
                                               struct pkt_meta *meta,
                                               int fallback)
{
    if (meta->action_flags & (1 << ACT_USERSPACE)) {
        int ret = bpf_redirect_map(&xsks_map, ctx->rx_queue_index, fallback);
        if (ret != XDP_REDIRECT) {
            STAT_INC(STAT_USERSPACE_FAIL);
            return ret;
        }
        STAT_INC(STAT_USERSPACE);
        return ret;
    }
    return fallback;
}

static __always_inline int get_default_action(struct pkt_meta *meta)
{
    __u32 key = 0;
    __u32 *def = NULL;

    if (meta->generation == 0)
        def = bpf_map_lookup_elem(&default_action_0, &key);
    else
        def = bpf_map_lookup_elem(&default_action_1, &key);

    if (!def || *def == ACT_DROP) {
        STAT_INC(STAT_DROP_L3_DEFAULT);
        return XDP_DROP;
    }
    STAT_INC(STAT_PASS_L3);
    return XDP_PASS;
}

static __always_inline int get_default_action_v6(struct pkt_meta *meta)
{
    __u32 key = 0;
    __u32 *def = NULL;

    if (meta->generation == 0)
        def = bpf_map_lookup_elem(&default_action_0, &key);
    else
        def = bpf_map_lookup_elem(&default_action_1, &key);

    if (!def || *def == ACT_DROP) {
        STAT_INC(STAT_DROP_L3_V6_DEFAULT);
        return XDP_DROP;
    }
    STAT_INC(STAT_PASS_L3_V6);
    return XDP_PASS;
}

static __always_inline int handle_l3_action(struct xdp_md *ctx,
                                            struct pkt_meta *meta,
                                            struct l3_rule *rule)
{
    switch (rule->action) {
    case ACT_ALLOW:
        break;

    case ACT_DROP:
        STAT_INC(STAT_DROP_L3_RULE);
        BPF_DBG("L3: rule %d → DROP", rule->rule_id);
        return XDP_DROP;

    case ACT_REDIRECT:
        if (rule->redirect_ifindex) {
            STAT_INC(STAT_REDIRECT);
            BPF_DBG("L3: rule %d → REDIRECT ifindex=%d", rule->rule_id, rule->redirect_ifindex);
            return bpf_redirect(rule->redirect_ifindex, 0);
        }
        STAT_INC(STAT_DROP_L3_REDIRECT_FAIL);
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
        STAT_INC(STAT_MIRROR);
        BPF_DBG("L3: rule %d → MIRROR ifindex=%d", rule->rule_id, rule->mirror_ifindex);
        break;

    case ACT_USERSPACE:
        /* Set flag for L4 interception or terminal redirect. */
        meta->action_flags |= (1 << ACT_USERSPACE);
        BPF_DBG("L3: rule %d → USERSPACE", rule->rule_id);
        break;

    default:
        STAT_INC(STAT_DROP_L3_RULE);
        return XDP_DROP;
    }

    /* Proceed to Layer 4 if configured */
    if (rule->has_next_layer) {
        if (meta->generation == 0)
            bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
        else
            bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);
        /* Tail call failed */
        STAT_INC(STAT_DROP_L3_TAIL);
        BPF_DBG("L3: tail call to L4 failed, gen=%d", meta->generation);
        return XDP_DROP;
    }

    STAT_INC(STAT_PASS_L3);
    return maybe_redirect_xsk(ctx, meta, XDP_PASS);
}

/* IPv6 variant — identical logic but uses v6-specific stat counters */
static __always_inline int handle_l3_action_v6(struct xdp_md *ctx,
                                               struct pkt_meta *meta,
                                               struct l3_rule *rule)
{
    switch (rule->action) {
    case ACT_ALLOW:
        break;

    case ACT_DROP:
        STAT_INC(STAT_DROP_L3_V6_RULE);
        BPF_DBG("L3v6: rule %d → DROP", rule->rule_id);
        return XDP_DROP;

    case ACT_REDIRECT:
        if (rule->redirect_ifindex) {
            STAT_INC(STAT_REDIRECT);
            BPF_DBG("L3v6: rule %d → REDIRECT ifindex=%d", rule->rule_id, rule->redirect_ifindex);
            return bpf_redirect(rule->redirect_ifindex, 0);
        }
        STAT_INC(STAT_DROP_L3_REDIRECT_FAIL);
        BPF_DBG("L3v6: rule %d → REDIRECT with ifindex=0", rule->rule_id);
        return XDP_DROP;

    case ACT_MIRROR:
        meta->action_flags |= (1 << ACT_MIRROR);
        meta->mirror_ifindex = rule->mirror_ifindex;
        STAT_INC(STAT_MIRROR);
        BPF_DBG("L3v6: rule %d → MIRROR ifindex=%d", rule->rule_id, rule->mirror_ifindex);
        break;

    case ACT_USERSPACE:
        meta->action_flags |= (1 << ACT_USERSPACE);
        BPF_DBG("L3v6: rule %d → USERSPACE", rule->rule_id);
        break;

    default:
        STAT_INC(STAT_DROP_L3_V6_RULE);
        return XDP_DROP;
    }

    if (rule->has_next_layer) {
        if (meta->generation == 0)
            bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
        else
            bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);
        STAT_INC(STAT_DROP_L3_TAIL);
        BPF_DBG("L3v6: tail call to L4 failed, gen=%d", meta->generation);
        return XDP_DROP;
    }

    STAT_INC(STAT_PASS_L3_V6);
    return maybe_redirect_xsk(ctx, meta, XDP_PASS);
}

SEC("xdp")
int layer3_prog(struct xdp_md *ctx)
{
    unsigned char *data     = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;

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
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((unsigned char *)(ip6h + 1) > data_end) {
            STAT_INC(STAT_DROP_L3_BOUNDS);
            return XDP_DROP;
        }

        /*
         * Drop IPv6 fragments — nexthdr 44 is the Fragment Header.
         * Walk up to 4 extension headers to catch Fragment headers
         * hidden behind Hop-by-Hop (0), Routing (43), Destination (60).
         * Fragmented IPv6 packets lack reliable L4 headers beyond
         * the first fragment, same rationale as IPv4 frag_off check.
         */
        {
            __u8 nhdr = ip6h->nexthdr;
            unsigned char *cursor = (unsigned char *)(ip6h + 1);

            #pragma unroll
            for (int i = 0; i < 4; i++) {
                if (nhdr == 44) {
                    STAT_INC(STAT_DROP_L3_V6_FRAGMENT);
                    BPF_DBG("L3v6: fragment header detected (depth=%d), dropping", i);
                    return XDP_DROP;
                }
                /* Only skip known extension headers */
                if (nhdr != 0 && nhdr != 43 && nhdr != 60)
                    break;
                /* Read next header + length fields */
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
            /* Final check after loop exits (e.g. fragment at depth 4) */
            if (nhdr == 44) {
                STAT_INC(STAT_DROP_L3_V6_FRAGMENT);
                BPF_DBG("L3v6: fragment header detected after ext walk, dropping");
                return XDP_DROP;
            }
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
            return handle_l3_action_v6(ctx, meta, rule6);

        /* VRF fallback */
        struct vrf_key vkey6 = { .ifindex = ctx->ingress_ifindex };
        struct l3_rule *vrule6 = NULL;
        if (meta->generation == 0)
            vrule6 = bpf_map_lookup_elem(&vrf_rules_0, &vkey6);
        else
            vrule6 = bpf_map_lookup_elem(&vrf_rules_1, &vkey6);

        if (vrule6)
            return handle_l3_action_v6(ctx, meta, vrule6);

        /* No match — try Layer 4, fall back to default */
        if (meta->generation == 0)
            bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
        else
            bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);

        return get_default_action_v6(meta);
    }

    /* ── IPv4 path ─────────────────────────────────────────── */
    if (eth_proto != bpf_htons(0x0800)) { /* ETH_P_IP */
        STAT_INC(STAT_DROP_L3_NOT_IPV4);
        return XDP_DROP;
    }

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
        return handle_l3_action(ctx, meta, rule);

    /* No subnet match — check VRF rules */
    struct vrf_key vkey = { .ifindex = ctx->ingress_ifindex };

    struct l3_rule *vrule = NULL;
    if (meta->generation == 0)
        vrule = bpf_map_lookup_elem(&vrf_rules_0, &vkey);
    else
        vrule = bpf_map_lookup_elem(&vrf_rules_1, &vkey);

    if (vrule)
        return handle_l3_action(ctx, meta, vrule);

    /* No match — try Layer 4, fall back to default action */
    if (meta->generation == 0)
        bpf_tail_call(ctx, &prog_array_0, LAYER_4_IDX);
    else
        bpf_tail_call(ctx, &prog_array_1, LAYER_4_IDX);

    /* Tail call failed (no L4 program) — apply default action */
    return get_default_action(meta);
}

char LICENSE[] SEC("license") = "GPL";
