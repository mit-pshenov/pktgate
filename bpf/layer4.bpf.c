// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "maps.h"

/*
 * Layer 4: Transport-layer filtering.
 *
 * Matches protocol + destination port against l4_rules map.
 * Actions:
 *   TAG        — set DSCP in metadata (TC will rewrite header)
 *   RATE_LIMIT — per-CPU token bucket
 *   ALLOW/DROP — terminal
 *
 * If no L4 rule matches, applies the default action from gen_default map.
 */

static __always_inline int do_rate_limit(struct l4_rule *rule, __u32 pkt_len)
{
    __u32 rid = rule->rule_id;

    struct rate_state *rs = bpf_map_lookup_elem(&rate_state_map, &rid);
    if (!rs) {
        /* First packet for this rule — initialize with BPF_ANY to handle race */
        struct rate_state init = {
            .tokens     = rule->rate_bps / 8,
            .last_refill = bpf_ktime_get_ns(),
            .rate_bps   = rule->rate_bps,
        };
        bpf_map_update_elem(&rate_state_map, &rid, &init, BPF_ANY);
        STAT_INC(STAT_RATE_LIMIT_PASS);
        return XDP_PASS;
    }

    /* Refill tokens based on elapsed time */
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed_ns = now - rs->last_refill;
    __u64 rate_bytes_per_sec = rs->rate_bps / 8;

    /*
     * Refill calculation avoiding overflow:
     * refill = elapsed_ns * rate_bytes_per_sec / 1e9
     * Split into: (elapsed_ns / 1000) * (rate_bytes_per_sec / 1000) / 1000
     * This gives microsecond precision while avoiding 64-bit overflow
     * for rates up to ~18 Tbps.
     *
     * Cap elapsed time to 1 second — tokens are capped at 1s burst
     * anyway, so longer idle periods just fill the bucket.
     */
    if (elapsed_ns > 1000000000ULL)
        elapsed_ns = 1000000000ULL;

    __u64 elapsed_us = elapsed_ns / 1000;
    __u64 rate_kbytes = rate_bytes_per_sec / 1000;
    __u64 refill = elapsed_us * rate_kbytes / 1000000;

    rs->tokens += refill;

    /* Cap tokens at 1 second burst */
    if (rs->tokens > rate_bytes_per_sec)
        rs->tokens = rate_bytes_per_sec;

    rs->last_refill = now;

    /* Consume tokens */
    if (rs->tokens >= pkt_len) {
        rs->tokens -= pkt_len;
        STAT_INC(STAT_RATE_LIMIT_PASS);
        return XDP_PASS;
    }

    /* Over limit — drop */
    STAT_INC(STAT_DROP_L4_RATE_LIMIT);
    BPF_DBG("L4: rate limit DROP rule=%d tokens=%llu pkt=%d", rid, rs->tokens, pkt_len);
    return XDP_DROP;
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
        STAT_INC(STAT_DROP_L4_DEFAULT);
        return XDP_DROP;
    }
    STAT_INC(STAT_PASS_L4);
    return XDP_PASS;
}

SEC("xdp")
int layer4_prog(struct xdp_md *ctx)
{
    unsigned char *data     = (unsigned char *)(long)ctx->data;
    unsigned char *data_end = (unsigned char *)(long)ctx->data_end;

    /* Parse Ethernet */
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((unsigned char *)(eth + 1) > data_end) {
        STAT_INC(STAT_DROP_L4_BOUNDS);
        return XDP_DROP;
    }

    __u8 proto = 0;
    __u16 dst_port = 0;
    unsigned char *l4 = NULL;

    if (eth->h_proto == bpf_htons(0x0800)) {
        /* ── IPv4 ────────────────────────────────────────── */
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((unsigned char *)(iph + 1) > data_end) {
            STAT_INC(STAT_DROP_L4_BOUNDS);
            return XDP_DROP;
        }

        if (iph->ihl < 5) {
            STAT_INC(STAT_DROP_L4_BOUNDS);
            return XDP_DROP;
        }

        proto = iph->protocol;
        __u32 ip_hdr_len = (__u32)iph->ihl * 4;
        l4 = (unsigned char *)iph + ip_hdr_len;

        if (l4 > data_end) {
            STAT_INC(STAT_DROP_L4_BOUNDS);
            return XDP_DROP;
        }
    } else if (eth->h_proto == bpf_htons(0x86DD)) {
        /* ── IPv6 ────────────────────────────────────────── */
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((unsigned char *)(ip6h + 1) > data_end) {
            STAT_INC(STAT_DROP_L4_BOUNDS);
            return XDP_DROP;
        }

        /*
         * Use nexthdr directly — extension header chasing
         * is complex in BPF; for now handle TCP/UDP only
         * when they are the immediate next header.
         */
        proto = ip6h->nexthdr;
        l4 = (unsigned char *)(ip6h + 1);
    } else {
        STAT_INC(STAT_DROP_L4_NOT_IPV4);
        return XDP_DROP;
    }

    if (proto == 6) { /* TCP */
        struct tcphdr *tcp = (struct tcphdr *)l4;
        if ((unsigned char *)(tcp + 1) > data_end) {
            STAT_INC(STAT_DROP_L4_BOUNDS);
            return XDP_DROP;
        }
        dst_port = bpf_ntohs(tcp->dest);
    } else if (proto == 17) { /* UDP */
        struct udphdr *udp = (struct udphdr *)l4;
        if ((unsigned char *)(udp + 1) > data_end) {
            STAT_INC(STAT_DROP_L4_BOUNDS);
            return XDP_DROP;
        }
        dst_port = bpf_ntohs(udp->dest);
    } else {
        /* Non TCP/UDP — no L4 rules apply */
        void *dm = (void *)(long)ctx->data_meta;
        struct pkt_meta *m = dm;
        if ((void *)(m + 1) > (void *)data) {
            STAT_INC(STAT_DROP_L4_NO_META);
            return XDP_DROP;
        }
        return get_default_action(m);
    }

    /* Read metadata from data_meta area */
    void *data_meta = (void *)(long)ctx->data_meta;
    struct pkt_meta *meta = data_meta;
    if ((void *)(meta + 1) > (void *)data) {
        STAT_INC(STAT_DROP_L4_NO_META);
        return XDP_DROP;
    }

    /* Lookup L4 rule */
    struct l4_match_key mkey = {
        .protocol = proto,
        .dst_port = dst_port,
    };

    struct l4_rule *rule = NULL;
    if (meta->generation == 0)
        rule = bpf_map_lookup_elem(&l4_rules_0, &mkey);
    else
        rule = bpf_map_lookup_elem(&l4_rules_1, &mkey);

    if (!rule)
        return get_default_action(meta);

    switch (rule->action) {
    case ACT_ALLOW:
        STAT_INC(STAT_PASS_L4);
        BPF_DBG("L4: rule %d proto=%d port=%d → ALLOW", rule->rule_id, proto, dst_port);
        return XDP_PASS;

    case ACT_DROP:
        STAT_INC(STAT_DROP_L4_RULE);
        BPF_DBG("L4: rule %d proto=%d port=%d → DROP", rule->rule_id, proto, dst_port);
        return XDP_DROP;

    case ACT_TAG:
        meta->action_flags |= (1 << ACT_TAG);
        meta->dscp = rule->dscp;
        meta->cos  = rule->cos;
        STAT_INC(STAT_TAG);
        BPF_DBG("L4: rule %d → TAG dscp=%d", rule->rule_id, rule->dscp);
        return XDP_PASS;

    case ACT_RATE_LIMIT: {
        __u32 pkt_len = (__u32)(data_end - data);
        return do_rate_limit(rule, pkt_len);
    }

    default:
        STAT_INC(STAT_DROP_L4_RULE);
        return XDP_DROP;
    }
}

char LICENSE[] SEC("license") = "GPL";
