// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"  /* BPF_DBG macro */

/* TC action return codes (not in vmlinux.h) */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/*
 * TC ingress companion program.
 *
 * Runs after the XDP pipeline. Reads deferred action flags set by
 * XDP layers in the packet's data_meta area and executes actions
 * that require skb context (not available in XDP):
 *
 *   - ACT_MIRROR: bpf_clone_redirect() to mirror_ifindex
 *   - ACT_TAG:    rewrite IP header DSCP field
 *
 * Returns TC_ACT_OK to pass the packet up the stack.
 */

/* ── Maps used by TC ──────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_STATS);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

#define STAT_INC(stat_key_val) do {                    \
    __u32 _sk = (stat_key_val);                        \
    __u64 *_cnt = bpf_map_lookup_elem(&stats_map, &_sk); \
    if (_cnt) (*_cnt)++;                               \
} while (0)

SEC("tc")
int tc_ingress_prog(struct __sk_buff *skb)
{
    void *data      = (void *)(long)skb->data;
    void *data_meta = (void *)(long)skb->data_meta;

    struct pkt_meta *meta = data_meta;
    if ((void *)(meta + 1) > data) {
        /* No XDP metadata present — nothing to do */
        STAT_INC(STAT_TC_NOOP);
        return TC_ACT_OK;
    }

    __u32 flags = meta->action_flags;
    if (flags == 0) {
        STAT_INC(STAT_TC_NOOP);
        return TC_ACT_OK;
    }

    /*
     * Cache metadata fields in local variables BEFORE calling any skb helper.
     * Helpers that take struct __sk_buff * (bpf_clone_redirect, bpf_skb_load_bytes)
     * cause the verifier to invalidate all packet/data_meta pointers, because the
     * packet buffer may be reallocated.  Reading from meta after such a call would
     * fail verification with "R7 invalid mem access 'scalar'".
     */
    __u32 mirror_ifindex = meta->mirror_ifindex;
    __u8  dscp           = meta->dscp;

    /* ── Mirror: clone packet to mirror_ifindex ─────────────── */
    if (flags & (1 << ACT_MIRROR)) {
        if (mirror_ifindex) {
            long ret = bpf_clone_redirect(skb, mirror_ifindex, 0);
            if (ret == 0) {
                STAT_INC(STAT_TC_MIRROR);
                BPF_DBG("TC: mirror to ifindex=%d OK", mirror_ifindex);
            } else {
                STAT_INC(STAT_TC_MIRROR_FAIL);
                BPF_DBG("TC: mirror to ifindex=%d FAILED ret=%ld", mirror_ifindex, ret);
            }
        }
    }

    /* ── Tag: rewrite DSCP field ──────────────────────────────── */
    if (flags & (1 << ACT_TAG)) {
        /*
         * Determine EtherType to select the correct header layout.
         * IPv4: TOS at byte 1, needs L3 checksum fixup.
         * IPv6: Traffic Class spans bytes 0-1 (bits 4-11), no checksum.
         */
        __u16 eth_proto;
        if (bpf_skb_load_bytes(skb, 12, &eth_proto, 2) < 0)
            goto done;

        eth_proto = bpf_ntohs(eth_proto);

        if (eth_proto == 0x0800) {
            /* ── IPv4: TOS at offset 15 ─────────────────────── */
            __u8 old_tos;
            if (bpf_skb_load_bytes(skb, 14 + 1, &old_tos, 1) == 0) {
                /* DSCP occupies bits 7:2, ECN occupies bits 1:0 */
                __u8 new_tos = (dscp << 2) | (old_tos & 0x03);
                if (new_tos != old_tos) {
                    bpf_skb_store_bytes(skb, 14 + 1, &new_tos, 1, 0);
                    /*
                     * Fix up IP header checksum after TOS modification.
                     * bpf_skb_store_bytes with BPF_F_RECOMPUTE_CSUM only updates
                     * skb->csum (L4), NOT the IP header checksum field itself.
                     * Use bpf_l3_csum_replace to do an incremental L3 checksum update.
                     * IP checksum is at offset 10 in the IP header (= byte 24 from frame start).
                     */
                    bpf_l3_csum_replace(skb, 14 + 10,
                                        bpf_htons((__u16)old_tos),
                                        bpf_htons((__u16)new_tos), 2);
                    STAT_INC(STAT_TC_TAG);
                    BPF_DBG("TC: IPv4 DSCP rewrite old_tos=0x%x new_tos=0x%x", old_tos, new_tos);
                }
            }
        } else if (eth_proto == 0x86DD) {
            /* ── IPv6: Traffic Class spans bytes 0-1 of IPv6 header ── */
            /*
             * IPv6 header layout (first 4 bytes, network order):
             *   byte 0: Version(4) | TC_high(4)
             *   byte 1: TC_low(4) | Flow Label_high(4)
             *   byte 2-3: Flow Label_low(16)
             *
             * Traffic Class = (byte0 & 0x0F) << 4 | (byte1 >> 4)
             * DSCP = TC >> 2, ECN = TC & 0x03
             */
            __u8 bytes[2];
            if (bpf_skb_load_bytes(skb, 14, bytes, 2) == 0) {
                __u8 old_tc = ((bytes[0] & 0x0F) << 4) | (bytes[1] >> 4);
                __u8 new_tc = (dscp << 2) | (old_tc & 0x03);
                if (new_tc != old_tc) {
                    /* Rewrite only TC bits, preserve Version and Flow Label */
                    bytes[0] = (bytes[0] & 0xF0) | (new_tc >> 4);
                    bytes[1] = (new_tc << 4) | (bytes[1] & 0x0F);
                    bpf_skb_store_bytes(skb, 14, bytes, 2, 0);
                    /* IPv6 has no header checksum — done */
                    STAT_INC(STAT_TC_TAG);
                    BPF_DBG("TC: IPv6 DSCP rewrite old_tc=0x%x new_tc=0x%x", old_tc, new_tc);
                }
            }
        }
    }

done:
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
