// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "maps.h"

/*
 * Layer 2: Ethernet source MAC filtering.
 * Looks up src_mac in the generation-specific mac_allow map.
 * If found → tail call to Layer 3.
 * If not found → DROP.
 */
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

    /* Build MAC key from source address */
    struct mac_key mkey = {};
    __builtin_memcpy(mkey.addr, eth->h_source, 6);

    /* Read generation from data_meta area */
    void *data_meta = (void *)(long)ctx->data_meta;
    struct pkt_meta *meta = data_meta;
    if ((void *)(meta + 1) > data) {
        STAT_INC(STAT_DROP_L2_NO_META);
        return XDP_DROP;
    }

    /* Lookup in generation-specific MAC map */
    __u32 *allowed = NULL;
    if (meta->generation == 0)
        allowed = bpf_map_lookup_elem(&mac_allow_0, &mkey);
    else
        allowed = bpf_map_lookup_elem(&mac_allow_1, &mkey);

    if (!allowed) {
        STAT_INC(STAT_DROP_L2_NO_MAC);
        BPF_DBG("L2: MAC not in allow-list, gen=%d", meta->generation);
        return XDP_DROP;
    }

    /* MAC allowed — proceed to Layer 3 */
    if (meta->generation == 0)
        bpf_tail_call(ctx, &prog_array_0, LAYER_3_IDX);
    else
        bpf_tail_call(ctx, &prog_array_1, LAYER_3_IDX);

    STAT_INC(STAT_DROP_L2_TAIL);
    BPF_DBG("L2: tail call to L3 failed, gen=%d", meta->generation);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
