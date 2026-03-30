// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "maps.h"

/*
 * Entry XDP program.
 * Reads the active generation from gen_config,
 * stores it in the XDP data_meta area,
 * and tail-calls into Layer 2 via the correct prog_array.
 */
SEC("xdp")
int entry_prog(struct xdp_md *ctx)
{
    __u32 key = 0;

    STAT_INC(STAT_PACKETS_TOTAL);

    /* Read active generation */
    __u32 *gen = bpf_map_lookup_elem(&gen_config, &key);
    if (!gen) {
        STAT_INC(STAT_DROP_NO_GEN);
        BPF_DBG("entry: gen_config lookup failed");
        return XDP_DROP;
    }

    /* Grow XDP metadata area to hold pkt_meta */
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct pkt_meta));
    if (ret) {
        STAT_INC(STAT_DROP_NO_META);
        BPF_DBG("entry: bpf_xdp_adjust_meta failed: %d", ret);
        return XDP_DROP;
    }

    /* Write metadata into data_meta area */
    void *data     = (void *)(long)ctx->data;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct pkt_meta *meta = data_meta;
    if ((void *)(meta + 1) > data) {
        STAT_INC(STAT_DROP_NO_META);
        return XDP_DROP;
    }

    __builtin_memset(meta, 0, sizeof(*meta));
    meta->generation = *gen;

    /* Tail call into Layer 2 using the correct generation's prog_array */
    if (*gen == 0)
        bpf_tail_call(ctx, &prog_array_0, LAYER_2_IDX);
    else
        bpf_tail_call(ctx, &prog_array_1, LAYER_2_IDX);

    /* Tail call failed — drop */
    STAT_INC(STAT_DROP_ENTRY_TAIL);
    BPF_DBG("entry: tail call to L2 failed, gen=%d", *gen);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
