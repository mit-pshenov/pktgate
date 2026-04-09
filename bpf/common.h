#ifndef FILTER_BPF_COMMON_H
#define FILTER_BPF_COMMON_H

/*
 * Shared definitions between BPF data plane and C++ control plane.
 *
 * When included from BPF programs, __u8/__u16/__u32/__u64 come from vmlinux.h.
 * When included from userspace C++, we provide compatible typedefs.
 */
#ifndef __bpf__
/* Userspace: use linux/types.h which is what libbpf headers also use.
 * This avoids conflicting typedefs when both common.h and bpf/bpf.h
 * are included. */
#include <linux/types.h>
#endif

/* ── Constants ─────────────────────────────────────────────── */

#define MAX_GENERATIONS     2
#define MAX_LAYERS          4   /* indices 0-3 in prog_array */
#define MAX_RULES_PER_LAYER 4096
#define MAX_MAC_ENTRIES     4096
#define MAX_SUBNET_ENTRIES  16384
#define MAX_PORT_ENTRIES    4096
#define MAX_VRF_ENTRIES     256
#define MAX_RATE_ENTRIES    4096
#define MAX_ETHERTYPE_ENTRIES 64
#define MAX_VLAN_ENTRIES    4096
#define MAX_PCP_ENTRIES     8

/* Layer indices inside prog_array */
#define LAYER_2_IDX  0
#define LAYER_3_IDX  1
#define LAYER_4_IDX  2

/* Action codes — shared between BPF and userspace */
enum filter_action {
    ACT_DROP       = 0,
    ACT_ALLOW      = 1,
    ACT_MIRROR     = 2,
    ACT_REDIRECT   = 3,
    ACT_TAG        = 4,
    ACT_RATE_LIMIT = 5,
};

/* ── Map key / value structures ────────────────────────────── */

/* MAC lookup (padded to 8 bytes for alignment) */
struct mac_key {
    unsigned char addr[6];
    unsigned char _pad[2];
};

/* LPM trie key for IPv4 subnets */
struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;       /* network byte order */
};
#ifdef __bpf__
_Static_assert(sizeof(struct lpm_v4_key) == 8, "lpm_v4_key must be 8 bytes (no padding)");
#else
static_assert(sizeof(struct lpm_v4_key) == 8, "lpm_v4_key must be 8 bytes (no padding)");
#endif

/* LPM trie key for IPv6 subnets */
struct lpm_v6_key {
    __u32 prefixlen;
    __u8  addr[16];   /* network byte order */
};
#ifdef __bpf__
_Static_assert(sizeof(struct lpm_v6_key) == 20, "lpm_v6_key must be 20 bytes (no padding)");
#else
static_assert(sizeof(struct lpm_v6_key) == 20, "lpm_v6_key must be 20 bytes (no padding)");
#endif

/* Port group membership */
struct port_key {
    __u16 port;       /* host byte order */
    __u16 _pad;
};

/* VRF identification */
struct vrf_key {
    __u32 ifindex;    /* VRF device ifindex */
};

/* EtherType lookup key */
struct ethertype_key {
    __u16 ethertype;  /* network byte order */
    __u16 _pad;
};

/* VLAN ID lookup key */
struct vlan_key {
    __u16 vlan_id;    /* host byte order, 0-4095 */
    __u16 _pad;
};

/* ── Rule structures ───────────────────────────────────────── */

/* Layer 2 rule — stored as value in L2 hash maps */
/* L2 secondary filter bitmask — which extra fields to check after primary match */
#define L2_FILTER_ETHERTYPE  (1 << 0)
#define L2_FILTER_VLAN       (1 << 1)
#define L2_FILTER_PCP        (1 << 2)

struct l2_rule {
    __u32 rule_id;
    __u32 action;           /* enum filter_action */
    __u32 redirect_ifindex; /* for ACT_REDIRECT */
    __u32 mirror_ifindex;   /* for ACT_MIRROR   */
    __u8  next_layer;       /* 0=terminal, LAYER_3_IDX, LAYER_4_IDX */
    __u8  filter_mask;      /* bitmask of L2_FILTER_* secondary checks */
    __u16 filter_vlan_id;   /* host byte order, checked if FILTER_VLAN */
    __u16 filter_ethertype; /* network byte order, checked if FILTER_ETHERTYPE */
    __u8  filter_pcp;       /* 0-7, checked if FILTER_PCP */
    __u8  _pad;
};

struct pcp_key {
    __u32 pcp;  /* 0-7, stored as u32 for BPF hash map key alignment */
};

/* Layer 3 rule — stored in rules array, indexed by LPM/VRF lookup */
struct l3_rule {
    __u32 rule_id;
    __u32 action;           /* enum filter_action */
    __u32 redirect_ifindex; /* for ACT_REDIRECT */
    __u32 mirror_ifindex;   /* for ACT_MIRROR   */
    __u8  has_next_layer;   /* proceed to layer 4? */
    __u8  _pad[3];
};

/* Layer 4 rule — matched by protocol + port */
struct l4_match_key {
    __u8  protocol;   /* IPPROTO_TCP / IPPROTO_UDP */
    __u8  _pad;
    __u16 dst_port;   /* host byte order */
};

/* TCP flag bits (byte 13 of TCP header, low-order byte of flags+offset field) */
#define TCPF_FIN  0x01
#define TCPF_SYN  0x02
#define TCPF_RST  0x04
#define TCPF_PSH  0x08
#define TCPF_ACK  0x10
#define TCPF_URG  0x20
#define TCPF_ECE  0x40
#define TCPF_CWR  0x80

struct l4_rule {
    __u32 rule_id;
    __u32 action;          /* enum filter_action */
    __u8  dscp;            /* for ACT_TAG (0-63) */
    __u8  cos;             /* for ACT_TAG (0-7)  */
    __u8  tcp_flags_set;   /* TCP flags that MUST be set (0 = don't check) */
    __u8  tcp_flags_unset; /* TCP flags that MUST NOT be set */
    __u8  _pad[4];         /* explicit padding to align rate_bps at offset 16 */
    __u64 rate_bps;        /* for ACT_RATE_LIMIT */
};

/* ── Per-packet metadata (passed between tail calls via per-CPU map) ── */

struct pkt_meta {
    __u32 generation;       /* current active generation */
    __u32 action_flags;     /* bitmap of deferred actions for TC */
    __u32 redirect_ifindex; /* target ifindex for redirect */
    __u32 mirror_ifindex;   /* target ifindex for mirror */
    __u8  dscp;             /* DSCP value for tagging */
    __u8  cos;              /* CoS value for tagging */
    __u8  _pad[2];
};

/* ── Statistics counters (percpu) ──────────────────────────── */

enum stat_key {
    /* Global */
    STAT_PACKETS_TOTAL       = 0,

    /* Entry drops */
    STAT_DROP_NO_GEN         = 1,
    STAT_DROP_NO_META        = 2,
    STAT_DROP_ENTRY_TAIL     = 3,

    /* Layer 2 */
    STAT_DROP_L2_BOUNDS      = 4,
    STAT_DROP_L2_NO_META     = 5,
    STAT_DROP_L2_NO_MATCH    = 6,   /* no L2 rule matched (was NO_MAC) */
    STAT_DROP_L2_TAIL        = 7,
    STAT_DROP_L2_RULE        = 37,  /* explicit DROP action in L2 rule */
    STAT_PASS_L2             = 38,  /* L2 rule matched, pass/allow */
    STAT_DROP_L2_REDIRECT_FAIL = 39,

    /* Layer 3 */
    STAT_DROP_L3_BOUNDS      = 8,
    STAT_DROP_L3_NOT_IPV4    = 9,
    STAT_DROP_L3_NO_META     = 10,
    STAT_DROP_L3_RULE        = 11,   /* explicit DROP action in L3 rule */
    STAT_DROP_L3_DEFAULT     = 12,   /* default action = DROP */
    STAT_DROP_L3_REDIRECT_FAIL = 13,
    STAT_DROP_L3_TAIL        = 14,   /* tail_call to L4 failed */

    /* Layer 4 */
    STAT_DROP_L4_BOUNDS      = 15,
    STAT_DROP_L4_RULE        = 16,   /* explicit DROP action in L4 rule */
    STAT_DROP_L4_DEFAULT     = 17,
    STAT_DROP_L4_RATE_LIMIT  = 18,
    STAT_DROP_L4_NO_META     = 19,

    /* Success actions */
    STAT_PASS_L3             = 20,
    STAT_PASS_L4             = 21,
    STAT_REDIRECT            = 22,
    STAT_MIRROR              = 23,   /* mirror flag set, packet continues */
    STAT_TAG                 = 24,
    STAT_RATE_LIMIT_PASS     = 25,

    /* TC ingress */
    STAT_TC_MIRROR           = 26,   /* bpf_clone_redirect executed */
    STAT_TC_MIRROR_FAIL      = 27,   /* bpf_clone_redirect failed */
    STAT_TC_TAG              = 28,   /* DSCP rewritten */
    STAT_TC_NOOP             = 29,   /* no deferred actions */

    /* Additional drops */
    STAT_DROP_L3_FRAGMENT    = 30,   /* IP fragment (non-first) dropped */
    STAT_DROP_L4_NOT_IPV4    = 31,   /* non-IPv4 reached L4 */

    /* IPv6 */
    STAT_PASS_L3_V6          = 32,   /* IPv6 packet passed L3 */
    STAT_DROP_L3_V6_RULE     = 33,   /* explicit DROP action in L3 IPv6 rule */
    STAT_DROP_L3_V6_DEFAULT  = 34,   /* IPv6 default action = DROP */
    STAT_DROP_L3_V6_FRAGMENT = 35,   /* IPv6 fragment header detected, dropped */
    STAT_DROP_L4_V6_FRAGMENT = 36,   /* IPv6 fragment after ext headers in L4 */

    STAT__MAX                = 40,
};

#define MAX_STATS STAT__MAX

/* ── Debug tracing ────────────────────────────────────────── */

/*
 * BPF_DBG — conditional bpf_printk, compiled out unless -DBPF_DEBUG.
 * Usage:  BPF_DBG("L3: src=%pI4 action=%d", &iph->saddr, rule->action);
 * Read:   cat /sys/kernel/debug/tracing/trace_pipe
 */
#ifdef BPF_DEBUG
#define BPF_DBG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define BPF_DBG(fmt, ...) ((void)0)
#endif

/* ── Token bucket state for rate limiting ──────────────────── */

struct rate_state {
    __u64 tokens;       /* remaining tokens (bytes) */
    __u64 last_refill;  /* last refill timestamp (ns) */
    __u64 rate_bps;     /* configured rate in bytes/sec */
};

#endif /* FILTER_BPF_COMMON_H */
