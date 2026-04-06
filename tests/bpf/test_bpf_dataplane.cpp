/*
 * BPF Data Plane Tests — uses BPF_PROG_TEST_RUN to validate XDP verdicts.
 *
 * Requires: CAP_BPF (run with sudo or appropriate capabilities).
 * Loads real BPF programs via skeleton, populates maps, sends crafted
 * packets, and checks XDP return codes.
 */

#include "loader/bpf_loader.hpp"
#include "loader/map_manager.hpp"
#include "../../bpf/common.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// ── Packet crafting helpers ─────────────────────────────────

struct PacketBuilder {
    std::vector<uint8_t> buf;

    PacketBuilder() { buf.reserve(128); }

    /// Add Ethernet header
    PacketBuilder& eth(const uint8_t src[6], const uint8_t dst[6], uint16_t proto) {
        size_t off = buf.size();
        buf.resize(off + sizeof(struct ethhdr));
        struct ethhdr h{};
        memcpy(h.h_source, src, 6);
        memcpy(h.h_dest, dst, 6);
        h.h_proto = htons(proto);
        memcpy(buf.data() + off, &h, sizeof(h));
        return *this;
    }

    /// Add IPv4 header (minimal, no options)
    PacketBuilder& ipv4(uint32_t src_nbo, uint32_t dst_nbo, uint8_t proto, uint16_t payload_len = 20) {
        size_t off = buf.size();
        buf.resize(off + sizeof(struct iphdr));
        struct iphdr h{};
        h.ihl = 5;
        h.version = 4;
        h.tot_len = htons(sizeof(struct iphdr) + payload_len);
        h.ttl = 64;
        h.protocol = proto;
        h.saddr = src_nbo;
        h.daddr = dst_nbo;
        memcpy(buf.data() + off, &h, sizeof(h));
        return *this;
    }

    /// Add TCP header (minimal)
    PacketBuilder& tcp(uint16_t src_port, uint16_t dst_port) {
        size_t off = buf.size();
        buf.resize(off + sizeof(struct tcphdr));
        struct tcphdr h{};
        h.source = htons(src_port);
        h.dest = htons(dst_port);
        h.doff = 5;
        memcpy(buf.data() + off, &h, sizeof(h));
        return *this;
    }

    /// Add UDP header (minimal)
    PacketBuilder& udp(uint16_t src_port, uint16_t dst_port, uint16_t len = 8) {
        size_t off = buf.size();
        buf.resize(off + sizeof(struct udphdr));
        struct udphdr h{};
        h.source = htons(src_port);
        h.dest = htons(dst_port);
        h.len = htons(len);
        h.check = 0;
        memcpy(buf.data() + off, &h, sizeof(h));
        return *this;
    }

    /// Pad to minimum Ethernet frame size
    PacketBuilder& pad(size_t min_size = 64) {
        if (buf.size() < min_size)
            buf.resize(min_size, 0);
        return *this;
    }

    const uint8_t* data() const { return buf.data(); }
    uint32_t size() const { return static_cast<uint32_t>(buf.size()); }
};

static uint32_t ip_nbo(const char* ip) {
    uint32_t addr;
    inet_pton(AF_INET, ip, &addr);
    return addr;
}

// ── BPF_PROG_TEST_RUN wrapper ───────────────────────────────

struct TestRunResult {
    int retval;       // XDP_DROP=1, XDP_PASS=2, XDP_REDIRECT=4, ...
    uint32_t duration_ns;
    bool ok;
};

/// Run XDP program via BPF_PROG_TEST_RUN.
/// When with_meta=true, prepends a pkt_meta struct to the packet data and
/// sets up ctx_in so data_meta is valid. Use this for layer programs (L2/L3/L4)
/// which expect entry_prog to have already allocated the meta area.
/// When with_meta=false (default), runs without data_meta — use for entry_prog
/// which calls bpf_xdp_adjust_meta itself.
static TestRunResult run_xdp_prog(int prog_fd, const uint8_t* data, uint32_t len,
                                   uint32_t repeat = 1, bool with_meta = false,
                                   uint32_t generation = 0) {
    TestRunResult res{};
    uint8_t data_out[1500]{};

    if (with_meta) {
        constexpr uint32_t meta_sz = sizeof(struct pkt_meta);
        std::vector<uint8_t> data_with_meta(meta_sz + len);
        struct pkt_meta meta{};
        meta.generation = generation;
        memcpy(data_with_meta.data(), &meta, meta_sz);
        memcpy(data_with_meta.data() + meta_sz, data, len);

        struct xdp_md ctx_in{};
        ctx_in.data_meta = 0;
        ctx_in.data      = meta_sz;
        ctx_in.data_end  = meta_sz + len;

        LIBBPF_OPTS(bpf_test_run_opts, opts,
            .data_in = data_with_meta.data(),
            .data_out = data_out,
            .data_size_in = static_cast<__u32>(data_with_meta.size()),
            .data_size_out = sizeof(data_out),
            .ctx_in = &ctx_in,
            .ctx_size_in = sizeof(ctx_in),
            .repeat = static_cast<int>(repeat),
        );

        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err < 0) { res.ok = false; return res; }
        res.retval = opts.retval;
        res.duration_ns = opts.duration;
        res.ok = true;
        return res;
    }

    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = data,
        .data_out = data_out,
        .data_size_in = len,
        .data_size_out = sizeof(data_out),
        .repeat = static_cast<int>(repeat),
    );

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err < 0) { res.ok = false; return res; }
    res.retval = opts.retval;
    res.duration_ns = opts.duration;
    res.ok = true;
    return res;
}

// ── Test framework ──────────────────────────────────────────

#define TEST(name) \
    static void name(pktgate::loader::BpfLoader& loader); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name(pktgate::loader::BpfLoader& loader)

struct TestEntry {
    const char* name;
    void (*fn)(pktgate::loader::BpfLoader&);
};
static std::vector<TestEntry> tests;

// Well-known MACs for tests
static const uint8_t KNOWN_MAC[6]   = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static const uint8_t UNKNOWN_MAC[6] = {0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00};
static const uint8_t DST_MAC[6]     = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

// ── Helper: populate maps for a standard test config ────────

static void setup_standard_config(pktgate::loader::BpfLoader& loader, uint32_t gen) {
    using MM = pktgate::loader::MapManager;

    // --- L2 src_mac rule: allow KNOWN_MAC → L3 ---
    struct mac_key mkey{};
    memcpy(mkey.addr, KNOWN_MAC, 6);
    struct l2_rule l2_allow{};
    l2_allow.rule_id = 1;
    l2_allow.action = ACT_ALLOW;
    l2_allow.next_layer = LAYER_3_IDX;
    auto r = MM::update_elem(loader.l2_src_mac_fd(gen), &mkey, &l2_allow, BPF_ANY);
    assert(r.has_value());

    // --- Subnet rules: 192.168.1.0/24 → DROP ---
    struct lpm_v4_key lpm_drop = { .prefixlen = 24, .addr = ip_nbo("192.168.1.0") };
    struct l3_rule l3_drop{};
    l3_drop.rule_id = 10;
    l3_drop.action = ACT_DROP;
    r = MM::update_elem(loader.subnet_rules_fd(gen), &lpm_drop, &l3_drop, BPF_ANY);
    assert(r.has_value());

    // --- Subnet rules: 10.0.0.0/8 → ALLOW + next_layer ---
    struct lpm_v4_key lpm_allow = { .prefixlen = 8, .addr = ip_nbo("10.0.0.0") };
    struct l3_rule l3_allow{};
    l3_allow.rule_id = 11;
    l3_allow.action = ACT_ALLOW;
    l3_allow.has_next_layer = 1;
    r = MM::update_elem(loader.subnet_rules_fd(gen), &lpm_allow, &l3_allow, BPF_ANY);
    assert(r.has_value());

    // --- L4 rules: TCP:80 → ALLOW ---
    struct l4_match_key l4_tcp80 = { .protocol = 6, ._pad = 0, .dst_port = 80 };
    struct l4_rule l4r_allow{};
    l4r_allow.rule_id = 100;
    l4r_allow.action = ACT_ALLOW;
    r = MM::update_elem(loader.l4_rules_fd(gen), &l4_tcp80, &l4r_allow, BPF_ANY);
    assert(r.has_value());

    // --- L4 rules: UDP:53 → TAG (DSCP=46, CoS=5) ---
    struct l4_match_key l4_udp53 = { .protocol = 17, ._pad = 0, .dst_port = 53 };
    struct l4_rule l4r_tag{};
    l4r_tag.rule_id = 101;
    l4r_tag.action = ACT_TAG;
    l4r_tag.dscp = 46;
    l4r_tag.cos = 5;
    r = MM::update_elem(loader.l4_rules_fd(gen), &l4_udp53, &l4r_tag, BPF_ANY);
    assert(r.has_value());

    // --- L4 rules: TCP:443 → RATE_LIMIT (1Gbps) ---
    struct l4_match_key l4_tcp443 = { .protocol = 6, ._pad = 0, .dst_port = 443 };
    struct l4_rule l4r_rate{};
    l4r_rate.rule_id = 102;
    l4r_rate.action = ACT_RATE_LIMIT;
    l4r_rate.rate_bps = 1000000000ULL;
    r = MM::update_elem(loader.l4_rules_fd(gen), &l4_tcp443, &l4r_rate, BPF_ANY);
    assert(r.has_value());

    // --- Default action: DROP ---
    uint32_t da_key = 0;
    uint32_t da_val = ACT_DROP;
    r = MM::update_elem(loader.default_action_fd(gen), &da_key, &da_val, BPF_ANY);
    assert(r.has_value());

    // --- Install programs in prog_array ---
    uint32_t idx;
    int fd;

    idx = LAYER_2_IDX;
    fd = loader.layer2_prog_fd();
    r = MM::update_elem(loader.prog_array_fd(gen), &idx, &fd, BPF_ANY);
    assert(r.has_value());

    idx = LAYER_3_IDX;
    fd = loader.layer3_prog_fd();
    r = MM::update_elem(loader.prog_array_fd(gen), &idx, &fd, BPF_ANY);
    assert(r.has_value());

    idx = LAYER_4_IDX;
    fd = loader.layer4_prog_fd();
    r = MM::update_elem(loader.prog_array_fd(gen), &idx, &fd, BPF_ANY);
    assert(r.has_value());

    // --- Set gen_config to this generation ---
    uint32_t gk = 0;
    r = MM::update_elem(loader.gen_config_fd(), &gk, &gen, BPF_ANY);
    assert(r.has_value());
}

// ═══════════════════════════════════════════════════════════
// Layer 2 Tests
// ═══════════════════════════════════════════════════════════

TEST(test_l2_known_mac_passes) {
    // Known MAC → should pass through L2 (tail call to L3)
    // Since L3 will try LPM lookup on src_ip, and we use 10.0.0.1
    // which matches 10.0.0.0/8 → ALLOW + next_layer → L4 → default DROP
    // But the packet has TCP:12345 which has no L4 rule → default DROP.
    // What matters: it got PAST L2 (didn't get dropped by L2).
    // We can't distinguish "dropped by L2" vs "dropped by L4 default" via retval alone.
    // So we test against entry_prog which does L2 first.

    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)  // TCP:80 → ALLOW
        .pad();

    // Run through entry program (tail-calls L2 → L3 → L4)
    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    // Known MAC passes L2, 10.0.0.1 → L3 ALLOW+next → L4 TCP:80 → ALLOW → XDP_PASS
    assert(res.retval == XDP_PASS);
}

TEST(test_l2_unknown_mac_falls_through) {
    // New L2 architecture: no match → fall through to L3.
    // Unknown MAC has no L2 rule → tail call to L3.
    // Use 192.168.1.100 (L3 DROP rule) to verify full pipeline drop.
    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.100"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped at L3 (192.168.1.0/24 → DROP)
}

TEST(test_l2_explicit_drop_rule) {
    // Add a dst_mac DROP rule and verify L2 drops matching packets
    using MM = pktgate::loader::MapManager;

    struct mac_key dkey{};
    uint8_t target_dst[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    memcpy(dkey.addr, target_dst, 6);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 99;
    drop_rule.action = ACT_DROP;
    auto r = MM::update_elem(loader.l2_dst_mac_fd(0), &dkey, &drop_rule, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, target_dst, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by L2 dst_mac rule

    // Clean up
    MM::delete_elem(loader.l2_dst_mac_fd(0), &dkey);
}

TEST(test_l2_truncated_packet_dropped) {
    // Packet smaller than Ethernet header but meets BPF_PROG_TEST_RUN minimum (14 bytes).
    // Fill with garbage — L2 should bounds-check and drop.
    uint8_t tiny[14]{};
    tiny[12] = 0x08; tiny[13] = 0x00; // ETH_P_IP, but no IP header follows
    auto res = run_xdp_prog(loader.layer2_prog_fd(), tiny, sizeof(tiny), 1, true);
    if (!res.ok) {
        // Some kernels reject packets < ETH_HLEN from BPF_PROG_TEST_RUN
        std::cout << "    [skip] kernel rejected tiny packet\n";
        return;
    }
    // If the kernel ran it, L2 should still drop (unknown MAC)
    assert(res.retval == XDP_DROP);
}

TEST(test_l2_broadcast_mac_no_match) {
    // Broadcast MAC has no L2 rule → falls through to L3.
    // Use 192.168.1.100 (L3 DROP) so pipeline ultimately drops.
    uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    auto pkt = PacketBuilder()
        .eth(bcast, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.100"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped at L3 (192.168.1.0/24 → DROP)
}

// ═══════════════════════════════════════════════════════════
// Layer 3 Tests
// ═══════════════════════════════════════════════════════════

TEST(test_l3_matching_subnet_drop) {
    // 192.168.1.100 matches 192.168.1.0/24 → ACT_DROP
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.100"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

TEST(test_l3_matching_subnet_allow_to_l4) {
    // 10.0.0.1 matches 10.0.0.0/8 → ACT_ALLOW + has_next_layer
    // L4 tail call may fail in isolated test → XDP_PASS (allow action returns PASS)
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    // With prog_array populated, tail calls to L4. L4 sees TCP:80 → ALLOW → XDP_PASS.
    // Without prog_array: handle_l3_action returns XDP_PASS after failed tail call.
    assert(res.retval == XDP_PASS);
}

TEST(test_l3_no_match_default_drop) {
    // 172.16.0.1 — no matching subnet, no VRF rule
    // → tail call to L4 (if available) or default action (DROP)
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("172.16.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 9999) // no L4 rule for this port
        .pad();

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    // No subnet match → try L4 tail call → if that works, L4 default DROP.
    // If tail call fails → get_default_action → DROP.
    assert(res.retval == XDP_DROP);
}

TEST(test_l3_non_ipv4_dropped) {
    // ARP frame — not IPv4, Layer 3 drops it
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, 0x0806) // ETH_P_ARP
        .pad(64);

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

TEST(test_l3_truncated_ip_header_dropped) {
    // Valid Ethernet but truncated IP (only 10 bytes, need 20)
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP);
    // Add only 10 bytes of "IP" (need 20 for valid header)
    pkt.buf.resize(pkt.buf.size() + 10, 0);
    pkt.buf[14] = 0x45; // version=4, ihl=5
    pkt.pad(34); // ensure minimum frame size for BPF_PROG_TEST_RUN

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

// ═══════════════════════════════════════════════════════════
// Layer 4 Tests
// ═══════════════════════════════════════════════════════════

TEST(test_l4_tcp80_allow) {
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS);
}

TEST(test_l4_udp53_tag_passes) {
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_UDP)
        .udp(1234, 53)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // TAG action returns PASS
}

TEST(test_l4_tcp443_rate_limit_first_pass) {
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 443)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // First packet always passes (token init)
}

TEST(test_l4_no_rule_default_drop) {
    // TCP:9999 — no L4 rule → default action (DROP)
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 9999)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

TEST(test_l4_non_tcpudp_default) {
    // ICMP — non TCP/UDP → default action
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_ICMP)
        .pad(64);

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

TEST(test_l4_truncated_tcp_dropped) {
    // Valid IP header but truncated TCP (only 2 bytes)
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP, 2);
    pkt.buf.push_back(0x00);
    pkt.buf.push_back(0x50); // partial TCP

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

// ═══════════════════════════════════════════════════════════
// Full Pipeline Tests (entry → L2 → L3 → L4)
// ═══════════════════════════════════════════════════════════

// Full pipeline: entry → L2 → L3 → L4 using entry_prog_fd

TEST(test_pipeline_full_tcp80_allow) {
    // Entry → L2 (known MAC) → L3 (10.0.0.0/8 ALLOW+next) → L4 (TCP:80 ALLOW) → PASS
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_PASS);
}

TEST(test_pipeline_full_no_l4_rule_drop) {
    // Entry → L2 → L3 (ALLOW+next) → L4 (TCP:9999, no rule) → default DROP
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 9999)
        .pad();

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

TEST(test_pipeline_full_l3_drop_overrides_l4) {
    // Entry → L2 → L3 (192.168.1.0/24 DROP) — never reaches L4
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.50"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80) // would be ALLOW in L4, but L3 drops first
        .pad();

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

TEST(test_pipeline_full_unknown_mac_l3_drop) {
    // Entry → L2 (no match, falls through) → L3 (192.168.1.0/24 → DROP)
    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.50"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_DROP);
}

TEST(test_pipeline_full_udp53_tag) {
    // Entry → L2 → L3 (ALLOW+next) → L4 (UDP:53 TAG) → PASS
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_UDP)
        .udp(1234, 53)
        .pad();

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_PASS);
}

// ═══════════════════════════════════════════════════════════
// Layer 2 Extended Tests (ethertype, VLAN, priority)
// ═══════════════════════════════════════════════════════════

TEST(test_l2_ethertype_match) {
    // Add ethertype rule: ARP (0x0806) → DROP
    using MM = pktgate::loader::MapManager;

    struct ethertype_key ekey{};
    ekey.ethertype = htons(0x0806);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 200;
    drop_rule.action = ACT_DROP;
    auto r = MM::update_elem(loader.l2_ethertype_fd(0), &ekey, &drop_rule, BPF_ANY);
    assert(r.has_value());

    // Build ARP packet (unknown MACs, no src/dst mac rule)
    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, 0x0806)
        .pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by ethertype rule

    MM::delete_elem(loader.l2_ethertype_fd(0), &ekey);
}

TEST(test_l2_vlan_match) {
    // Add vlan_id rule: VLAN 100 → DROP
    using MM = pktgate::loader::MapManager;

    struct vlan_key vkey{};
    vkey.vlan_id = htons(100);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 201;
    drop_rule.action = ACT_DROP;
    auto r = MM::update_elem(loader.l2_vlan_fd(0), &vkey, &drop_rule, BPF_ANY);
    assert(r.has_value());

    // Build 802.1Q tagged packet: eth(src, dst, 0x8100) + VLAN TCI + inner ethertype
    PacketBuilder pkt;
    // Ethernet header with 802.1Q tag type
    struct ethhdr eh{};
    memcpy(eh.h_source, UNKNOWN_MAC, 6);
    memcpy(eh.h_dest, DST_MAC, 6);
    eh.h_proto = htons(0x8100);
    pkt.buf.resize(sizeof(eh));
    memcpy(pkt.buf.data(), &eh, sizeof(eh));

    // VLAN TCI: priority=0, DEI=0, VID=100 (lower 12 bits)
    uint16_t tci = htons(100);
    pkt.buf.push_back(static_cast<uint8_t>(tci >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(tci & 0xFF));

    // Inner ethertype (IPv4)
    uint16_t inner_proto = htons(ETH_P_IP);
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto & 0xFF));

    // Pad to minimum frame size
    pkt.pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by vlan_id rule

    MM::delete_elem(loader.l2_vlan_fd(0), &vkey);
}

TEST(test_l2_dst_mac_allow_to_l3) {
    // Add dst_mac ALLOW rule with next_layer=L3 → packet proceeds to L3→L4→PASS
    using MM = pktgate::loader::MapManager;

    struct mac_key dkey{};
    uint8_t target_dst[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(dkey.addr, target_dst, 6);
    struct l2_rule allow_rule{};
    allow_rule.rule_id = 202;
    allow_rule.action = ACT_ALLOW;
    allow_rule.next_layer = LAYER_3_IDX;
    auto r = MM::update_elem(loader.l2_dst_mac_fd(0), &dkey, &allow_rule, BPF_ANY);
    assert(r.has_value());

    // Use unknown src_mac (no src_mac rule) but matching dst_mac
    // IP: 10.0.0.1 → L3 ALLOW+next → L4 TCP:80 → ALLOW → PASS
    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, target_dst, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // dst_mac ALLOW → L3 → L4 → PASS

    MM::delete_elem(loader.l2_dst_mac_fd(0), &dkey);
}

TEST(test_l2_src_mac_priority_over_dst_mac) {
    // src_mac has higher priority than dst_mac in L2 lookup order.
    // Add src_mac DROP for a MAC, and dst_mac ALLOW for same packet's dst.
    // Verify src_mac rule wins → DROP.
    using MM = pktgate::loader::MapManager;

    uint8_t test_src[6] = {0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33};
    uint8_t test_dst[6] = {0xCC, 0xDD, 0xEE, 0x44, 0x55, 0x66};

    struct mac_key skey{};
    memcpy(skey.addr, test_src, 6);
    struct l2_rule src_drop{};
    src_drop.rule_id = 203;
    src_drop.action = ACT_DROP;
    auto r = MM::update_elem(loader.l2_src_mac_fd(0), &skey, &src_drop, BPF_ANY);
    assert(r.has_value());

    struct mac_key dkey{};
    memcpy(dkey.addr, test_dst, 6);
    struct l2_rule dst_allow{};
    dst_allow.rule_id = 204;
    dst_allow.action = ACT_ALLOW;
    dst_allow.next_layer = LAYER_3_IDX;
    r = MM::update_elem(loader.l2_dst_mac_fd(0), &dkey, &dst_allow, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(test_src, test_dst, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // src_mac DROP wins over dst_mac ALLOW

    MM::delete_elem(loader.l2_src_mac_fd(0), &skey);
    MM::delete_elem(loader.l2_dst_mac_fd(0), &dkey);
}

TEST(test_l2_ethertype_ipv4_allow) {
    // Add ethertype rule: IPv4 (0x0800) → ALLOW + next_layer=L3
    using MM = pktgate::loader::MapManager;

    struct ethertype_key ekey{};
    ekey.ethertype = htons(0x0800);
    struct l2_rule allow_rule{};
    allow_rule.rule_id = 205;
    allow_rule.action = ACT_ALLOW;
    allow_rule.next_layer = LAYER_3_IDX;
    auto r = MM::update_elem(loader.l2_ethertype_fd(0), &ekey, &allow_rule, BPF_ANY);
    assert(r.has_value());

    // Use unknown src/dst MACs (no mac rules) so ethertype rule is the match
    uint8_t rnd_src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t rnd_dst[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    auto pkt = PacketBuilder()
        .eth(rnd_src, rnd_dst, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // ethertype ALLOW → L3 → L4 TCP:80 → PASS

    MM::delete_elem(loader.l2_ethertype_fd(0), &ekey);
}

TEST(test_pipeline_full_ethertype_drop) {
    // Via entry_prog: ethertype rule drops ARP before reaching L3
    using MM = pktgate::loader::MapManager;

    struct ethertype_key ekey{};
    ekey.ethertype = htons(0x0806);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 206;
    drop_rule.action = ACT_DROP;
    auto r = MM::update_elem(loader.l2_ethertype_fd(0), &ekey, &drop_rule, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, 0x0806)
        .pad(64);

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_DROP); // ARP dropped by L2 ethertype rule

    MM::delete_elem(loader.l2_ethertype_fd(0), &ekey);
}

// ═══════════════════════════════════════════════════════════
// Layer 2 VLAN / EtherType Edge-Case Tests
// ═══════════════════════════════════════════════════════════

TEST(test_l2_vlan_tagged_no_matching_rule_fallthrough) {
    // 802.1Q VLAN 200 tagged packet — no VLAN rules in standard config.
    // Falls through L2 to L3. src_ip 192.168.1.100 → L3 DROP.
    PacketBuilder pkt;
    struct ethhdr eh{};
    memcpy(eh.h_source, UNKNOWN_MAC, 6);
    memcpy(eh.h_dest, DST_MAC, 6);
    eh.h_proto = htons(0x8100);
    pkt.buf.resize(sizeof(eh));
    memcpy(pkt.buf.data(), &eh, sizeof(eh));

    // VLAN TCI: VID=200
    uint16_t tci = htons(200);
    pkt.buf.push_back(static_cast<uint8_t>(tci >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(tci & 0xFF));

    // Inner ethertype: IPv4
    uint16_t inner_proto = htons(ETH_P_IP);
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto & 0xFF));

    // IP + TCP payload (src=192.168.1.100 → L3 DROP)
    pkt.ipv4(ip_nbo("192.168.1.100"), ip_nbo("10.0.0.2"), IPPROTO_TCP);
    pkt.tcp(1234, 80);
    pkt.pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // no VLAN rule → L3 → 192.168.1.0/24 DROP
}

TEST(test_l2_ethertype_ipv6_match) {
    // Add ethertype rule for IPv6 (0x86DD) → DROP
    using MM = pktgate::loader::MapManager;

    struct ethertype_key ekey{};
    ekey.ethertype = htons(0x86DD);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 210;
    drop_rule.action = ACT_DROP;
    auto r = MM::update_elem(loader.l2_ethertype_fd(0), &ekey, &drop_rule, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, 0x86DD)
        .pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by IPv6 ethertype rule

    MM::delete_elem(loader.l2_ethertype_fd(0), &ekey);
}

TEST(test_l2_vlan_boundary_4095) {
    // Add vlan_id=4095 rule → DROP. Verify max VLAN ID boundary.
    using MM = pktgate::loader::MapManager;

    struct vlan_key vkey{};
    vkey.vlan_id = htons(4095);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 211;
    drop_rule.action = ACT_DROP;
    auto r = MM::update_elem(loader.l2_vlan_fd(0), &vkey, &drop_rule, BPF_ANY);
    assert(r.has_value());

    PacketBuilder pkt;
    struct ethhdr eh{};
    memcpy(eh.h_source, UNKNOWN_MAC, 6);
    memcpy(eh.h_dest, DST_MAC, 6);
    eh.h_proto = htons(0x8100);
    pkt.buf.resize(sizeof(eh));
    memcpy(pkt.buf.data(), &eh, sizeof(eh));

    // VLAN TCI: VID=4095 (0x0FFF)
    uint16_t tci = htons(4095);
    pkt.buf.push_back(static_cast<uint8_t>(tci >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(tci & 0xFF));

    uint16_t inner_proto = htons(ETH_P_IP);
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto & 0xFF));

    pkt.pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by vlan_id 4095 rule

    MM::delete_elem(loader.l2_vlan_fd(0), &vkey);
}

TEST(test_l2_ethertype_priority_over_vlan) {
    // Add ethertype (0x0800→DROP) and vlan (100→ALLOW) rules.
    // BPF checks ethertype BEFORE vlan, so ethertype wins → DROP.
    using MM = pktgate::loader::MapManager;

    struct ethertype_key ekey{};
    ekey.ethertype = htons(0x0800);
    struct l2_rule etype_drop{};
    etype_drop.rule_id = 212;
    etype_drop.action = ACT_DROP;
    auto r = MM::update_elem(loader.l2_ethertype_fd(0), &ekey, &etype_drop, BPF_ANY);
    assert(r.has_value());

    struct vlan_key vkey{};
    vkey.vlan_id = htons(100);
    struct l2_rule vlan_allow{};
    vlan_allow.rule_id = 213;
    vlan_allow.action = ACT_ALLOW;
    vlan_allow.next_layer = LAYER_3_IDX;
    r = MM::update_elem(loader.l2_vlan_fd(0), &vkey, &vlan_allow, BPF_ANY);
    assert(r.has_value());

    // Build 802.1Q VLAN 100 tagged IPv4 packet (unknown MACs)
    PacketBuilder pkt;
    struct ethhdr eh{};
    memcpy(eh.h_source, UNKNOWN_MAC, 6);
    memcpy(eh.h_dest, DST_MAC, 6);
    eh.h_proto = htons(0x8100);
    pkt.buf.resize(sizeof(eh));
    memcpy(pkt.buf.data(), &eh, sizeof(eh));

    uint16_t tci = htons(100);
    pkt.buf.push_back(static_cast<uint8_t>(tci >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(tci & 0xFF));

    uint16_t inner_proto = htons(ETH_P_IP);
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto & 0xFF));

    pkt.ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP);
    pkt.tcp(1234, 80);
    pkt.pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // ethertype 0x0800 DROP wins over vlan 100 ALLOW

    MM::delete_elem(loader.l2_ethertype_fd(0), &ekey);
    MM::delete_elem(loader.l2_vlan_fd(0), &vkey);
}

TEST(test_l2_allow_terminal_no_next_layer) {
    // Add src_mac rule with ACT_ALLOW and next_layer=0 (terminal).
    // Packet should get XDP_PASS at L2 (line 73-74 of layer2.bpf.c).
    using MM = pktgate::loader::MapManager;

    uint8_t term_mac[6] = {0xFE, 0xED, 0xFA, 0xCE, 0x00, 0x01};
    struct mac_key mkey{};
    memcpy(mkey.addr, term_mac, 6);
    struct l2_rule allow_term{};
    allow_term.rule_id = 214;
    allow_term.action = ACT_ALLOW;
    allow_term.next_layer = 0; // terminal — no next layer
    auto r = MM::update_elem(loader.l2_src_mac_fd(0), &mkey, &allow_term, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(term_mac, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.100"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // terminal ALLOW at L2 → XDP_PASS

    MM::delete_elem(loader.l2_src_mac_fd(0), &mkey);
}

TEST(test_l2_qinq_not_parsed) {
    // QinQ frame: outer h_proto = 0x88a8. BPF only handles 0x8100.
    // 0x88a8 is treated as a regular ethertype, no VLAN parsing.
    // No ethertype rule for 0x88a8 → falls through to L3.
    // L3 sees non-IPv4/v6 (the inner frame is garbage) → DROP.
    PacketBuilder pkt;
    struct ethhdr eh{};
    memcpy(eh.h_source, UNKNOWN_MAC, 6);
    memcpy(eh.h_dest, DST_MAC, 6);
    eh.h_proto = htons(0x88a8); // QinQ / 802.1ad
    pkt.buf.resize(sizeof(eh));
    memcpy(pkt.buf.data(), &eh, sizeof(eh));

    // Outer VLAN TCI + inner 802.1Q tag (won't be parsed by BPF)
    uint16_t outer_tci = htons(100);
    pkt.buf.push_back(static_cast<uint8_t>(outer_tci >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(outer_tci & 0xFF));
    uint16_t inner_tag = htons(0x8100);
    pkt.buf.push_back(static_cast<uint8_t>(inner_tag >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_tag & 0xFF));

    // Inner VLAN TCI + ethertype
    uint16_t inner_tci = htons(200);
    pkt.buf.push_back(static_cast<uint8_t>(inner_tci >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_tci & 0xFF));
    uint16_t inner_proto = htons(ETH_P_IP);
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto & 0xFF));

    pkt.pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // QinQ not parsed → L3 → non-IPv4 → DROP
}

// ═══════════════════════════════════════════════════════════
// Performance Benchmark
// ═══════════════════════════════════════════════════════════

TEST(bench_l4_tcp80_1M_packets) {
    constexpr uint32_t N = 1000000;
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), N, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS);

    // opts.duration = average ns per repetition
    double ns_per_pkt = static_cast<double>(res.duration_ns);
    double mpps = (ns_per_pkt > 0) ? 1000.0 / ns_per_pkt : 0;
    std::cout << "    [perf] L4 TCP:80 allow: "
              << ns_per_pkt << " ns/pkt, ~"
              << mpps << " Mpps\n";
}

TEST(bench_l3_lpm_lookup_1M) {
    constexpr uint32_t N = 1000000;
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), N, true);
    assert(res.ok);

    double ns_per_pkt = static_cast<double>(res.duration_ns);
    double mpps = (ns_per_pkt > 0) ? 1000.0 / ns_per_pkt : 0;
    std::cout << "    [perf] L3 LPM+L4 pipeline: "
              << ns_per_pkt << " ns/pkt, ~"
              << mpps << " Mpps\n";
}

TEST(bench_l2_no_match_fallthrough_1M) {
    constexpr uint32_t N = 1000000;
    // Unknown MAC → no L2 match → L3 → L4 → full pipeline
    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.100"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), N, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped at L3 (192.168.1.0/24)

    double ns_per_pkt = static_cast<double>(res.duration_ns);
    double mpps = (ns_per_pkt > 0) ? 1000.0 / ns_per_pkt : 0;
    std::cout << "    [perf] L2 no-match → L3 drop: "
              << ns_per_pkt << " ns/pkt, ~"
              << mpps << " Mpps\n";
}

// ═══════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════

int main() {
    // Suppress libbpf warnings
    libbpf_set_print([](enum libbpf_print_level, const char*, va_list) -> int {
        return 0;
    });

    // Load BPF programs
    pktgate::loader::BpfLoader loader;
    auto lr = loader.load();
    if (!lr) {
        std::cerr << "Failed to load BPF programs: " << lr.error() << "\n";
        std::cerr << "Hint: run with sudo or CAP_BPF\n";
        return 77; // skip code for test frameworks
    }

    // Populate maps with standard test config (gen 0)
    setup_standard_config(loader, 0);

    int passed = 0, failed = 0, skipped = 0;
    for (auto& [name, fn] : tests) {
        try {
            fn(loader);
            std::cout << "  PASS  " << name << "\n";
            ++passed;
        } catch (const std::exception& e) {
            std::cout << "  FAIL  " << name << ": " << e.what() << "\n";
            ++failed;
        }
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed > 0 ? 1 : 0;
}
