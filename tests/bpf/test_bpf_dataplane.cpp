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
    PacketBuilder& tcp(uint16_t src_port, uint16_t dst_port, uint8_t flags = 0) {
        size_t off = buf.size();
        buf.resize(off + sizeof(struct tcphdr));
        struct tcphdr h{};
        h.source = htons(src_port);
        h.dest = htons(dst_port);
        h.doff = 5;
        // Set flags via raw byte at offset 13 within the TCP header
        memcpy(buf.data() + off, &h, sizeof(h));
        if (flags)
            buf[off + 13] = flags;
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

/// Run an XDP layer program and return both the retval and the post-execution
/// meta+data so callers can verify stamping or no-corruption. Mirrors
/// run_xdp_prog(with_meta=true) but exposes the raw buffer.
struct LayerRunResult {
    TestRunResult run;
    struct pkt_meta meta;            // meta as returned by the program
    std::vector<uint8_t> packet;     // packet bytes as returned (post-action)
};

static LayerRunResult run_layer_prog(int prog_fd, const uint8_t* data, uint32_t len,
                                      uint32_t generation = 0) {
    LayerRunResult out{};
    constexpr uint32_t meta_sz = sizeof(struct pkt_meta);
    std::vector<uint8_t> data_with_meta(meta_sz + len);
    struct pkt_meta meta_in{};
    meta_in.generation = generation;
    memcpy(data_with_meta.data(), &meta_in, meta_sz);
    memcpy(data_with_meta.data() + meta_sz, data, len);

    std::vector<uint8_t> data_out(meta_sz + len + 64, 0);

    struct xdp_md ctx_in{};
    ctx_in.data_meta = 0;
    ctx_in.data      = meta_sz;
    ctx_in.data_end  = meta_sz + len;

    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = data_with_meta.data(),
        .data_out = data_out.data(),
        .data_size_in = static_cast<__u32>(data_with_meta.size()),
        .data_size_out = static_cast<__u32>(data_out.size()),
        .ctx_in = &ctx_in,
        .ctx_size_in = sizeof(ctx_in),
        .repeat = 1,
    );

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err < 0) { out.run.ok = false; return out; }
    out.run.retval = opts.retval;
    out.run.duration_ns = opts.duration;
    out.run.ok = true;
    memcpy(&out.meta, data_out.data(), meta_sz);
    out.packet.assign(data_out.begin() + meta_sz, data_out.begin() + meta_sz + len);
    return out;
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

// ── L2 helpers (post-#10 single-dispatch refactor) ─────────
// Tests previously poked one of five per-field L2 maps directly. Under the
// composite-key design they install (key, rule) into a single l2_rules map
// and must also register the filter_mask in l2_active_masks_{gen} so the BPF
// iterator hits it. install_l2_rule + activate_l2_mask wrap that boilerplate.

static void activate_l2_mask(pktgate::loader::BpfLoader& loader,
                              uint32_t gen, uint8_t mask) {
    using MM = pktgate::loader::MapManager;
    int masks_fd = loader.l2_active_masks_fd(gen);
    // Append to the first empty slot. Tests build state incrementally; no need
    // to sort by popcount because they assert specific match expectations.
    for (uint32_t i = 0; i < MAX_L2_MASKS; ++i) {
        uint8_t cur = 0;
        bpf_map_lookup_elem(masks_fd, &i, &cur);
        if (cur == mask) return;          // already activated
        if (cur == 0) {
            MM::update_elem(masks_fd, &i, &mask, BPF_ANY);
            return;
        }
    }
}

static void install_l2_rule(pktgate::loader::BpfLoader& loader,
                             uint32_t gen,
                             const struct l2_key& key,
                             const struct l2_rule& rule) {
    using MM = pktgate::loader::MapManager;
    MM::update_elem(loader.l2_rules_fd(gen), &key, &rule, BPF_ANY);
    activate_l2_mask(loader, gen, key.filter_mask);
}

// ── Helper: populate maps for a standard test config ────────

static void setup_standard_config(pktgate::loader::BpfLoader& loader, uint32_t gen) {
    using MM = pktgate::loader::MapManager;

    // --- L2 src_mac rule: allow KNOWN_MAC → L3 ---
    struct l2_key lkey{};
    lkey.filter_mask = FILTER_MASK_SRCMAC;
    memcpy(lkey.src_mac, KNOWN_MAC, 6);
    struct l2_rule l2_allow{};
    l2_allow.rule_id = 1;
    l2_allow.action = ACT_ALLOW;
    l2_allow.next_layer = LAYER_3_IDX;
    install_l2_rule(loader, gen, lkey, l2_allow);

    // --- Subnet rules: 192.168.1.0/24 → DROP ---
    struct lpm_v4_key lpm_drop = { .prefixlen = 24, .addr = ip_nbo("192.168.1.0") };
    struct l3_rule l3_drop{};
    l3_drop.rule_id = 10;
    l3_drop.action = ACT_DROP;
    auto r = MM::update_elem(loader.subnet_rules_fd(gen), &lpm_drop, &l3_drop, BPF_ANY);
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

    // --- L4 rules: TCP:8080 → ALLOW only SYN,!ACK ---
    struct l4_match_key l4_tcp8080 = { .protocol = 6, ._pad = 0, .dst_port = 8080 };
    struct l4_rule l4r_syn{};
    l4r_syn.rule_id = 103;
    l4r_syn.action = ACT_ALLOW;
    l4r_syn.tcp_flags_set = TCPF_SYN;
    l4r_syn.tcp_flags_unset = TCPF_ACK;
    r = MM::update_elem(loader.l4_rules_fd(gen), &l4_tcp8080, &l4r_syn, BPF_ANY);
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
    // layer_present.L2 is unset in setup_standard_config, so L2 no-match
    // falls through to L3 (the "L3-only config" ergonomic path).
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

    uint8_t target_dst[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    struct l2_key dkey{};
    dkey.filter_mask = FILTER_MASK_DSTMAC;
    memcpy(dkey.dst_mac, target_dst, 6);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 99;
    drop_rule.action = ACT_DROP;
    install_l2_rule(loader, 0, dkey, drop_rule);

    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, target_dst, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by L2 dst_mac rule

    // Clean up
    MM::delete_elem(loader.l2_rules_fd(0), &dkey);
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
    // Broadcast MAC has no L2 rule → falls through to L3 (layer_present.L2 unset).
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

TEST(test_l2_layer_present_default_drop_unknown_mac) {
    // With LAYER_PRESENT_L2 set, an unknown MAC must hit L2 default_behavior
    // (DROP) — NOT fall through to L3. Target IP 10.0.0.x is L3-ALLOW, so any
    // fallthrough would yield XDP_PASS at L4 (TCP:80 allow). XDP_DROP proves
    // the default action fired at L2.
    using MM = pktgate::loader::MapManager;

    uint32_t key = 0;
    uint8_t mask = LAYER_PRESENT_L2;
    auto r = MM::update_elem(loader.layer_present_fd(0), &key, &mask, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.5"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();
    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);

    // Clean up — restore "empty L2 layer" flag for sibling tests.
    mask = 0;
    MM::update_elem(loader.layer_present_fd(0), &key, &mask, BPF_ANY);
}

TEST(test_l2_layer_present_default_allow_unknown_mac) {
    // With LAYER_PRESENT_L2 set and default_action=ALLOW, an unknown MAC must
    // PASS at L2 (no fallthrough to L3). Use 192.168.1.100 as src — would be
    // L3-DROPped on fallthrough; XDP_PASS proves L2 stopped the walk.
    using MM = pktgate::loader::MapManager;

    uint32_t key = 0;
    uint8_t mask = LAYER_PRESENT_L2;
    auto r = MM::update_elem(loader.layer_present_fd(0), &key, &mask, BPF_ANY);
    assert(r.has_value());

    uint32_t da_key = 0;
    uint32_t da_val = ACT_ALLOW;
    r = MM::update_elem(loader.default_action_fd(0), &da_key, &da_val, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.100"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();
    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS);

    // Clean up — restore defaults for sibling tests.
    mask = 0;
    MM::update_elem(loader.layer_present_fd(0), &key, &mask, BPF_ANY);
    da_val = ACT_DROP;
    MM::update_elem(loader.default_action_fd(0), &da_key, &da_val, BPF_ANY);
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

// ═══════════════════════════════════════════════════════════
// L4 TCP Flags Tests
// ═══════════════════════════════════════════════════════════

TEST(test_l4_tcp_flags_syn_match) {
    // TCP:8080 with SYN flag → rule matches (SYN set, ACK not set)
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 8080, TCPF_SYN)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS);  // ALLOW
}

TEST(test_l4_tcp_flags_syn_not_ack_match) {
    // TCP:8080 with SYN only → matches "SYN,!ACK" rule
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 8080, TCPF_SYN)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS);
}

TEST(test_l4_tcp_flags_syn_not_ack_mismatch) {
    // TCP:8080 with SYN+ACK → fails "SYN,!ACK" rule → default DROP
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 8080, TCPF_SYN | TCPF_ACK)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);  // flags mismatch → default action
}

TEST(test_l4_tcp_flags_backward_compat) {
    // TCP:80 rule has no tcp_flags → matches any TCP packet regardless of flags
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80, TCPF_SYN | TCPF_ACK | TCPF_FIN)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS);  // ALLOW — no flags check
}

TEST(test_l4_tcp_flags_udp_unaffected) {
    // UDP:53 rule has no tcp_flags → still matches normally
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_UDP)
        .udp(1234, 53)
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS);  // TAG action returns PASS
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

    struct l2_key ekey{};
    ekey.filter_mask = FILTER_MASK_ETHERTYPE;
    ekey.ethertype = htons(0x0806);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 200;
    drop_rule.action = ACT_DROP;
    install_l2_rule(loader, 0, ekey, drop_rule);

    // Build ARP packet (unknown MACs, no src/dst mac rule)
    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, 0x0806)
        .pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by ethertype rule

    MM::delete_elem(loader.l2_rules_fd(0), &ekey);
}

TEST(test_l2_vlan_match) {
    // Add vlan_id rule: VLAN 100 → DROP
    using MM = pktgate::loader::MapManager;

    struct l2_key vkey{};
    vkey.filter_mask = FILTER_MASK_VLAN;
    vkey.vlan_id = 100;  // host byte order
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 201;
    drop_rule.action = ACT_DROP;
    install_l2_rule(loader, 0, vkey, drop_rule);

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

    MM::delete_elem(loader.l2_rules_fd(0), &vkey);
}

TEST(test_l2_dst_mac_allow_to_l3) {
    // Add dst_mac ALLOW rule with next_layer=L3 → packet proceeds to L3→L4→PASS
    using MM = pktgate::loader::MapManager;

    uint8_t target_dst[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55};
    struct l2_key dkey{};
    dkey.filter_mask = FILTER_MASK_DSTMAC;
    memcpy(dkey.dst_mac, target_dst, 6);
    struct l2_rule allow_rule{};
    allow_rule.rule_id = 202;
    allow_rule.action = ACT_ALLOW;
    allow_rule.next_layer = LAYER_3_IDX;
    install_l2_rule(loader, 0, dkey, allow_rule);

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

    MM::delete_elem(loader.l2_rules_fd(0), &dkey);
}

TEST(test_l2_src_mac_priority_over_dst_mac) {
    // Post-#10 the L2 iterator hits most-specific masks first (popcount desc),
    // but src+dst here have the same popcount (1 each). Activation order in
    // the test's install_l2_rule decides which fires; src_mac was added by
    // setup_standard_config first → its mask precedes dst_mac in active set.
    // The rule under test still validates that src_mac DROP wins over dst_mac
    // ALLOW for a packet matching both — same operator-intent assertion.
    using MM = pktgate::loader::MapManager;

    uint8_t test_src[6] = {0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33};
    uint8_t test_dst[6] = {0xCC, 0xDD, 0xEE, 0x44, 0x55, 0x66};

    struct l2_key skey{};
    skey.filter_mask = FILTER_MASK_SRCMAC;
    memcpy(skey.src_mac, test_src, 6);
    struct l2_rule src_drop{};
    src_drop.rule_id = 203;
    src_drop.action = ACT_DROP;
    install_l2_rule(loader, 0, skey, src_drop);

    struct l2_key dkey{};
    dkey.filter_mask = FILTER_MASK_DSTMAC;
    memcpy(dkey.dst_mac, test_dst, 6);
    struct l2_rule dst_allow{};
    dst_allow.rule_id = 204;
    dst_allow.action = ACT_ALLOW;
    dst_allow.next_layer = LAYER_3_IDX;
    install_l2_rule(loader, 0, dkey, dst_allow);

    auto pkt = PacketBuilder()
        .eth(test_src, test_dst, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // src_mac DROP wins over dst_mac ALLOW

    MM::delete_elem(loader.l2_rules_fd(0), &skey);
    MM::delete_elem(loader.l2_rules_fd(0), &dkey);
}

TEST(test_l2_ethertype_ipv4_allow) {
    // Add ethertype rule: IPv4 (0x0800) → ALLOW + next_layer=L3
    using MM = pktgate::loader::MapManager;

    struct l2_key ekey{};
    ekey.filter_mask = FILTER_MASK_ETHERTYPE;
    ekey.ethertype = htons(0x0800);
    struct l2_rule allow_rule{};
    allow_rule.rule_id = 205;
    allow_rule.action = ACT_ALLOW;
    allow_rule.next_layer = LAYER_3_IDX;
    install_l2_rule(loader, 0, ekey, allow_rule);

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

    MM::delete_elem(loader.l2_rules_fd(0), &ekey);
}

TEST(test_pipeline_full_ethertype_drop) {
    // Via entry_prog: ethertype rule drops ARP before reaching L3
    using MM = pktgate::loader::MapManager;

    struct l2_key ekey{};
    ekey.filter_mask = FILTER_MASK_ETHERTYPE;
    ekey.ethertype = htons(0x0806);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 206;
    drop_rule.action = ACT_DROP;
    install_l2_rule(loader, 0, ekey, drop_rule);

    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, 0x0806)
        .pad(64);

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_DROP); // ARP dropped by L2 ethertype rule

    MM::delete_elem(loader.l2_rules_fd(0), &ekey);
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

    struct l2_key ekey{};
    ekey.filter_mask = FILTER_MASK_ETHERTYPE;
    ekey.ethertype = htons(0x86DD);
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 210;
    drop_rule.action = ACT_DROP;
    install_l2_rule(loader, 0, ekey, drop_rule);

    auto pkt = PacketBuilder()
        .eth(UNKNOWN_MAC, DST_MAC, 0x86DD)
        .pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by IPv6 ethertype rule

    MM::delete_elem(loader.l2_rules_fd(0), &ekey);
}

TEST(test_l2_vlan_boundary_4095) {
    // Add vlan_id=4095 rule → DROP. Verify max VLAN ID boundary.
    using MM = pktgate::loader::MapManager;

    struct l2_key vkey{};
    vkey.filter_mask = FILTER_MASK_VLAN;
    vkey.vlan_id = 4095;  // host byte order
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 211;
    drop_rule.action = ACT_DROP;
    install_l2_rule(loader, 0, vkey, drop_rule);

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

    MM::delete_elem(loader.l2_rules_fd(0), &vkey);
}

TEST(test_l2_ethertype_priority_over_vlan) {
    // Add ethertype (0x0800→DROP) and vlan (100→ALLOW) rules.
    // BPF checks ethertype BEFORE vlan, so ethertype wins → DROP.
    using MM = pktgate::loader::MapManager;

    struct l2_key ekey{};
    ekey.filter_mask = FILTER_MASK_ETHERTYPE;
    ekey.ethertype = htons(0x0800);
    struct l2_rule etype_drop{};
    etype_drop.rule_id = 212;
    etype_drop.action = ACT_DROP;
    install_l2_rule(loader, 0, ekey, etype_drop);

    struct l2_key vkey{};
    vkey.filter_mask = FILTER_MASK_VLAN;
    vkey.vlan_id = 100;
    struct l2_rule vlan_allow{};
    vlan_allow.rule_id = 213;
    vlan_allow.action = ACT_ALLOW;
    vlan_allow.next_layer = LAYER_3_IDX;
    install_l2_rule(loader, 0, vkey, vlan_allow);

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

    MM::delete_elem(loader.l2_rules_fd(0), &ekey);
    MM::delete_elem(loader.l2_rules_fd(0), &vkey);
}

TEST(test_l2_allow_terminal_no_next_layer) {
    // Add src_mac rule with ACT_ALLOW and next_layer=0 (terminal).
    // Packet should get XDP_PASS at L2 (line 73-74 of layer2.bpf.c).
    using MM = pktgate::loader::MapManager;

    uint8_t term_mac[6] = {0xFE, 0xED, 0xFA, 0xCE, 0x00, 0x01};
    struct l2_key mkey{};
    mkey.filter_mask = FILTER_MASK_SRCMAC;
    memcpy(mkey.src_mac, term_mac, 6);
    struct l2_rule allow_term{};
    allow_term.rule_id = 214;
    allow_term.action = ACT_ALLOW;
    allow_term.next_layer = 0; // terminal — no next layer
    install_l2_rule(loader, 0, mkey, allow_term);

    auto pkt = PacketBuilder()
        .eth(term_mac, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.100"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // terminal ALLOW at L2 → XDP_PASS

    MM::delete_elem(loader.l2_rules_fd(0), &mkey);
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
// Additional L2 Tests
// ═══════════════════════════════════════════════════════════

TEST(test_l2_pcp_match_drop) {
    // PCP primary lookup: VLAN-tagged packet with PCP=5 → PCP rule → DROP.
    using MM = pktgate::loader::MapManager;

    struct l2_key pk{};
    pk.filter_mask = FILTER_MASK_PCP;
    pk.pcp = 5;
    struct l2_rule drop_rule{};
    drop_rule.rule_id = 900;
    drop_rule.action = ACT_DROP;
    install_l2_rule(loader, 0, pk, drop_rule);

    // Build 802.1Q tagged packet with PCP=5, VID=100
    // PCP occupies bits 15-13 of TCI, VID is bits 11-0
    // TCI = (PCP << 13) | VID = (5 << 13) | 100 = 0xA064
    PacketBuilder pkt;
    struct ethhdr eh{};
    memcpy(eh.h_source, UNKNOWN_MAC, 6);
    memcpy(eh.h_dest, DST_MAC, 6);
    eh.h_proto = htons(0x8100);
    pkt.buf.resize(sizeof(eh));
    memcpy(pkt.buf.data(), &eh, sizeof(eh));

    uint16_t tci = htons((5 << 13) | 100);
    pkt.buf.push_back(static_cast<uint8_t>(tci >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(tci & 0xFF));

    uint16_t inner_proto = htons(ETH_P_IP);
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto & 0xFF));

    pkt.pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // dropped by PCP rule

    MM::delete_elem(loader.l2_rules_fd(0), &pk);
}

TEST(test_l2_secondary_ethertype_mismatch) {
    // src_mac ALLOW rule with L2_FILTER_ETHERTYPE=IPv4. Send IPv6 from that MAC.
    // Secondary filter fails → rule doesn't match → falls through.
    // No other rule matches → tail to L3 → L3 sees 0x86DD → IPv6 path → no subnet6 → default DROP.
    using MM = pktgate::loader::MapManager;

    uint8_t test_src[6] = {0x02, 0x00, 0x00, 0x00, 0xFF, 0x01};
    // Compound rule: src_mac AND ethertype constraints — now expressed by
    // setting both bits in the key's filter_mask and populating both fields.
    struct l2_key mk{};
    mk.filter_mask = FILTER_MASK_SRCMAC | FILTER_MASK_ETHERTYPE;
    memcpy(mk.src_mac, test_src, 6);
    mk.ethertype = htons(0x0800); // expect IPv4
    struct l2_rule allow_rule{};
    allow_rule.rule_id = 901;
    allow_rule.action = ACT_ALLOW;
    allow_rule.next_layer = 0; // terminal allow
    install_l2_rule(loader, 0, mk, allow_rule);

    // Send IPv6 packet (0x86DD) from that MAC
    auto pkt = PacketBuilder()
        .eth(test_src, DST_MAC, 0x86DD)
        .pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    // Secondary ethertype filter rejects → no L2 match → tail to L3 → IPv6 path → no rule → default DROP
    assert(res.retval == XDP_DROP);

    MM::delete_elem(loader.l2_rules_fd(0), &mk);
}

TEST(test_l2_secondary_vlan_mismatch) {
    // src_mac ALLOW rule with L2_FILTER_VLAN=200. Send VLAN 300 from that MAC.
    // Secondary VLAN filter fails → rule doesn't match → falls through → DROP.
    using MM = pktgate::loader::MapManager;

    uint8_t test_src[6] = {0x02, 0x00, 0x00, 0x00, 0xFF, 0x02};
    struct l2_key mk{};
    mk.filter_mask = FILTER_MASK_SRCMAC | FILTER_MASK_VLAN;
    memcpy(mk.src_mac, test_src, 6);
    mk.vlan_id = 200; // host byte order
    struct l2_rule allow_rule{};
    allow_rule.rule_id = 902;
    allow_rule.action = ACT_ALLOW;
    allow_rule.next_layer = 0; // terminal allow
    install_l2_rule(loader, 0, mk, allow_rule);

    // Build 802.1Q tagged packet with VID=300 (mismatch)
    PacketBuilder pkt;
    struct ethhdr eh{};
    memcpy(eh.h_source, test_src, 6);
    memcpy(eh.h_dest, DST_MAC, 6);
    eh.h_proto = htons(0x8100);
    pkt.buf.resize(sizeof(eh));
    memcpy(pkt.buf.data(), &eh, sizeof(eh));

    uint16_t tci = htons(300); // VID=300
    pkt.buf.push_back(static_cast<uint8_t>(tci >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(tci & 0xFF));

    uint16_t inner_proto = htons(ETH_P_IP);
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto >> 8));
    pkt.buf.push_back(static_cast<uint8_t>(inner_proto & 0xFF));

    pkt.pad(64);

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    // Secondary VLAN filter fails → no L2 match → tail to L3 → 0x8100 is neither v4 nor v6 → DROP
    assert(res.retval == XDP_DROP);

    MM::delete_elem(loader.l2_rules_fd(0), &mk);
}

TEST(test_l2_mirror_action) {
    // ACT_MIRROR sets action_flags and mirror_ifindex in metadata, then continues.
    // Terminal mirror (next_layer=0) → XDP_PASS.
    using MM = pktgate::loader::MapManager;

    uint8_t mirr_src[6] = {0x02, 0x00, 0x00, 0x00, 0xFF, 0x03};
    struct l2_key mk{};
    mk.filter_mask = FILTER_MASK_SRCMAC;
    memcpy(mk.src_mac, mirr_src, 6);
    struct l2_rule mirr_rule{};
    mirr_rule.rule_id = 903;
    mirr_rule.action = ACT_MIRROR;
    mirr_rule.mirror_ifindex = 42;
    mirr_rule.next_layer = 0; // terminal
    install_l2_rule(loader, 0, mk, mirr_rule);

    auto pkt = PacketBuilder()
        .eth(mirr_src, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // mirror is non-terminal: sets flags, then terminal ALLOW → PASS

    MM::delete_elem(loader.l2_rules_fd(0), &mk);
}

TEST(test_l2_vlan_truncated_drop) {
    // Packet with 0x8100 ethertype but too short for VLAN TCI (only 14 bytes of eth).
    // Should fail the bounds check in L2 VLAN parsing → STAT_DROP_L2_BOUNDS → XDP_DROP.
    PacketBuilder pkt;
    struct ethhdr eh{};
    memcpy(eh.h_source, UNKNOWN_MAC, 6);
    memcpy(eh.h_dest, DST_MAC, 6);
    eh.h_proto = htons(0x8100);
    pkt.buf.resize(sizeof(eh));
    memcpy(pkt.buf.data(), &eh, sizeof(eh));

    // Only add 2 bytes (need 4: TCI + inner ethertype)
    pkt.buf.push_back(0x00);
    pkt.buf.push_back(0x64);
    // Do NOT add inner ethertype — truncated

    auto res = run_xdp_prog(loader.layer2_prog_fd(), pkt.data(), pkt.size(), 1, true);
    if (!res.ok) {
        // Some kernels reject packets this small
        std::cout << "    [skip] kernel rejected truncated VLAN packet\n";
        return;
    }
    assert(res.retval == XDP_DROP); // L2 bounds check fails for truncated VLAN
}

// ═══════════════════════════════════════════════════════════
// Additional L3 Tests
// ═══════════════════════════════════════════════════════════

/// Helper: build a minimal IPv6 packet with given nexthdr and src/dst addresses.
/// Returns a PacketBuilder with Ethernet + IPv6 header. Caller should add L4 or pad.
static PacketBuilder build_ipv6_packet(const uint8_t src_mac[6], const uint8_t dst_mac[6],
                                        uint8_t nexthdr,
                                        const char* src_v6, const char* dst_v6,
                                        uint16_t payload_len = 0) {
    PacketBuilder pkt;
    // Ethernet header
    pkt.eth(src_mac, dst_mac, 0x86DD);

    // IPv6 header (40 bytes)
    size_t off = pkt.buf.size();
    pkt.buf.resize(off + 40, 0);
    uint8_t* ip6 = pkt.buf.data() + off;

    // Version (4) + Traffic Class (8) + Flow Label (20) = first 4 bytes
    ip6[0] = 0x60; // version=6, traffic class high nibble=0
    ip6[1] = 0x00; // traffic class low + flow label high
    ip6[2] = 0x00;
    ip6[3] = 0x00;

    // Payload length (2 bytes, network byte order)
    uint16_t plen_nbo = htons(payload_len);
    memcpy(ip6 + 4, &plen_nbo, 2);

    // Next header
    ip6[6] = nexthdr;

    // Hop limit
    ip6[7] = 64;

    // Source address
    struct in6_addr saddr{}, daddr{};
    inet_pton(AF_INET6, src_v6, &saddr);
    inet_pton(AF_INET6, dst_v6, &daddr);
    memcpy(ip6 + 8, &saddr, 16);
    memcpy(ip6 + 24, &daddr, 16);

    return pkt;
}

TEST(test_l3_ipv6_lpm_match) {
    // Add IPv6 subnet rule: 2001:db8::/32 → DROP. Send 2001:db8::1 → should match → DROP.
    using MM = pktgate::loader::MapManager;

    struct lpm_v6_key lpm6_drop{};
    lpm6_drop.prefixlen = 32;
    // 2001:0db8:: → first 4 bytes = 0x20, 0x01, 0x0d, 0xb8
    struct in6_addr net_addr{};
    inet_pton(AF_INET6, "2001:db8::", &net_addr);
    memcpy(lpm6_drop.addr, &net_addr, 16);

    struct l3_rule l3_drop{};
    l3_drop.rule_id = 300;
    l3_drop.action = ACT_DROP;
    auto r = MM::update_elem(loader.subnet6_rules_fd(0), &lpm6_drop, &l3_drop, BPF_ANY);
    assert(r.has_value());

    auto pkt = build_ipv6_packet(KNOWN_MAC, DST_MAC, IPPROTO_TCP,
                                  "2001:db8::1", "2001:db8::2", 20);
    pkt.tcp(1234, 80);
    pkt.pad(86); // eth(14) + ipv6(40) + tcp(20) + padding

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // IPv6 subnet match → DROP

    MM::delete_elem(loader.subnet6_rules_fd(0), &lpm6_drop);
}

TEST(test_l3_ipv6_fragment_dropped) {
    // IPv6 with nexthdr=44 (Fragment Header) → L3 drops immediately.
    auto pkt = build_ipv6_packet(KNOWN_MAC, DST_MAC, 44, // nexthdr=44 (Fragment)
                                  "2001:db8::1", "2001:db8::2", 8);
    // Add 8 bytes of fragment header stub
    for (int i = 0; i < 8; i++)
        pkt.buf.push_back(0);
    pkt.pad(64);

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // IPv6 fragment → dropped
}

TEST(test_l3_mirror_metadata) {
    // ACT_MIRROR in L3 sets mirror_ifindex in metadata, packet continues.
    // With has_next_layer=0 → terminal → XDP_PASS.
    using MM = pktgate::loader::MapManager;

    struct lpm_v4_key lpm_mirr = { .prefixlen = 32, .addr = ip_nbo("172.20.0.1") };
    struct l3_rule mirr_rule{};
    mirr_rule.rule_id = 301;
    mirr_rule.action = ACT_MIRROR;
    mirr_rule.mirror_ifindex = 77;
    mirr_rule.has_next_layer = 0; // terminal
    auto r = MM::update_elem(loader.subnet_rules_fd(0), &lpm_mirr, &mirr_rule, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("172.20.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // MIRROR sets flags, terminal → PASS

    MM::delete_elem(loader.subnet_rules_fd(0), &lpm_mirr);
}

TEST(test_l3_redirect_zero_ifindex) {
    // ACT_REDIRECT with ifindex=0 → STAT_DROP_L3_REDIRECT_FAIL → XDP_DROP.
    using MM = pktgate::loader::MapManager;

    struct lpm_v4_key lpm_redir = { .prefixlen = 32, .addr = ip_nbo("172.21.0.1") };
    struct l3_rule redir_rule{};
    redir_rule.rule_id = 302;
    redir_rule.action = ACT_REDIRECT;
    redir_rule.redirect_ifindex = 0; // invalid
    auto r = MM::update_elem(loader.subnet_rules_fd(0), &lpm_redir, &redir_rule, BPF_ANY);
    assert(r.has_value());

    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("172.21.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // redirect with ifindex=0 → DROP

    MM::delete_elem(loader.subnet_rules_fd(0), &lpm_redir);
}

// ═══════════════════════════════════════════════════════════
// Additional L4 Tests
// ═══════════════════════════════════════════════════════════

TEST(test_l4_ipv6_tcp_match) {
    // IPv6 TCP:80 → matches existing TCP:80 ALLOW rule in L4.
    auto pkt = build_ipv6_packet(KNOWN_MAC, DST_MAC, IPPROTO_TCP,
                                  "2001:db8::10", "2001:db8::20", 20);
    pkt.tcp(4321, 80);
    pkt.pad(86);

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // TCP:80 ALLOW matches for IPv6 too
}

TEST(test_l4_ipv6_ext_header_chain) {
    // IPv6 with Hop-by-Hop(0) + Routing(43) extension headers → TCP:80 → ALLOW.
    // L4 should skip extension headers and find TCP.
    PacketBuilder pkt;
    pkt.eth(KNOWN_MAC, DST_MAC, 0x86DD);

    // IPv6 header: nexthdr=0 (Hop-by-Hop Options)
    size_t off = pkt.buf.size();
    pkt.buf.resize(off + 40, 0);
    uint8_t* ip6 = pkt.buf.data() + off;
    ip6[0] = 0x60;
    // Payload length: HbH(8) + Routing(8) + TCP(20) = 36
    uint16_t plen = htons(36);
    memcpy(ip6 + 4, &plen, 2);
    ip6[6] = 0;   // nexthdr = Hop-by-Hop Options
    ip6[7] = 64;  // hop limit
    struct in6_addr saddr{}, daddr{};
    inet_pton(AF_INET6, "2001:db8::10", &saddr);
    inet_pton(AF_INET6, "2001:db8::20", &daddr);
    memcpy(ip6 + 8, &saddr, 16);
    memcpy(ip6 + 24, &daddr, 16);

    // Hop-by-Hop extension header (8 bytes: nexthdr=43, len=0 → 8 bytes)
    pkt.buf.push_back(43);  // next header = Routing
    pkt.buf.push_back(0);   // header ext len = 0 → (0+1)*8 = 8 bytes total
    for (int i = 0; i < 6; i++)
        pkt.buf.push_back(0); // padding

    // Routing extension header (8 bytes: nexthdr=6(TCP), len=0 → 8 bytes)
    pkt.buf.push_back(6);   // next header = TCP
    pkt.buf.push_back(0);   // header ext len = 0 → 8 bytes total
    for (int i = 0; i < 6; i++)
        pkt.buf.push_back(0); // padding

    // TCP header (port 80)
    pkt.tcp(4321, 80);
    pkt.pad(96);

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // skipped ext headers → TCP:80 → ALLOW
}

TEST(test_l4_ipv6_fragment_after_ext) {
    // IPv6 with Hop-by-Hop(0) ext → then nexthdr=44 (Fragment).
    // L4 stops at fragment header and drops defensively.
    PacketBuilder pkt;
    pkt.eth(KNOWN_MAC, DST_MAC, 0x86DD);

    // IPv6 header: nexthdr=0 (Hop-by-Hop)
    size_t off = pkt.buf.size();
    pkt.buf.resize(off + 40, 0);
    uint8_t* ip6 = pkt.buf.data() + off;
    ip6[0] = 0x60;
    uint16_t plen = htons(16); // HbH(8) + Fragment(8)
    memcpy(ip6 + 4, &plen, 2);
    ip6[6] = 0;   // nexthdr = Hop-by-Hop
    ip6[7] = 64;
    struct in6_addr saddr{}, daddr{};
    inet_pton(AF_INET6, "2001:db8::30", &saddr);
    inet_pton(AF_INET6, "2001:db8::40", &daddr);
    memcpy(ip6 + 8, &saddr, 16);
    memcpy(ip6 + 24, &daddr, 16);

    // Hop-by-Hop ext header: nexthdr=44 (Fragment), len=0 → 8 bytes
    pkt.buf.push_back(44);  // next header = Fragment
    pkt.buf.push_back(0);   // len=0 → 8 bytes
    for (int i = 0; i < 6; i++)
        pkt.buf.push_back(0);

    // Fragment header stub (8 bytes)
    for (int i = 0; i < 8; i++)
        pkt.buf.push_back(0);

    pkt.pad(80);

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // fragment after ext headers → DROP
}

// ── #4 IPv6-as-a-class regression tests ─────────────────────────

TEST(test_l3_stamps_ip_family_v4) {
    // After L3 processes an IPv4 packet, meta->ip_family must equal IP_FAMILY_V4.
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.5"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto out = run_layer_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size());
    assert(out.run.ok);
    assert(out.meta.ip_family == IP_FAMILY_V4);
}

TEST(test_l3_stamps_ip_family_v6) {
    // After L3 processes an IPv6 packet, meta->ip_family must equal IP_FAMILY_V6.
    auto pkt = build_ipv6_packet(KNOWN_MAC, DST_MAC, IPPROTO_TCP,
                                  "2001:db8::1", "2001:db8::2", 20);
    pkt.tcp(1234, 80);
    pkt.pad(86);

    auto out = run_layer_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size());
    assert(out.run.ok);
    assert(out.meta.ip_family == IP_FAMILY_V6);
}

TEST(test_l4_ipv6_ext_chain_depth_5_fail_closed) {
    // P0-04: a chain of 5 Hop-by-Hop ext headers used to leave nhdr in
    // {0,43,60} after the bounded walk and silently bypass all L4 rules and
    // rate-limit via the default action. With the fix, the walker fails
    // closed: XDP_DROP regardless of default_action.
    //
    // To prove the failure mode, switch default_action to ALLOW for this
    // test — pre-fix the packet would pass, post-fix it drops.
    using MM = pktgate::loader::MapManager;

    uint32_t da_key = 0;
    uint32_t da_val = ACT_ALLOW;
    auto r = MM::update_elem(loader.default_action_fd(0), &da_key, &da_val, BPF_ANY);
    assert(r.has_value());

    PacketBuilder pkt;
    pkt.eth(KNOWN_MAC, DST_MAC, 0x86DD);
    size_t off = pkt.buf.size();
    pkt.buf.resize(off + 40, 0);
    uint8_t* ip6 = pkt.buf.data() + off;
    ip6[0] = 0x60;
    uint16_t plen = htons(5 * 8 + 20); // 5 HBH + TCP
    memcpy(ip6 + 4, &plen, 2);
    ip6[6] = 0;   // nexthdr = Hop-by-Hop
    ip6[7] = 64;
    struct in6_addr saddr{}, daddr{};
    inet_pton(AF_INET6, "2001:db8::101", &saddr);
    inet_pton(AF_INET6, "2001:db8::102", &daddr);
    memcpy(ip6 + 8, &saddr, 16);
    memcpy(ip6 + 24, &daddr, 16);

    // Five Hop-by-Hop headers. First four are HBH → HBH; the fifth → TCP.
    for (int i = 0; i < 4; i++) {
        pkt.buf.push_back(0);  // next = HBH
        pkt.buf.push_back(0);  // len = 0 → 8 bytes
        for (int j = 0; j < 6; j++) pkt.buf.push_back(0);
    }
    pkt.buf.push_back(6);      // fifth HBH: next = TCP
    pkt.buf.push_back(0);
    for (int j = 0; j < 6; j++) pkt.buf.push_back(0);

    pkt.tcp(4321, 80);
    pkt.pad(120);

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);  // walker fails closed

    // Restore default for sibling tests.
    da_val = ACT_DROP;
    MM::update_elem(loader.default_action_fd(0), &da_key, &da_val, BPF_ANY);
}

TEST(test_l3_ipv6_fragment_behind_hbh_drops) {
    // P1#8: a Hop-by-Hop → Fragment chain previously hid the Fragment from
    // L3's immediate-nexthdr check; a terminal-ALLOW L3 rule would let the
    // non-first-fragment-equivalent payload through to userspace. With the
    // fix, L3 walks ext headers and drops at any depth.
    using MM = pktgate::loader::MapManager;

    // Add terminal-ALLOW L3 rule for 2001:db8::/32 so the pre-fix path would
    // bypass L4's defensive frag drop.
    struct lpm_v6_key lpm6_allow{};
    lpm6_allow.prefixlen = 32;
    struct in6_addr net_addr{};
    inet_pton(AF_INET6, "2001:db8::", &net_addr);
    memcpy(lpm6_allow.addr, &net_addr, 16);
    struct l3_rule l3_allow{};
    l3_allow.rule_id = 333;
    l3_allow.action = ACT_ALLOW;   // terminal — no next_layer
    auto r = MM::update_elem(loader.subnet6_rules_fd(0), &lpm6_allow, &l3_allow, BPF_ANY);
    assert(r.has_value());

    PacketBuilder pkt;
    pkt.eth(KNOWN_MAC, DST_MAC, 0x86DD);
    size_t off = pkt.buf.size();
    pkt.buf.resize(off + 40, 0);
    uint8_t* ip6 = pkt.buf.data() + off;
    ip6[0] = 0x60;
    uint16_t plen = htons(16); // HBH(8) + Fragment(8)
    memcpy(ip6 + 4, &plen, 2);
    ip6[6] = 0;   // Hop-by-Hop
    ip6[7] = 64;
    struct in6_addr saddr{}, daddr{};
    inet_pton(AF_INET6, "2001:db8::501", &saddr);
    inet_pton(AF_INET6, "2001:db8::502", &daddr);
    memcpy(ip6 + 8, &saddr, 16);
    memcpy(ip6 + 24, &daddr, 16);

    // HBH ext header: next = Fragment (44)
    pkt.buf.push_back(44);
    pkt.buf.push_back(0);
    for (int i = 0; i < 6; i++) pkt.buf.push_back(0);
    // Fragment header stub (8 bytes)
    for (int i = 0; i < 8; i++) pkt.buf.push_back(0);
    pkt.pad(80);

    auto res = run_xdp_prog(loader.layer3_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);  // L3 walker catches the fragment

    MM::delete_elem(loader.subnet6_rules_fd(0), &lpm6_allow);
}

TEST(test_tc_ipv6_tag_does_not_corrupt) {
    // P0-03: ACT_TAG previously hard-coded IPv4 byte offsets, smashing the
    // IPv6 Flow Label byte and writing a 16-bit checksum delta into the
    // source-address bytes (IPv6 has no L3 checksum at offset 24). The fix
    // gates the rewrite on ip_family — for V6 it becomes a no-op and bumps
    // STAT_TC_TAG_V6_UNIMPL. This test verifies the IPv6 packet body is
    // returned byte-for-byte unchanged.

    auto pkt = build_ipv6_packet(KNOWN_MAC, DST_MAC, IPPROTO_TCP,
                                  "2001:db8::abcd", "2001:db8::dcba", 20);
    pkt.tcp(1234, 80);
    pkt.pad(86);

    // Build pkt_meta as L4 would have set it for a TAG-targeted IPv6 packet.
    constexpr uint32_t meta_sz = sizeof(struct pkt_meta);
    std::vector<uint8_t> data_with_meta(meta_sz + pkt.size());
    struct pkt_meta meta{};
    meta.generation = 0;
    meta.ip_family = IP_FAMILY_V6;
    meta.action_flags = (1u << ACT_TAG);
    meta.dscp = 46;  // EF — would corrupt v6 Flow Label byte under pre-fix code
    memcpy(data_with_meta.data(), &meta, meta_sz);
    memcpy(data_with_meta.data() + meta_sz, pkt.data(), pkt.size());

    std::vector<uint8_t> data_out(meta_sz + pkt.size() + 64, 0);

    struct __sk_buff skb_ctx{};
    skb_ctx.data_meta = 0;
    skb_ctx.data      = meta_sz;
    skb_ctx.data_end  = meta_sz + pkt.size();

    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in  = data_with_meta.data(),
        .data_out = data_out.data(),
        .data_size_in  = static_cast<__u32>(data_with_meta.size()),
        .data_size_out = static_cast<__u32>(data_out.size()),
        .ctx_in  = &skb_ctx,
        .ctx_size_in  = sizeof(skb_ctx),
        .repeat = 1,
    );

    int err = bpf_prog_test_run_opts(loader.tc_ingress_prog_fd(), &opts);
    if (err != 0) {
        // Some kernels return -ENOTSUPP for BPF_PROG_TEST_RUN on TC/clsact
        // programs. The fix is verified by the per-test stat path; this
        // test surface is best-effort under PROG_TEST_RUN.
        std::cout << "    [skip] kernel rejected TC PROG_TEST_RUN (err=" << err << ")\n";
        return;
    }

    // Critical: the IPv6 header bytes (Flow Label byte 1, source address
    // bytes 8-23, dest 24-39) must be untouched.
    const uint8_t* before = pkt.data() + 14;       // skip Ethernet
    const uint8_t* after  = data_out.data() + meta_sz + 14;
    for (size_t i = 0; i < 40; i++) {
        if (before[i] != after[i]) {
            std::cout << "    [v6 corruption at IPv6 byte " << i
                      << "] before=0x" << std::hex << (int)before[i]
                      << " after=0x" << (int)after[i] << std::dec << "\n";
            assert(false && "IPv6 header corrupted by TC ACT_TAG");
        }
    }
}

TEST(test_l4_rate_limit_depletion) {
    // Verify rate limiter drops when tokens are exhausted.
    // rate_state_map is PERCPU — must write per-cpu values from userspace.
    // Strategy: pre-populate rate_state with tokens=0, tiny rate (8000 bps = 1000 B/s),
    // and recent last_refill. Even after 1s max refill, tokens=1 < packet size → DROP.

    uint32_t rid = 102; // TCP:443 rule
    bpf_map_delete_elem(loader.rate_state_fd(), &rid);

    // Per-CPU map needs one value per CPU
    int ncpus = libbpf_num_possible_cpus();
    std::vector<struct rate_state> percpu_rs(ncpus);

    // Get approximate ktime for last_refill
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    for (int i = 0; i < ncpus; i++) {
        percpu_rs[i].tokens = 0;
        percpu_rs[i].last_refill = now_ns;
        percpu_rs[i].rate_bps = 8000; // 1000 bytes/sec → max 1s refill = 1000 < 1414
    }
    bpf_map_update_elem(loader.rate_state_fd(), &rid, percpu_rs.data(), BPF_ANY);

    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP, 1380)
        .tcp(1234, 443);
    pkt.pad(1414);

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP);

    bpf_map_delete_elem(loader.rate_state_fd(), &rid);
}

TEST(test_l4_tcp_flags_partial_mismatch) {
    // Add rule for TCP:9090 requiring SYN+PSH set. Send packet with only SYN → default.
    using MM = pktgate::loader::MapManager;

    struct l4_match_key l4k = { .protocol = 6, ._pad = 0, .dst_port = 9090 };
    struct l4_rule l4r{};
    l4r.rule_id = 110;
    l4r.action = ACT_ALLOW;
    l4r.tcp_flags_set = TCPF_SYN | TCPF_PSH;  // require both SYN and PSH
    auto r = MM::update_elem(loader.l4_rules_fd(0), &l4k, &l4r, BPF_ANY);
    assert(r.has_value());

    // Send only SYN (missing PSH) → flags_set check fails → default action
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 9090, TCPF_SYN) // only SYN, no PSH
        .pad();

    auto res = run_xdp_prog(loader.layer4_prog_fd(), pkt.data(), pkt.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_DROP); // flags mismatch → default DROP

    // Also verify: SYN+PSH → ALLOW (positive check)
    auto pkt2 = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 9090, TCPF_SYN | TCPF_PSH)
        .pad();

    res = run_xdp_prog(loader.layer4_prog_fd(), pkt2.data(), pkt2.size(), 1, true);
    assert(res.ok);
    assert(res.retval == XDP_PASS); // SYN+PSH present → ALLOW

    MM::delete_elem(loader.l4_rules_fd(0), &l4k);
}

// ═══════════════════════════════════════════════════════════
// Additional Integration / Pipeline Tests
// ═══════════════════════════════════════════════════════════

TEST(test_pipeline_ipv6_full_tcp80) {
    // Full pipeline: Entry → L2 (no MAC match, fall through) → L3 (IPv6 no subnet6 match,
    // no VRF → tail to L4) → L4 (IPv6 TCP:80 → ALLOW) → PASS.
    auto pkt = build_ipv6_packet(UNKNOWN_MAC, DST_MAC, IPPROTO_TCP,
                                  "fd00::1", "fd00::2", 20);
    pkt.tcp(4321, 80);
    pkt.pad(86);

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_PASS); // IPv6 through full pipeline → TCP:80 ALLOW
}

TEST(test_pipeline_ipv6_fragment_dropped_at_l3) {
    // Full pipeline: Entry → L2 (no match) → L3 (IPv6, nexthdr=44 Fragment) → DROP.
    // Verifies that IPv6 fragment detection works through the full pipeline.
    auto pkt = build_ipv6_packet(UNKNOWN_MAC, DST_MAC, 44, // Fragment header
                                  "fd00::10", "fd00::20", 8);
    for (int i = 0; i < 8; i++)
        pkt.buf.push_back(0); // fragment header stub
    pkt.pad(72);

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_DROP); // IPv6 fragment dropped at L3
}

TEST(test_pipeline_l2_mirror_l3_continues) {
    // L2 mirror rule + next_layer=L3: packet should have mirror flags set,
    // then continue to L3→L4. Verify final verdict is based on L3/L4.
    // Use KNOWN_MAC override with MIRROR + next_layer=L3.
    using MM = pktgate::loader::MapManager;

    // Save original KNOWN_MAC rule, replace with MIRROR + L3
    struct l2_key mkey{};
    mkey.filter_mask = FILTER_MASK_SRCMAC;
    memcpy(mkey.src_mac, KNOWN_MAC, 6);
    struct l2_rule orig_rule{};
    bpf_map_lookup_elem(loader.l2_rules_fd(0), &mkey, &orig_rule);

    struct l2_rule mirr_rule{};
    mirr_rule.rule_id = 910;
    mirr_rule.action = ACT_MIRROR;
    mirr_rule.mirror_ifindex = 99;
    mirr_rule.next_layer = LAYER_3_IDX;
    auto r = MM::update_elem(loader.l2_rules_fd(0), &mkey, &mirr_rule, BPF_ANY);
    assert(r.has_value());

    // 10.0.0.1 → L3 ALLOW+next → L4 TCP:80 → ALLOW → XDP_PASS
    auto pkt = PacketBuilder()
        .eth(KNOWN_MAC, DST_MAC, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP)
        .tcp(1234, 80)
        .pad();

    auto res = run_xdp_prog(loader.entry_prog_fd(), pkt.data(), pkt.size());
    assert(res.ok);
    assert(res.retval == XDP_PASS); // mirror sets flags, continues to L3→L4 → PASS

    // Restore original rule
    r = MM::update_elem(loader.l2_rules_fd(0), &mkey, &orig_rule, BPF_ANY);
    assert(r.has_value());
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
