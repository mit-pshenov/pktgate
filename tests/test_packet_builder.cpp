/*
 * PacketBuilder verification: validate crafted packet headers are correct.
 * Runs without root — pure userspace byte verification.
 */
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

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry { const char* name; void (*fn)(); };
static std::vector<TestEntry> tests;

// ── PacketBuilder (copied from bpf test, tested independently) ──

struct PacketBuilder {
    std::vector<uint8_t> buf;

    PacketBuilder() { buf.reserve(128); }

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

    PacketBuilder& pad(size_t min_size = 64) {
        if (buf.size() < min_size)
            buf.resize(min_size, 0);
        return *this;
    }

    const uint8_t* data() const { return buf.data(); }
    uint32_t size() const { return static_cast<uint32_t>(buf.size()); }
};

// Safe unaligned read helper — copies from packet buffer to aligned struct
template<typename T>
static T read_hdr(const uint8_t* ptr) {
    T h;
    memcpy(&h, ptr, sizeof(T));
    return h;
}

static uint32_t ip_nbo(const char* ip) {
    uint32_t addr;
    inet_pton(AF_INET, ip, &addr);
    return addr;
}

// ═══════════════════════════════════════════════════════════
// Ethernet header verification
// ═══════════════════════════════════════════════════════════

TEST(eth_header_size_14) {
    assert(sizeof(struct ethhdr) == 14);
}

TEST(eth_src_dst_mac_correct) {
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t dst[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    auto pkt = PacketBuilder().eth(src, dst, ETH_P_IP);
    assert(pkt.size() == 14);

    auto eth = read_hdr<struct ethhdr>(pkt.data());
    assert(memcmp(eth.h_source, src, 6) == 0);
    assert(memcmp(eth.h_dest, dst, 6) == 0);
}

TEST(eth_proto_is_network_byte_order) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder().eth(mac, mac, ETH_P_IP);

    auto eth = read_hdr<struct ethhdr>(pkt.data());
    assert(eth.h_proto == htons(ETH_P_IP));
    // Raw bytes: 0x08, 0x00
    assert(pkt.data()[12] == 0x08);
    assert(pkt.data()[13] == 0x00);
}

TEST(eth_arp_proto) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder().eth(mac, mac, 0x0806);

    assert(pkt.data()[12] == 0x08);
    assert(pkt.data()[13] == 0x06);
}

// ═══════════════════════════════════════════════════════════
// IPv4 header verification
// ═══════════════════════════════════════════════════════════

TEST(ipv4_header_at_offset_14) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.1"), ip_nbo("10.0.0.1"), IPPROTO_TCP);

    assert(pkt.size() == 14 + 20); // ETH + IP

    auto iph = read_hdr<struct iphdr>(pkt.data() + 14);
    assert(iph.version == 4);
    assert(iph.ihl == 5);
    assert(iph.ttl == 64);
    assert(iph.protocol == IPPROTO_TCP);
}

TEST(ipv4_src_dst_nbo) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("192.168.1.1"), ip_nbo("10.0.0.1"), IPPROTO_UDP);

    auto iph = read_hdr<struct iphdr>(pkt.data() + 14);
    assert(iph.saddr == ip_nbo("192.168.1.1"));
    assert(iph.daddr == ip_nbo("10.0.0.1"));
}

TEST(ipv4_tot_len_correct) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("1.1.1.1"), ip_nbo("2.2.2.2"), IPPROTO_TCP, 20);

    auto iph = read_hdr<struct iphdr>(pkt.data() + 14);
    // tot_len = iphdr(20) + payload(20) = 40
    assert(ntohs(iph.tot_len) == 40);
}

TEST(ipv4_protocol_field_tcp_6) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("1.1.1.1"), ip_nbo("2.2.2.2"), IPPROTO_TCP);

    auto iph = read_hdr<struct iphdr>(pkt.data() + 14);
    assert(iph.protocol == 6);
}

TEST(ipv4_protocol_field_udp_17) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("1.1.1.1"), ip_nbo("2.2.2.2"), IPPROTO_UDP);

    auto iph = read_hdr<struct iphdr>(pkt.data() + 14);
    assert(iph.protocol == 17);
}

// ═══════════════════════════════════════════════════════════
// TCP header verification
// ═══════════════════════════════════════════════════════════

TEST(tcp_header_at_offset_34) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("1.1.1.1"), ip_nbo("2.2.2.2"), IPPROTO_TCP)
        .tcp(12345, 80);

    // ETH(14) + IP(20) + TCP(20) = 54
    assert(pkt.size() == 54);

    auto tcp = read_hdr<struct tcphdr>(pkt.data() + 34);
    assert(ntohs(tcp.source) == 12345);
    assert(ntohs(tcp.dest) == 80);
    assert(tcp.doff == 5);
}

TEST(tcp_ports_network_byte_order) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("1.1.1.1"), ip_nbo("2.2.2.2"), IPPROTO_TCP)
        .tcp(0x1234, 0x5678);

    auto tcp = read_hdr<struct tcphdr>(pkt.data() + 34);
    // In NBO: 0x1234 → bytes 0x12, 0x34
    assert(pkt.data()[34] == 0x12);
    assert(pkt.data()[35] == 0x34);
    assert(pkt.data()[36] == 0x56);
    assert(pkt.data()[37] == 0x78);
}

// ═══════════════════════════════════════════════════════════
// UDP header verification
// ═══════════════════════════════════════════════════════════

TEST(udp_header_at_offset_34) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("1.1.1.1"), ip_nbo("2.2.2.2"), IPPROTO_UDP)
        .udp(5353, 53, 8);

    // ETH(14) + IP(20) + UDP(8) = 42
    assert(pkt.size() == 42);

    auto udp = read_hdr<struct udphdr>(pkt.data() + 34);
    assert(ntohs(udp.source) == 5353);
    assert(ntohs(udp.dest) == 53);
    assert(ntohs(udp.len) == 8);
    assert(udp.check == 0);
}

// ═══════════════════════════════════════════════════════════
// Padding
// ═══════════════════════════════════════════════════════════

TEST(pad_extends_to_minimum) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder().eth(mac, mac, ETH_P_IP).pad(64);
    assert(pkt.size() == 64);
}

TEST(pad_does_not_shrink) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("1.1.1.1"), ip_nbo("2.2.2.2"), IPPROTO_TCP)
        .tcp(1, 2)
        .pad(10); // 54 bytes already, pad(10) should not shrink

    assert(pkt.size() == 54);
}

TEST(pad_fills_with_zeros) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder().eth(mac, mac, ETH_P_IP).pad(64);

    // Bytes 14..63 should be zero (padding after ETH header)
    for (size_t i = 14; i < 64; ++i)
        assert(pkt.data()[i] == 0);
}

// ═══════════════════════════════════════════════════════════
// Full packet structure
// ═══════════════════════════════════════════════════════════

TEST(full_tcp_packet_layer_offsets) {
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t dst[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    auto pkt = PacketBuilder()
        .eth(src, dst, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_TCP, 20)
        .tcp(1234, 80)
        .pad();

    assert(pkt.size() == 64);

    // ETH at 0
    auto eth = read_hdr<struct ethhdr>(pkt.data());
    assert(memcmp(eth.h_source, src, 6) == 0);

    // IP at 14
    auto iph = read_hdr<struct iphdr>(pkt.data() + 14);
    assert(iph.version == 4);
    assert(iph.protocol == IPPROTO_TCP);

    // TCP at 34
    auto tcp = read_hdr<struct tcphdr>(pkt.data() + 34);
    assert(ntohs(tcp.dest) == 80);
}

TEST(full_udp_packet_layer_offsets) {
    uint8_t mac[6] = {};
    auto pkt = PacketBuilder()
        .eth(mac, mac, ETH_P_IP)
        .ipv4(ip_nbo("10.0.0.1"), ip_nbo("10.0.0.2"), IPPROTO_UDP, 8)
        .udp(1234, 53)
        .pad();

    // IP at 14
    auto iph = read_hdr<struct iphdr>(pkt.data() + 14);
    assert(iph.protocol == IPPROTO_UDP);
    assert(ntohs(iph.tot_len) == 28); // 20 + 8

    // UDP at 34
    auto udp = read_hdr<struct udphdr>(pkt.data() + 34);
    assert(ntohs(udp.dest) == 53);
}

int main() {
    int passed = 0, failed = 0;
    for (auto& [name, fn] : tests) {
        try {
            fn();
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
