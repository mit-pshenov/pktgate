#include "util/net_types.hpp"
#include <cassert>
#include <iostream>
#include <vector>
#include <arpa/inet.h>

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry {
    const char* name;
    void (*fn)();
};
static std::vector<TestEntry> tests;

using namespace pktgate::util;

// ── MacAddr tests ───────────────────────────────────────────

TEST(test_mac_parse_colon_separator) {
    auto m = MacAddr::parse("00:11:22:33:44:55");
    assert(m.bytes[0] == 0x00);
    assert(m.bytes[1] == 0x11);
    assert(m.bytes[2] == 0x22);
    assert(m.bytes[3] == 0x33);
    assert(m.bytes[4] == 0x44);
    assert(m.bytes[5] == 0x55);
}

TEST(test_mac_parse_dash_separator) {
    auto m = MacAddr::parse("AA-BB-CC-DD-EE-FF");
    assert(m.bytes[0] == 0xAA);
    assert(m.bytes[1] == 0xBB);
    assert(m.bytes[5] == 0xFF);
}

TEST(test_mac_parse_lowercase) {
    auto m = MacAddr::parse("ab:cd:ef:01:23:45");
    assert(m.bytes[0] == 0xAB);
    assert(m.bytes[1] == 0xCD);
    assert(m.bytes[2] == 0xEF);
    assert(m.bytes[3] == 0x01);
    assert(m.bytes[4] == 0x23);
    assert(m.bytes[5] == 0x45);
}

TEST(test_mac_parse_mixed_case) {
    auto m = MacAddr::parse("aB:Cd:eF:01:23:45");
    assert(m.bytes[0] == 0xAB);
    assert(m.bytes[1] == 0xCD);
    assert(m.bytes[2] == 0xEF);
}

TEST(test_mac_broadcast) {
    auto m = MacAddr::parse("FF:FF:FF:FF:FF:FF");
    for (int i = 0; i < 6; ++i)
        assert(m.bytes[i] == 0xFF);
}

TEST(test_mac_all_zeros) {
    auto m = MacAddr::parse("00:00:00:00:00:00");
    for (int i = 0; i < 6; ++i)
        assert(m.bytes[i] == 0x00);
}

TEST(test_mac_parse_too_short) {
    bool threw = false;
    try { MacAddr::parse("00:11:22:33:44"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_mac_parse_too_long) {
    bool threw = false;
    try { MacAddr::parse("00:11:22:33:44:55:66"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_mac_parse_invalid_hex) {
    bool threw = false;
    try { MacAddr::parse("GG:HH:II:JJ:KK:LL"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_mac_parse_bad_separator) {
    bool threw = false;
    try { MacAddr::parse("00X11X22X33X44X55"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_mac_parse_empty) {
    bool threw = false;
    try { MacAddr::parse(""); } catch (...) { threw = true; }
    assert(threw);
}

// ── Ipv4Prefix tests ────────────────────────────────────────

TEST(test_ipv4_prefix_basic) {
    auto p = Ipv4Prefix::parse("192.168.1.0/24");
    assert(p.prefixlen == 24);
    // addr is in host byte order: 192.168.1.0 = 0xC0A80100
    assert(p.addr == 0xC0A80100);
}

TEST(test_ipv4_prefix_host) {
    auto p = Ipv4Prefix::parse("10.0.0.1/32");
    assert(p.prefixlen == 32);
    assert(p.addr == 0x0A000001);
}

TEST(test_ipv4_prefix_classA) {
    auto p = Ipv4Prefix::parse("10.0.0.0/8");
    assert(p.prefixlen == 8);
    assert(p.addr == 0x0A000000);
}

TEST(test_ipv4_prefix_default_route) {
    auto p = Ipv4Prefix::parse("0.0.0.0/0");
    assert(p.prefixlen == 0);
    assert(p.addr == 0);
}

TEST(test_ipv4_prefix_nbo) {
    auto p = Ipv4Prefix::parse("192.168.1.0/24");
    uint32_t expected_nbo;
    inet_pton(AF_INET, "192.168.1.0", &expected_nbo);
    assert(p.addr_nbo() == expected_nbo);
}

TEST(test_ipv4_prefix_nbo_loopback) {
    auto p = Ipv4Prefix::parse("127.0.0.1/32");
    uint32_t expected_nbo;
    inet_pton(AF_INET, "127.0.0.1", &expected_nbo);
    assert(p.addr_nbo() == expected_nbo);
}

TEST(test_ipv4_prefix_missing_slash) {
    bool threw = false;
    try { Ipv4Prefix::parse("192.168.1.0"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_ipv4_prefix_bad_prefixlen) {
    bool threw = false;
    try { Ipv4Prefix::parse("10.0.0.0/33"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_ipv4_prefix_negative_prefixlen) {
    bool threw = false;
    try { Ipv4Prefix::parse("10.0.0.0/-1"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_ipv4_prefix_bad_ip) {
    bool threw = false;
    try { Ipv4Prefix::parse("999.999.999.999/24"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_ipv4_prefix_too_few_octets) {
    bool threw = false;
    try { Ipv4Prefix::parse("192.168.1/24"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_ipv4_prefix_non_numeric) {
    bool threw = false;
    try { Ipv4Prefix::parse("abc.def.ghi.jkl/24"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_ipv4_prefix_empty) {
    bool threw = false;
    try { Ipv4Prefix::parse(""); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_ipv4_prefix_rfc1918_ranges) {
    auto p1 = Ipv4Prefix::parse("10.0.0.0/8");
    assert(p1.addr == 0x0A000000);

    auto p2 = Ipv4Prefix::parse("172.16.0.0/12");
    assert(p2.prefixlen == 12);
    assert(p2.addr == 0xAC100000);

    auto p3 = Ipv4Prefix::parse("192.168.0.0/16");
    assert(p3.prefixlen == 16);
    assert(p3.addr == 0xC0A80000);
}

TEST(test_ipv4_255_octets) {
    auto p = Ipv4Prefix::parse("255.255.255.255/32");
    assert(p.addr == 0xFFFFFFFF);
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
