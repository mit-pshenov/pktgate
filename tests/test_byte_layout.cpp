/*
 * Byte-level verification of compiled map keys and values.
 * Ensures the control plane produces exactly the bytes the BPF data plane expects.
 */
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "config/config_parser.hpp"
#include "util/net_types.hpp"
#include "../../bpf/common.h"
#include <bpf/libbpf.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>

using namespace pktgate;

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry { const char* name; void (*fn)(); };
static std::vector<TestEntry> tests;

static auto null_resolver = [](const std::string&) -> uint32_t { return 42; };

// ═══════════════════════════════════════════════════════════
// MAC key byte layout
// ═══════════════════════════════════════════════════════════

TEST(mac_key_sizeof_is_8) {
    // BPF map expects 8-byte key (6 MAC + 2 pad)
    assert(sizeof(struct mac_key) == 8);
}

TEST(mac_key_bytes_match_parsed_mac) {
    config::ObjectStore objs;
    objs.mac_groups["test"] = {"AA:BB:CC:DD:EE:FF"};

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());
    assert(co->macs.size() == 1);

    auto& k = co->macs[0].key;
    assert(k.addr[0] == 0xAA);
    assert(k.addr[1] == 0xBB);
    assert(k.addr[2] == 0xCC);
    assert(k.addr[3] == 0xDD);
    assert(k.addr[4] == 0xEE);
    assert(k.addr[5] == 0xFF);
    assert(k._pad[0] == 0);
    assert(k._pad[1] == 0);
}

TEST(mac_key_lowercase_hex) {
    config::ObjectStore objs;
    objs.mac_groups["test"] = {"0a:1b:2c:3d:4e:5f"};

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    auto& k = co->macs[0].key;
    assert(k.addr[0] == 0x0A);
    assert(k.addr[1] == 0x1B);
    assert(k.addr[2] == 0x2C);
    assert(k.addr[3] == 0x3D);
    assert(k.addr[4] == 0x4E);
    assert(k.addr[5] == 0x5F);
}

TEST(mac_key_all_zeros) {
    config::ObjectStore objs;
    objs.mac_groups["test"] = {"00:00:00:00:00:00"};

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    struct mac_key expected{};
    memset(&expected, 0, sizeof(expected));
    assert(memcmp(&co->macs[0].key, &expected, sizeof(struct mac_key)) == 0);
}

TEST(mac_key_all_ff) {
    config::ObjectStore objs;
    objs.mac_groups["test"] = {"FF:FF:FF:FF:FF:FF"};

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    auto& k = co->macs[0].key;
    for (int i = 0; i < 6; ++i)
        assert(k.addr[i] == 0xFF);
    assert(k._pad[0] == 0); // padding must still be zero
    assert(k._pad[1] == 0);
}

TEST(mac_value_is_one) {
    config::ObjectStore objs;
    objs.mac_groups["test"] = {"AA:BB:CC:DD:EE:FF"};

    auto co = compiler::compile_objects(objs);
    assert(co->macs[0].value == 1);
}

// ═══════════════════════════════════════════════════════════
// LPM key byte layout (subnet)
// ═══════════════════════════════════════════════════════════

TEST(lpm_key_sizeof_is_8) {
    assert(sizeof(struct lpm_v4_key) == 8);
}

TEST(lpm_key_addr_is_network_byte_order) {
    config::ObjectStore objs;
    objs.subnets["net"] = "192.168.1.0/24";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());
    assert(co->subnets.size() == 1);

    auto& k = co->subnets[0].key;
    assert(k.prefixlen == 24);

    // 192.168.1.0 in NBO = 0xC0A80100
    uint32_t expected_nbo;
    inet_pton(AF_INET, "192.168.1.0", &expected_nbo);
    assert(k.addr == expected_nbo);
}

TEST(lpm_key_10_0_0_0_slash_8) {
    config::ObjectStore objs;
    objs.subnets["net"] = "10.0.0.0/8";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    auto& k = co->subnets[0].key;
    assert(k.prefixlen == 8);

    uint32_t expected_nbo;
    inet_pton(AF_INET, "10.0.0.0", &expected_nbo);
    assert(k.addr == expected_nbo);
}

TEST(lpm_key_host_route_slash_32) {
    config::ObjectStore objs;
    objs.subnets["host"] = "1.2.3.4/32";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    auto& k = co->subnets[0].key;
    assert(k.prefixlen == 32);

    // Raw bytes: 0x01, 0x02, 0x03, 0x04
    auto* bytes = reinterpret_cast<uint8_t*>(&k.addr);
    assert(bytes[0] == 1);
    assert(bytes[1] == 2);
    assert(bytes[2] == 3);
    assert(bytes[3] == 4);
}

TEST(lpm_key_default_route_slash_0) {
    config::ObjectStore objs;
    objs.subnets["default"] = "0.0.0.0/0";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    auto& k = co->subnets[0].key;
    assert(k.prefixlen == 0);
    assert(k.addr == 0);
}

// ═══════════════════════════════════════════════════════════
// L3 rule byte layout (via rule compiler)
// ═══════════════════════════════════════════════════════════

TEST(l3_rule_sizeof_is_20) {
    assert(sizeof(struct l3_rule) == 20);
}

TEST(l3_rule_drop_action_bytes) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 100;
    r.action = config::Action::Drop;
    r.match.src_ip = "10.0.0.0/8";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.size() == 1);

    auto& rule = cr->l3_rules[0].rule;
    assert(rule.rule_id == 100);
    assert(rule.action == ACT_DROP);
    assert(rule.has_next_layer == 0);
    assert(rule.redirect_ifindex == 0);
    assert(rule.mirror_ifindex == 0);
}

TEST(l3_rule_allow_with_next_layer) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 200;
    r.action = config::Action::Allow;
    r.match.src_ip = "172.16.0.0/12";
    r.next_layer = "layer_4";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    auto& rule = cr->l3_rules[0].rule;
    assert(rule.action == ACT_ALLOW);
    assert(rule.has_next_layer == 1);

    auto& key = cr->l3_rules[0].subnet_key;
    assert(key.prefixlen == 12);
    uint32_t expected_nbo;
    inet_pton(AF_INET, "172.16.0.0", &expected_nbo);
    assert(key.addr == expected_nbo);
}

TEST(l3_rule_mirror_ifindex) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 300;
    r.action = config::Action::Mirror;
    r.match.src_ip = "1.2.3.0/24";
    r.params.target_port = "eth0";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver); // resolver returns 42
    assert(cr.has_value());

    assert(cr->l3_rules[0].rule.action == ACT_MIRROR);
    assert(cr->l3_rules[0].rule.mirror_ifindex == 42);
}

TEST(l3_rule_redirect_ifindex) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 400;
    r.action = config::Action::Redirect;
    r.match.src_ip = "5.6.7.0/24";
    r.params.target_vrf = "captive_vrf";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    assert(cr->l3_rules[0].rule.action == ACT_REDIRECT);
    assert(cr->l3_rules[0].rule.redirect_ifindex == 42);
}

TEST(l3_rule_vrf_flag_set) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 500;
    r.action = config::Action::Drop;
    r.match.vrf = "my_vrf";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    assert(cr->l3_rules[0].is_vrf_rule == true);
    assert(cr->l3_rules[0].vrf_ifindex == 42);
}

// ═══════════════════════════════════════════════════════════
// L4 match key byte layout
// ═══════════════════════════════════════════════════════════

TEST(l4_match_key_sizeof_is_4) {
    assert(sizeof(struct l4_match_key) == 4);
}

TEST(l4_match_key_tcp_80) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l4_rules.size() == 1);

    auto& m = cr->l4_rules[0].match;
    assert(m.protocol == 6);     // IPPROTO_TCP
    assert(m.dst_port == 80);    // host byte order
    assert(m._pad == 0);
}

TEST(l4_match_key_udp_53) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 2;
    r.action = config::Action::Allow;
    r.match.protocol = "UDP";
    r.match.dst_port = "53";
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    auto& m = cr->l4_rules[0].match;
    assert(m.protocol == 17);    // IPPROTO_UDP
    assert(m.dst_port == 53);
}

TEST(l4_match_key_port_host_byte_order) {
    // Port 0x1234 (4660) — verify it's stored as-is, not swapped
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "4660";
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    assert(cr->l4_rules[0].match.dst_port == 4660);

    // Verify raw bytes: on little-endian, 4660 = 0x1234 → bytes 0x34, 0x12
    auto* bytes = reinterpret_cast<uint8_t*>(&cr->l4_rules[0].match.dst_port);
    assert(bytes[0] == 0x34); // little-endian low byte
    assert(bytes[1] == 0x12);
}

// ═══════════════════════════════════════════════════════════
// L4 rule byte layout
// ═══════════════════════════════════════════════════════════

TEST(l4_rule_sizeof_is_24) {
    assert(sizeof(struct l4_rule) == 24);
}

TEST(l4_rule_rate_bps_at_offset_16) {
    // rate_bps must be at offset 16 for 8-byte alignment
    assert(offsetof(struct l4_rule, rate_bps) == 16);
}

TEST(l4_rule_tag_dscp_cos) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 10;
    r.action = config::Action::Tag;
    r.match.protocol = "UDP";
    r.match.dst_port = "53";
    r.params.dscp = "EF";
    r.params.cos = 5;
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    auto& rule = cr->l4_rules[0].rule;
    assert(rule.action == ACT_TAG);
    assert(rule.dscp == 46);    // EF = 46
    assert(rule.cos == 5);
    assert(rule.rate_bps == 0); // not a rate-limit rule
}

TEST(l4_rule_rate_limit_bps) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 20;
    r.action = config::Action::RateLimit;
    r.match.protocol = "TCP";
    r.match.dst_port = "443";
    r.params.bandwidth = "10Gbps";
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    auto& rule = cr->l4_rules[0].rule;
    assert(rule.action == ACT_RATE_LIMIT);
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) ncpus = 1;
    assert(rule.rate_bps == 10000000000ULL / ncpus);
    assert(rule.dscp == 0);
    assert(rule.cos == 0);
}

TEST(l4_rule_allow_all_zeros_except_action) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 0;
    r.action = config::Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    auto& rule = cr->l4_rules[0].rule;
    assert(rule.rule_id == 0);
    assert(rule.action == ACT_ALLOW);
    assert(rule.dscp == 0);
    assert(rule.cos == 0);
    assert(rule.rate_bps == 0);
}

// ═══════════════════════════════════════════════════════════
// Port group expansion into multiple L4 rules
// ═══════════════════════════════════════════════════════════

TEST(port_group_expands_to_multiple_rules) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 50;
    r.action = config::Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "object:web";
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    objs.port_groups["web"] = {80, 443, 8080};

    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l4_rules.size() == 3);

    assert(cr->l4_rules[0].match.dst_port == 80);
    assert(cr->l4_rules[1].match.dst_port == 443);
    assert(cr->l4_rules[2].match.dst_port == 8080);

    // All share same rule_id and action
    for (auto& lr : cr->l4_rules) {
        assert(lr.rule.rule_id == 50);
        assert(lr.rule.action == ACT_ALLOW);
        assert(lr.match.protocol == 6);
    }
}

TEST(subnet_object_resolves_in_l3_rule) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 60;
    r.action = config::Action::Drop;
    r.match.src_ip = "object:bad_net";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    objs.subnets["bad_net"] = "192.0.2.0/24";

    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.size() == 1);

    auto& key = cr->l3_rules[0].subnet_key;
    assert(key.prefixlen == 24);

    uint32_t expected_nbo;
    inet_pton(AF_INET, "192.0.2.0", &expected_nbo);
    assert(key.addr == expected_nbo);
}

// ═══════════════════════════════════════════════════════════
// Struct padding / zeroing
// ═══════════════════════════════════════════════════════════

TEST(l4_rule_padding_is_zero) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    // Check tcp_flags and _pad bytes at offset 10-15 are zero
    auto& rule = cr->l4_rules[0].rule;
    assert(rule.tcp_flags_set == 0);
    assert(rule.tcp_flags_unset == 0);
    assert(rule._pad[0] == 0);
    assert(rule._pad[1] == 0);
    assert(rule._pad[2] == 0);
    assert(rule._pad[3] == 0);
}

TEST(l3_rule_padding_is_zero) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Allow;
    r.match.src_ip = "10.0.0.0/8";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    auto& rule = cr->l3_rules[0].rule;
    assert(rule._pad[0] == 0);
    assert(rule._pad[1] == 0);
    assert(rule._pad[2] == 0);
}

TEST(l4_match_key_padding_is_zero) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    pl.layer_4.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());

    assert(cr->l4_rules[0].match._pad == 0);
}

// ═══════════════════════════════════════════════════════════
// L2 rule struct size and PCP key
// ═══════════════════════════════════════════════════════════

TEST(l2_rule_sizeof_24) {
    assert(sizeof(struct l2_rule) == 24);
}

TEST(pcp_key_sizeof_4) {
    assert(sizeof(struct pcp_key) == 4);
}

TEST(l2_rule_filter_mask_offset_17) {
    assert(offsetof(struct l2_rule, filter_mask) == 17);
}

TEST(l2_rule_filter_vlan_offset_18) {
    assert(offsetof(struct l2_rule, filter_vlan_id) == 18);
}

// ═══════════════════════════════════════════════════════════
// L4 rule tcp_flags fields
// ═══════════════════════════════════════════════════════════

TEST(l4_rule_sizeof_still_24) {
    assert(sizeof(struct l4_rule) == 24);
}

TEST(l4_rule_tcp_flags_set_offset_10) {
    assert(offsetof(struct l4_rule, tcp_flags_set) == 10);
}

TEST(l4_rule_tcp_flags_unset_offset_11) {
    assert(offsetof(struct l4_rule, tcp_flags_unset) == 11);
}

TEST(l4_rule_rate_bps_offset_still_16) {
    assert(offsetof(struct l4_rule, rate_bps) == 16);
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
