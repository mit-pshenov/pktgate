/*
 * IPv6 dual-stack support tests.
 * Covers: Ipv6Prefix parsing (positive, negative, edge), lpm_v6_key byte layout,
 *         L3v6 rule compilation (all actions), object6 resolution, collision detection,
 *         dual-stack mixing, config parsing, validation, roundtrip.
 */
#include "util/net_types.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "config/config_parser.hpp"
#include "config/config_validator.hpp"
#include "../../bpf/common.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
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
// Ipv6Prefix parsing
// ═══════════════════════════════════════════════════════════

TEST(ipv6_parse_basic) {
    auto p = util::Ipv6Prefix::parse("2001:db8::/32");
    assert(p.prefixlen == 32);
    struct in6_addr expected{};
    inet_pton(AF_INET6, "2001:db8::", &expected);
    assert(memcmp(p.addr.data(), &expected, 16) == 0);
}

TEST(ipv6_parse_full_addr) {
    auto p = util::Ipv6Prefix::parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128");
    assert(p.prefixlen == 128);
    struct in6_addr expected{};
    inet_pton(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", &expected);
    assert(memcmp(p.addr.data(), &expected, 16) == 0);
}

TEST(ipv6_parse_loopback) {
    auto p = util::Ipv6Prefix::parse("::1/128");
    assert(p.prefixlen == 128);
    assert(p.addr[15] == 1);
    for (int i = 0; i < 15; ++i)
        assert(p.addr[i] == 0);
}

TEST(ipv6_parse_default_route) {
    auto p = util::Ipv6Prefix::parse("::/0");
    assert(p.prefixlen == 0);
    for (int i = 0; i < 16; ++i)
        assert(p.addr[i] == 0);
}

TEST(ipv6_parse_link_local) {
    auto p = util::Ipv6Prefix::parse("fe80::/10");
    assert(p.prefixlen == 10);
    assert(p.addr[0] == 0xfe);
    assert(p.addr[1] == 0x80);
}

TEST(ipv6_parse_slash_64) {
    auto p = util::Ipv6Prefix::parse("2001:db8:1:2::/64");
    assert(p.prefixlen == 64);
}

TEST(ipv6_parse_missing_slash) {
    bool threw = false;
    try { util::Ipv6Prefix::parse("2001:db8::"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_bad_prefixlen) {
    bool threw = false;
    try { util::Ipv6Prefix::parse("2001:db8::/129"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_invalid_addr) {
    bool threw = false;
    try { util::Ipv6Prefix::parse("not-an-ip/64"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_empty) {
    bool threw = false;
    try { util::Ipv6Prefix::parse(""); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_ipv4_mapped) {
    // ::ffff:192.168.1.1 is valid IPv6
    auto p = util::Ipv6Prefix::parse("::ffff:192.168.1.1/128");
    assert(p.prefixlen == 128);
    // Bytes 10-11 should be 0xff,0xff; bytes 12-15 = 192.168.1.1
    assert(p.addr[10] == 0xff);
    assert(p.addr[11] == 0xff);
    assert(p.addr[12] == 192);
    assert(p.addr[13] == 168);
    assert(p.addr[14] == 1);
    assert(p.addr[15] == 1);
}

TEST(ipv6_parse_all_ff) {
    auto p = util::Ipv6Prefix::parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128");
    assert(p.prefixlen == 128);
    for (int i = 0; i < 16; ++i)
        assert(p.addr[i] == 0xff);
}

TEST(ipv6_parse_all_zeros_slash128) {
    auto p = util::Ipv6Prefix::parse("::/128");
    assert(p.prefixlen == 128);
    for (int i = 0; i < 16; ++i)
        assert(p.addr[i] == 0);
}

TEST(ipv6_parse_slash_only) {
    bool threw = false;
    try { util::Ipv6Prefix::parse("/64"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_negative_prefixlen) {
    bool threw = false;
    try { util::Ipv6Prefix::parse("2001:db8::/-1"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_non_numeric_prefixlen) {
    bool threw = false;
    try { util::Ipv6Prefix::parse("2001:db8::/abc"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_ipv4_string_rejected) {
    // Dotted-decimal without :: mapping is invalid IPv6
    bool threw = false;
    try { util::Ipv6Prefix::parse("192.168.1.0/24"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_multicast) {
    auto p = util::Ipv6Prefix::parse("ff02::1/128");
    assert(p.prefixlen == 128);
    assert(p.addr[0] == 0xff);
    assert(p.addr[1] == 0x02);
    assert(p.addr[15] == 1);
}

TEST(ipv6_parse_compressed_middle) {
    // 2001:db8::1 = 2001:0db8:0000:0000:0000:0000:0000:0001
    auto p = util::Ipv6Prefix::parse("2001:db8::1/128");
    assert(p.addr[0] == 0x20);
    assert(p.addr[1] == 0x01);
    assert(p.addr[15] == 1);
    // Middle bytes should all be zero
    for (int i = 4; i < 15; ++i)
        assert(p.addr[i] == 0);
}

TEST(ipv6_parse_extra_colons) {
    bool threw = false;
    try { util::Ipv6Prefix::parse("2001:db8:::/32"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(ipv6_parse_too_many_groups) {
    bool threw = false;
    try { util::Ipv6Prefix::parse("2001:db8:1:2:3:4:5:6:7/64"); } catch (...) { threw = true; }
    assert(threw);
}

// ═══════════════════════════════════════════════════════════
// lpm_v6_key byte layout
// ═══════════════════════════════════════════════════════════

TEST(lpm_v6_key_sizeof_is_20) {
    assert(sizeof(struct lpm_v6_key) == 20);
}

TEST(lpm_v6_key_object_compiler) {
    config::ObjectStore objs;
    objs.subnets6["trusted_v6"] = "2001:db8:cafe::/48";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());
    assert(co->subnets6.size() == 1);

    auto& k = co->subnets6[0].key;
    assert(k.prefixlen == 48);

    struct in6_addr expected{};
    inet_pton(AF_INET6, "2001:db8:cafe::", &expected);
    assert(memcmp(k.addr, &expected, 16) == 0);
}

TEST(lpm_v6_key_loopback) {
    config::ObjectStore objs;
    objs.subnets6["lo"] = "::1/128";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    auto& k = co->subnets6[0].key;
    assert(k.prefixlen == 128);
    assert(k.addr[15] == 1);
    for (int i = 0; i < 15; ++i)
        assert(k.addr[i] == 0);
}

TEST(lpm_v6_key_default_route_all_zeros) {
    config::ObjectStore objs;
    objs.subnets6["default6"] = "::/0";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    auto& k = co->subnets6[0].key;
    assert(k.prefixlen == 0);
    for (int i = 0; i < 16; ++i)
        assert(k.addr[i] == 0);
}

TEST(lpm_v6_key_all_ff) {
    config::ObjectStore objs;
    objs.subnets6["maxaddr"] = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    auto& k = co->subnets6[0].key;
    assert(k.prefixlen == 128);
    for (int i = 0; i < 16; ++i)
        assert(k.addr[i] == 0xff);
}

TEST(lpm_v6_key_struct_offsets) {
    // prefixlen at offset 0, addr at offset 4
    assert(offsetof(struct lpm_v6_key, prefixlen) == 0);
    assert(offsetof(struct lpm_v6_key, addr) == 4);
}

TEST(lpm_v6_key_padding_bytes_zero) {
    // Verify the compiled key has no garbage between fields
    config::ObjectStore objs;
    objs.subnets6["net"] = "2001:db8::/32";

    auto co = compiler::compile_objects(objs);
    assert(co.has_value());

    // Check raw bytes: first 4 bytes = prefixlen (32 = 0x20)
    auto* raw = reinterpret_cast<const uint8_t*>(&co->subnets6[0].key);
    // Little-endian: 32 = 0x20, 0x00, 0x00, 0x00
    assert(raw[0] == 0x20);
    assert(raw[1] == 0x00);
    assert(raw[2] == 0x00);
    assert(raw[3] == 0x00);
    // Bytes 4-5 = 0x20, 0x01 (2001:)
    assert(raw[4] == 0x20);
    assert(raw[5] == 0x01);
}

TEST(lpm_v6_key_invalid_cidr_in_object) {
    config::ObjectStore objs;
    objs.subnets6["bad"] = "not-an-ipv6/64";

    auto co = compiler::compile_objects(objs);
    assert(!co.has_value());
}

// ═══════════════════════════════════════════════════════════
// L3 IPv6 rule compilation
// ═══════════════════════════════════════════════════════════

TEST(l3v6_rule_basic) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 200;
    r.action = config::Action::Drop;
    r.match.src_ip6 = "2001:db8:bad::/48";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.empty());      // no v4 rules
    assert(cr->l3v6_rules.size() == 1);

    auto& rule = cr->l3v6_rules[0];
    assert(rule.rule.rule_id == 200);
    assert(rule.rule.action == ACT_DROP);
    assert(rule.subnet_key.prefixlen == 48);

    struct in6_addr expected{};
    inet_pton(AF_INET6, "2001:db8:bad::", &expected);
    assert(memcmp(rule.subnet_key.addr, &expected, 16) == 0);
}

TEST(l3v6_rule_allow_with_next_layer) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 300;
    r.action = config::Action::Allow;
    r.match.src_ip6 = "fd00::/8";
    r.next_layer = "layer_4";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.size() == 1);
    assert(cr->l3v6_rules[0].rule.has_next_layer == 1);
}

TEST(l3v6_rule_object6_resolution) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 400;
    r.action = config::Action::Drop;
    r.match.src_ip6 = "object6:evil_v6";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    objs.subnets6["evil_v6"] = "2001:db8:dead::/48";

    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.size() == 1);

    struct in6_addr expected{};
    inet_pton(AF_INET6, "2001:db8:dead::", &expected);
    assert(memcmp(cr->l3v6_rules[0].subnet_key.addr, &expected, 16) == 0);
}

TEST(l3v6_unknown_object6) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 500;
    r.action = config::Action::Drop;
    r.match.src_ip6 = "object6:nonexistent";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(!cr.has_value());
}

TEST(l3v6_mirror_action) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 350;
    r.action = config::Action::Mirror;
    r.match.src_ip6 = "2001:db8:aa::/48";
    r.params.target_port = "eth1";
    r.next_layer = "layer_4";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.size() == 1);
    assert(cr->l3v6_rules[0].rule.action == ACT_MIRROR);
    assert(cr->l3v6_rules[0].rule.mirror_ifindex == 42);
    assert(cr->l3v6_rules[0].rule.has_next_layer == 1);
}

TEST(l3v6_redirect_action) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 360;
    r.action = config::Action::Redirect;
    r.match.src_ip6 = "2001:db8:bb::/48";
    r.params.target_vrf = "quarantine";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.size() == 1);
    assert(cr->l3v6_rules[0].rule.action == ACT_REDIRECT);
    assert(cr->l3v6_rules[0].rule.redirect_ifindex == 42);
}

TEST(l3v6_literal_cidr) {
    // Literal IPv6 CIDR (not object6: ref)
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 370;
    r.action = config::Action::Drop;
    r.match.src_ip6 = "fe80::/10";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.size() == 1);
    assert(cr->l3v6_rules[0].subnet_key.prefixlen == 10);
    assert(cr->l3v6_rules[0].subnet_key.addr[0] == 0xfe);
    assert(cr->l3v6_rules[0].subnet_key.addr[1] == 0x80);
}

TEST(l3v6_no_collision_v4_v6_same_rule_ids) {
    // v4 and v6 rules go into different maps — no collision
    config::Pipeline pl;

    config::Rule r1;
    r1.rule_id = 10;
    r1.action = config::Action::Drop;
    r1.match.src_ip = "10.0.0.0/8";
    pl.layer_3.push_back(r1);

    config::Rule r2;
    r2.rule_id = 11;
    r2.action = config::Action::Drop;
    r2.match.src_ip6 = "2001:db8::/32";
    pl.layer_3.push_back(r2);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.size() == 1);
    assert(cr->l3v6_rules.size() == 1);
}

TEST(l3v6_multiple_no_collision) {
    config::Pipeline pl;

    config::Rule r1;
    r1.rule_id = 10;
    r1.action = config::Action::Allow;
    r1.match.src_ip6 = "2001:db8:a::/48";
    pl.layer_3.push_back(r1);

    config::Rule r2;
    r2.rule_id = 20;
    r2.action = config::Action::Drop;
    r2.match.src_ip6 = "2001:db8:b::/48";
    pl.layer_3.push_back(r2);

    config::Rule r3;
    r3.rule_id = 30;
    r3.action = config::Action::Allow;
    r3.match.src_ip6 = "fd00::/8";
    pl.layer_3.push_back(r3);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.size() == 3);
}

TEST(l3v6_empty_when_only_v4) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 10;
    r.action = config::Action::Allow;
    r.match.src_ip = "10.0.0.0/8";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.empty());
    assert(cr->l3_rules.size() == 1);
}

TEST(l3v6_default_route) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 999;
    r.action = config::Action::Allow;
    r.match.src_ip6 = "::/0";
    r.next_layer = "layer_4";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.size() == 1);
    assert(cr->l3v6_rules[0].subnet_key.prefixlen == 0);
    for (int i = 0; i < 16; ++i)
        assert(cr->l3v6_rules[0].subnet_key.addr[i] == 0);
}

TEST(l3v6_host_route_128) {
    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 888;
    r.action = config::Action::Drop;
    r.match.src_ip6 = "2001:db8::dead:beef/128";
    pl.layer_3.push_back(r);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules[0].subnet_key.prefixlen == 128);

    struct in6_addr expected{};
    inet_pton(AF_INET6, "2001:db8::dead:beef", &expected);
    assert(memcmp(cr->l3v6_rules[0].subnet_key.addr, &expected, 16) == 0);
}

TEST(l3v6_collision_detection) {
    config::Pipeline pl;

    config::Rule r1;
    r1.rule_id = 600;
    r1.action = config::Action::Allow;
    r1.match.src_ip6 = "2001:db8::/32";
    pl.layer_3.push_back(r1);

    config::Rule r2;
    r2.rule_id = 601;
    r2.action = config::Action::Drop;
    r2.match.src_ip6 = "2001:db8::/32";
    pl.layer_3.push_back(r2);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(!cr.has_value());
    assert(cr.error().find("IPv6") != std::string::npos);
}

// ═══════════════════════════════════════════════════════════
// Dual-stack: mix of v4 and v6 rules
// ═══════════════════════════════════════════════════════════

TEST(dual_stack_mixed_rules) {
    config::Pipeline pl;

    config::Rule r1;
    r1.rule_id = 10;
    r1.action = config::Action::Allow;
    r1.match.src_ip = "10.0.0.0/8";
    r1.next_layer = "layer_4";
    pl.layer_3.push_back(r1);

    config::Rule r2;
    r2.rule_id = 20;
    r2.action = config::Action::Drop;
    r2.match.src_ip6 = "2001:db8:bad::/48";
    pl.layer_3.push_back(r2);

    config::Rule r3;
    r3.rule_id = 30;
    r3.action = config::Action::Allow;
    r3.match.vrf = "mgmt";
    pl.layer_3.push_back(r3);

    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.size() == 2);    // v4 subnet + VRF
    assert(cr->l3v6_rules.size() == 1);  // v6 subnet
}

// ═══════════════════════════════════════════════════════════
// Config parsing with IPv6
// ═══════════════════════════════════════════════════════════

TEST(config_parse_ipv6) {
    auto cfg = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {
            "subnets6": {
                "trusted_v6": "2001:db8:cafe::/48",
                "blocked_v6": "2001:db8:dead::/48"
            }
        },
        "pipeline": {
            "layer_3": [
                {"rule_id": 10, "action": "allow",
                 "match": {"src_ip6": "object6:trusted_v6"},
                 "next_layer": "layer_4"},
                {"rule_id": 20, "action": "drop",
                 "match": {"src_ip6": "object6:blocked_v6"}}
            ]
        },
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());
    assert(cfg->objects.subnets6.size() == 2);
    assert(cfg->pipeline.layer_3.size() == 2);
    assert(cfg->pipeline.layer_3[0].match.src_ip6.has_value());
    assert(*cfg->pipeline.layer_3[0].match.src_ip6 == "object6:trusted_v6");
}

TEST(config_parse_dual_stack) {
    auto cfg = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {
            "subnets": {"trusted_v4": "10.0.0.0/8"},
            "subnets6": {"trusted_v6": "2001:db8::/32"}
        },
        "pipeline": {
            "layer_3": [
                {"rule_id": 10, "action": "allow", "match": {"src_ip": "object:trusted_v4"}},
                {"rule_id": 20, "action": "allow", "match": {"src_ip6": "object6:trusted_v6"}}
            ]
        },
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());
    assert(cfg->objects.subnets.size() == 1);
    assert(cfg->objects.subnets6.size() == 1);
}

TEST(config_parse_empty_subnets6) {
    auto cfg = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {
            "subnets6": {}
        },
        "pipeline": {},
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());
    assert(cfg->objects.subnets6.empty());
}

TEST(config_parse_no_subnets6_key) {
    // Missing subnets6 key entirely — should be fine
    auto cfg = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {
            "subnets": {"net": "10.0.0.0/8"}
        },
        "pipeline": {},
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());
    assert(cfg->objects.subnets6.empty());
}

// ═══════════════════════════════════════════════════════════
// Validator — IPv6-specific
// ═══════════════════════════════════════════════════════════

TEST(validator_unknown_object6_ref) {
    config::Config cfg;
    cfg.interface = "eth0";
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Drop;
    r.match.src_ip6 = "object6:ghost_v6";
    cfg.pipeline.layer_3.push_back(r);

    auto result = config::validate_config(cfg);
    assert(!result.has_value());
    // Should report unknown subnet6 object
    bool found = false;
    for (auto& e : result.error())
        if (e.message.find("unknown subnet6 object: ghost_v6") != std::string::npos)
            found = true;
    assert(found);
}

TEST(validator_literal_ipv6_ok) {
    config::Config cfg;
    cfg.interface = "eth0";
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Drop;
    r.match.src_ip6 = "2001:db8::/32"; // literal, no object6: prefix
    cfg.pipeline.layer_3.push_back(r);

    auto result = config::validate_config(cfg);
    assert(result.has_value());
}

TEST(validator_valid_object6_ref) {
    config::Config cfg;
    cfg.interface = "eth0";
    cfg.objects.subnets6["mynet"] = "2001:db8::/32";
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Allow;
    r.match.src_ip6 = "object6:mynet";
    cfg.pipeline.layer_3.push_back(r);

    auto result = config::validate_config(cfg);
    assert(result.has_value());
}

// ═══════════════════════════════════════════════════════════
// Roundtrip: parse → validate → compile → verify
// ═══════════════════════════════════════════════════════════

TEST(roundtrip_ipv6_full) {
    auto cfg = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {
            "subnets6": {
                "trusted": "2001:db8:cafe::/48",
                "blocked": "2001:db8:dead::/48"
            },
            "port_groups": {"dns": [53]}
        },
        "pipeline": {
            "layer_3": [
                {"rule_id": 10, "action": "allow",
                 "match": {"src_ip6": "object6:trusted"},
                 "next_layer": "layer_4"},
                {"rule_id": 20, "action": "drop",
                 "match": {"src_ip6": "object6:blocked"}}
            ],
            "layer_4": [
                {"rule_id": 100, "action": "allow",
                 "match": {"protocol": "UDP", "dst_port": "object:dns"}}
            ]
        },
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());

    auto vr = config::validate_config(*cfg);
    assert(vr.has_value());

    auto co = compiler::compile_objects(cfg->objects);
    assert(co.has_value());
    assert(co->subnets6.size() == 2);

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, null_resolver);
    assert(cr.has_value());
    assert(cr->l3v6_rules.size() == 2);
    assert(cr->l4_rules.size() == 1);

    // Verify first v6 rule
    assert(cr->l3v6_rules[0].rule.rule_id == 10);
    assert(cr->l3v6_rules[0].rule.action == ACT_ALLOW);
    assert(cr->l3v6_rules[0].rule.has_next_layer == 1);
    assert(cr->l3v6_rules[0].subnet_key.prefixlen == 48);

    // Verify second v6 rule
    assert(cr->l3v6_rules[1].rule.rule_id == 20);
    assert(cr->l3v6_rules[1].rule.action == ACT_DROP);
    assert(cr->l3v6_rules[1].rule.has_next_layer == 0);
}

TEST(roundtrip_dual_stack_full) {
    auto cfg = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {
            "subnets": {"v4net": "10.0.0.0/8"},
            "subnets6": {"v6net": "2001:db8::/32"},
            "mac_groups": {"routers": ["AA:BB:CC:DD:EE:FF"]},
            "port_groups": {"web": [80, 443]}
        },
        "pipeline": {
            "layer_2": [
                {"rule_id": 1, "action": "allow",
                 "match": {"src_mac": "object:routers"},
                 "next_layer": "layer_3"}
            ],
            "layer_3": [
                {"rule_id": 10, "action": "allow",
                 "match": {"src_ip": "object:v4net"},
                 "next_layer": "layer_4"},
                {"rule_id": 20, "action": "allow",
                 "match": {"src_ip6": "object6:v6net"},
                 "next_layer": "layer_4"}
            ],
            "layer_4": [
                {"rule_id": 100, "action": "allow",
                 "match": {"protocol": "TCP", "dst_port": "object:web"}}
            ]
        },
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());

    auto vr = config::validate_config(*cfg);
    assert(vr.has_value());

    auto co = compiler::compile_objects(cfg->objects);
    assert(co.has_value());
    assert(co->subnets.size() == 1);
    assert(co->subnets6.size() == 1);
    assert(co->macs.size() == 1);

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, null_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.size() == 1);    // v4
    assert(cr->l3v6_rules.size() == 1);  // v6
    assert(cr->l4_rules.size() == 2);    // 80, 443
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
