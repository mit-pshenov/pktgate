#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "config/config_parser.hpp"
#include <bpf/libbpf.h>
#include <cassert>
#include <iostream>
#include <cstring>

using namespace pktgate;

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry {
    const char* name;
    void (*fn)();
};
static std::vector<TestEntry> tests;

static auto null_resolver = [](const std::string&) -> uint32_t { return 0; };

// ── Object reference errors ─────────────────────────────────

TEST(test_unknown_subnet_ref) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "object:nonexistent";
    r.action = config::Action::Allow;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

TEST(test_unknown_port_group_ref) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "object:nonexistent_ports";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

// ── Literal values vs object refs ───────────────────────────

TEST(test_literal_subnet) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "10.0.0.0/8";
    r.action = config::Action::Allow;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules.size() == 1);
    assert(result->l3_rules[0].subnet_key.prefixlen == 8);
}

TEST(test_literal_port) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "443";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules.size() == 1);
    assert(result->l4_rules[0].match.dst_port == 443);
}

// ── Port expansion ──────────────────────────────────────────

TEST(test_single_port_group) {
    config::ObjectStore objects;
    objects.port_groups["one"] = {22};
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "object:one";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules.size() == 1);
    assert(result->l4_rules[0].match.dst_port == 22);
}

TEST(test_large_port_group_expansion) {
    config::ObjectStore objects;
    std::vector<uint16_t> ports;
    for (uint16_t p = 8000; p <= 8099; ++p)
        ports.push_back(p);
    objects.port_groups["range"] = ports;

    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "object:range";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules.size() == 100);
    assert(result->l4_rules[0].match.dst_port == 8000);
    assert(result->l4_rules[99].match.dst_port == 8099);
}

// ── Protocol handling ───────────────────────────────────────

TEST(test_tcp_protocol_number) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules[0].match.protocol == 6);
}

TEST(test_udp_protocol_number) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "UDP";
    r.match.dst_port = "53";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules[0].match.protocol == 17);
}

TEST(test_lowercase_protocol) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "tcp";
    r.match.dst_port = "80";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules[0].match.protocol == 6);
}

TEST(test_unknown_protocol) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "SCTP";
    r.match.dst_port = "80";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

// ── All action BPF codes ────────────────────────────────────

TEST(test_action_codes_l3) {
    auto make_rule = [](config::Action act) {
        config::ObjectStore objects;
        objects.subnets["net"] = "10.0.0.0/8";
        config::Pipeline pipeline;
        config::Rule r;
        r.rule_id = 1;
        r.match.src_ip = "object:net";
        r.action = act;
        if (act == config::Action::Mirror)
            r.params.target_port = "eth0";
        if (act == config::Action::Redirect)
            r.params.target_vrf = "vrf1";
        pipeline.layer_3.push_back(r);
        return compiler::compile_rules(pipeline, objects, null_resolver);
    };

    auto r_allow = make_rule(config::Action::Allow);
    assert(r_allow.has_value());
    assert(r_allow->l3_rules[0].rule.action == 1); // ACT_ALLOW

    auto r_drop = make_rule(config::Action::Drop);
    assert(r_drop.has_value());
    assert(r_drop->l3_rules[0].rule.action == 0); // ACT_DROP

    auto r_mirror = make_rule(config::Action::Mirror);
    assert(r_mirror.has_value());
    assert(r_mirror->l3_rules[0].rule.action == 2); // ACT_MIRROR

    auto r_redir = make_rule(config::Action::Redirect);
    assert(r_redir.has_value());
    assert(r_redir->l3_rules[0].rule.action == 3); // ACT_REDIRECT
}

// ── Tag action details ──────────────────────────────────────

TEST(test_tag_all_dscp_values) {
    auto make_tag_rule = [](const std::string& dscp, uint8_t cos_val) {
        config::ObjectStore objects;
        config::Pipeline pipeline;
        config::Rule r;
        r.rule_id = 1;
        r.match.protocol = "UDP";
        r.match.dst_port = "53";
        r.action = config::Action::Tag;
        r.params.dscp = dscp;
        r.params.cos = cos_val;
        pipeline.layer_4.push_back(r);
        return compiler::compile_rules(pipeline, objects, null_resolver);
    };

    auto r_ef = make_tag_rule("EF", 5);
    assert(r_ef.has_value());
    assert(r_ef->l4_rules[0].rule.dscp == 46);
    assert(r_ef->l4_rules[0].rule.cos == 5);

    auto r_be = make_tag_rule("BE", 0);
    assert(r_be.has_value());
    assert(r_be->l4_rules[0].rule.dscp == 0);
    assert(r_be->l4_rules[0].rule.cos == 0);

    auto r_cs7 = make_tag_rule("CS7", 7);
    assert(r_cs7.has_value());
    assert(r_cs7->l4_rules[0].rule.dscp == 56);
    assert(r_cs7->l4_rules[0].rule.cos == 7);
}

// ── Rate limit compilation ──────────────────────────────────

TEST(test_rate_limit_compilation) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    r.action = config::Action::RateLimit;
    r.params.bandwidth = "1Gbps";
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) ncpus = 1;
    assert(result->l4_rules[0].rule.rate_bps == 1000000000ULL / ncpus);
    assert(result->l4_rules[0].rule.action == 5); // ACT_RATE_LIMIT
}

// ── Resolver interaction ────────────────────────────────────

TEST(test_mirror_uses_resolver) {
    config::ObjectStore objects;
    objects.subnets["net"] = "10.0.0.0/8";
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "object:net";
    r.action = config::Action::Mirror;
    r.params.target_port = "eth2";
    pipeline.layer_3.push_back(r);

    auto resolver = [](const std::string& name) -> uint32_t {
        if (name == "eth2") return 99;
        return 0;
    };

    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    assert(result->l3_rules[0].rule.mirror_ifindex == 99);
}

TEST(test_redirect_uses_resolver) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.vrf = "customer_vrf";
    r.action = config::Action::Redirect;
    r.params.target_vrf = "captive_vrf";
    pipeline.layer_3.push_back(r);

    auto resolver = [](const std::string& name) -> uint32_t {
        if (name == "customer_vrf") return 10;
        if (name == "captive_vrf") return 20;
        return 0;
    };

    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    assert(result->l3_rules[0].is_vrf_rule);
    assert(result->l3_rules[0].vrf_ifindex == 10);
    assert(result->l3_rules[0].rule.redirect_ifindex == 20);
}

// ── has_next_layer flag ─────────────────────────────────────

TEST(test_has_next_layer_set) {
    config::ObjectStore objects;
    objects.subnets["net"] = "10.0.0.0/8";
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "object:net";
    r.action = config::Action::Allow;
    r.next_layer = "layer_4";
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules[0].rule.has_next_layer == 1);
}

TEST(test_has_next_layer_unset) {
    config::ObjectStore objects;
    objects.subnets["net"] = "10.0.0.0/8";
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "object:net";
    r.action = config::Action::Drop;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules[0].rule.has_next_layer == 0);
}

// ── Empty pipeline ──────────────────────────────────────────

TEST(test_empty_pipeline_compiles) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules.empty());
    assert(result->l4_rules.empty());
}

// ── Multiple rules in single layer ──────────────────────────

TEST(test_multiple_l3_rules) {
    config::ObjectStore objects;
    objects.subnets["n1"] = "10.0.0.0/8";
    objects.subnets["n2"] = "172.16.0.0/12";
    objects.subnets["n3"] = "192.168.0.0/16";

    config::Pipeline pipeline;
    for (int i = 0; i < 3; ++i) {
        config::Rule r;
        r.rule_id = 100 + i;
        r.match.src_ip = "object:n" + std::to_string(i + 1);
        r.action = config::Action::Drop;
        pipeline.layer_3.push_back(r);
    }

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules.size() == 3);
    assert(result->l3_rules[0].rule.rule_id == 100);
    assert(result->l3_rules[1].rule.rule_id == 101);
    assert(result->l3_rules[2].rule.rule_id == 102);
}

// ── Negative: invalid literals ───────────────────────────────

TEST(test_invalid_literal_cidr) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "not-a-cidr/24"; // literal, not object ref
    r.action = config::Action::Drop;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

TEST(test_invalid_literal_cidr_no_prefix) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "10.0.0.1"; // missing /prefix
    r.action = config::Action::Drop;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

TEST(test_invalid_literal_port_negative) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "-1";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

TEST(test_invalid_literal_port_non_numeric) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "http";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

TEST(test_invalid_bandwidth_in_rate_limit) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    r.action = config::Action::RateLimit;
    r.params.bandwidth = "fast-as-possible";
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

TEST(test_invalid_dscp_in_tag) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "UDP";
    r.match.dst_port = "53";
    r.action = config::Action::Tag;
    r.params.dscp = "BOGUS_DSCP";
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

// ── Boundary values ─────────────────────────────────────────

TEST(test_port_zero) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "0";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules[0].match.dst_port == 0);
}

TEST(test_port_65535) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "65535";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules[0].match.dst_port == 65535);
}

TEST(test_rule_id_zero) {
    config::ObjectStore objects;
    objects.subnets["net"] = "10.0.0.0/8";
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 0;
    r.match.src_ip = "object:net";
    r.action = config::Action::Drop;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules[0].rule.rule_id == 0);
}

TEST(test_rule_id_max) {
    config::ObjectStore objects;
    objects.subnets["net"] = "10.0.0.0/8";
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = UINT32_MAX;
    r.match.src_ip = "object:net";
    r.action = config::Action::Drop;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules[0].rule.rule_id == UINT32_MAX);
}

TEST(test_prefix_zero_default_route) {
    config::ObjectStore objects;
    objects.subnets["default"] = "0.0.0.0/0";
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "object:default";
    r.action = config::Action::Allow;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules[0].subnet_key.prefixlen == 0);
}

TEST(test_prefix_32_host_route) {
    config::ObjectStore objects;
    objects.subnets["host"] = "10.0.0.1/32";
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "object:host";
    r.action = config::Action::Drop;
    pipeline.layer_3.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules[0].subnet_key.prefixlen == 32);
}

TEST(test_rate_limit_zero_bandwidth) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    r.action = config::Action::RateLimit;
    r.params.bandwidth = "0bps";
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules[0].rule.rate_bps == 0);
}

TEST(test_tag_cos_zero) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "UDP";
    r.match.dst_port = "53";
    r.action = config::Action::Tag;
    r.params.dscp = "CS0";
    r.params.cos = 0;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules[0].rule.dscp == 0);
    assert(result->l4_rules[0].rule.cos == 0);
}

TEST(test_tag_cos_seven) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "UDP";
    r.match.dst_port = "53";
    r.action = config::Action::Tag;
    r.params.dscp = "CS7";
    r.params.cos = 7;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules[0].rule.dscp == 56);
    assert(result->l4_rules[0].rule.cos == 7);
}

// ── Map key collision detection ─────────────────────────────

TEST(test_l4_collision_same_proto_port) {
    // Two rules: TCP:80 → collision
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r1;
    r1.rule_id = 1;
    r1.match.protocol = "TCP";
    r1.match.dst_port = "80";
    r1.action = config::Action::Allow;
    pipeline.layer_4.push_back(r1);

    config::Rule r2;
    r2.rule_id = 2;
    r2.match.protocol = "TCP";
    r2.match.dst_port = "80";
    r2.action = config::Action::Drop;
    pipeline.layer_4.push_back(r2);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
    assert(result.error().find("L4 key collision") != std::string::npos);
    assert(result.error().find("TCP:80") != std::string::npos);
    assert(result.error().find("rule 1") != std::string::npos);
    assert(result.error().find("rule 2") != std::string::npos);
}

TEST(test_l4_collision_via_port_group) {
    // Rule 1: TCP:80 literal. Rule 2: TCP:object:web_ports which includes 80.
    config::ObjectStore objects;
    objects.port_groups["web"] = {80, 443};
    config::Pipeline pipeline;

    config::Rule r1;
    r1.rule_id = 10;
    r1.match.protocol = "TCP";
    r1.match.dst_port = "80";
    r1.action = config::Action::Allow;
    pipeline.layer_4.push_back(r1);

    config::Rule r2;
    r2.rule_id = 20;
    r2.match.protocol = "TCP";
    r2.match.dst_port = "object:web";
    r2.action = config::Action::Drop;
    pipeline.layer_4.push_back(r2);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
    assert(result.error().find("L4 key collision") != std::string::npos);
    assert(result.error().find("TCP:80") != std::string::npos);
}

TEST(test_l4_collision_two_port_groups_overlap) {
    // Two port groups that both contain port 443
    config::ObjectStore objects;
    objects.port_groups["web"] = {80, 443};
    objects.port_groups["tls"] = {443, 8443};
    config::Pipeline pipeline;

    config::Rule r1;
    r1.rule_id = 1;
    r1.match.protocol = "TCP";
    r1.match.dst_port = "object:web";
    r1.action = config::Action::Allow;
    pipeline.layer_4.push_back(r1);

    config::Rule r2;
    r2.rule_id = 2;
    r2.match.protocol = "TCP";
    r2.match.dst_port = "object:tls";
    r2.action = config::Action::Drop;
    pipeline.layer_4.push_back(r2);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
    assert(result.error().find("TCP:443") != std::string::npos);
}

TEST(test_l4_no_collision_different_protocols) {
    // TCP:80 and UDP:80 are different keys — no collision
    config::ObjectStore objects;
    config::Pipeline pipeline;

    config::Rule r1;
    r1.rule_id = 1;
    r1.match.protocol = "TCP";
    r1.match.dst_port = "80";
    r1.action = config::Action::Allow;
    pipeline.layer_4.push_back(r1);

    config::Rule r2;
    r2.rule_id = 2;
    r2.match.protocol = "UDP";
    r2.match.dst_port = "80";
    r2.action = config::Action::Drop;
    pipeline.layer_4.push_back(r2);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules.size() == 2);
}

TEST(test_l4_no_collision_different_ports) {
    // TCP:80 and TCP:443 — no collision
    config::ObjectStore objects;
    config::Pipeline pipeline;

    config::Rule r1;
    r1.rule_id = 1;
    r1.match.protocol = "TCP";
    r1.match.dst_port = "80";
    r1.action = config::Action::Allow;
    pipeline.layer_4.push_back(r1);

    config::Rule r2;
    r2.rule_id = 2;
    r2.match.protocol = "TCP";
    r2.match.dst_port = "443";
    r2.action = config::Action::Drop;
    pipeline.layer_4.push_back(r2);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules.size() == 2);
}

TEST(test_l3_subnet_collision) {
    // Two rules matching same CIDR
    config::ObjectStore objects;
    objects.subnets["net_a"] = "10.0.0.0/8";
    objects.subnets["net_b"] = "10.0.0.0/8"; // same CIDR, different object name
    config::Pipeline pipeline;

    config::Rule r1;
    r1.rule_id = 1;
    r1.match.src_ip = "object:net_a";
    r1.action = config::Action::Allow;
    pipeline.layer_3.push_back(r1);

    config::Rule r2;
    r2.rule_id = 2;
    r2.match.src_ip = "object:net_b";
    r2.action = config::Action::Drop;
    pipeline.layer_3.push_back(r2);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
    assert(result.error().find("L3 subnet key collision") != std::string::npos);
    assert(result.error().find("rule 1") != std::string::npos);
    assert(result.error().find("rule 2") != std::string::npos);
}

TEST(test_l3_subnet_no_collision_different_prefix) {
    // 10.0.0.0/8 and 10.0.0.0/16 — different prefixlen, no collision
    config::ObjectStore objects;
    objects.subnets["wide"] = "10.0.0.0/8";
    objects.subnets["narrow"] = "10.0.0.0/16";
    config::Pipeline pipeline;

    config::Rule r1;
    r1.rule_id = 1;
    r1.match.src_ip = "object:wide";
    r1.action = config::Action::Allow;
    pipeline.layer_3.push_back(r1);

    config::Rule r2;
    r2.rule_id = 2;
    r2.match.src_ip = "object:narrow";
    r2.action = config::Action::Drop;
    pipeline.layer_3.push_back(r2);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules.size() == 2);
}

TEST(test_l3_vrf_collision) {
    // Two VRF rules resolving to same ifindex
    config::ObjectStore objects;
    config::Pipeline pipeline;

    config::Rule r1;
    r1.rule_id = 1;
    r1.match.vrf = "vrf_alpha";
    r1.action = config::Action::Allow;
    pipeline.layer_3.push_back(r1);

    config::Rule r2;
    r2.rule_id = 2;
    r2.match.vrf = "vrf_beta";
    r2.action = config::Action::Drop;
    pipeline.layer_3.push_back(r2);

    // Both names resolve to same ifindex
    auto resolver = [](const std::string&) -> uint32_t { return 42; };

    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(!result.has_value());
    assert(result.error().find("L3 VRF key collision") != std::string::npos);
    assert(result.error().find("ifindex 42") != std::string::npos);
}

TEST(test_l3_vrf_no_collision_different_ifindex) {
    config::ObjectStore objects;
    config::Pipeline pipeline;

    config::Rule r1;
    r1.rule_id = 1;
    r1.match.vrf = "vrf_alpha";
    r1.action = config::Action::Allow;
    pipeline.layer_3.push_back(r1);

    config::Rule r2;
    r2.rule_id = 2;
    r2.match.vrf = "vrf_beta";
    r2.action = config::Action::Drop;
    pipeline.layer_3.push_back(r2);

    auto resolver = [](const std::string& name) -> uint32_t {
        return name == "vrf_alpha" ? 10 : 20;
    };

    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    assert(result->l3_rules.size() == 2);
}

// ── Struct layout checks ────────────────────────────────────

TEST(test_struct_layout_l3_rule) {
    static_assert(sizeof(struct l3_rule) == 20, "l3_rule should be 20 bytes");
    static_assert(offsetof(struct l3_rule, action) == 4);
    static_assert(offsetof(struct l3_rule, redirect_ifindex) == 8);
    static_assert(offsetof(struct l3_rule, mirror_ifindex) == 12);
}

TEST(test_struct_layout_lpm_key) {
    static_assert(sizeof(struct lpm_v4_key) == 8, "lpm_v4_key should be 8 bytes");
}

TEST(test_struct_layout_mac_key) {
    static_assert(sizeof(struct mac_key) == 8, "mac_key should be 8 bytes (padded)");
}

TEST(test_struct_layout_l4_match_key) {
    static_assert(sizeof(struct l4_match_key) == 4, "l4_match_key should be 4 bytes");
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
