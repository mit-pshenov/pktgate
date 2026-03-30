/*
 * Config round-trip tests: parse JSON → validate → compile → verify results.
 * End-to-end without BPF, verifying object resolution, port expansion, CIDR parsing.
 */
#include "config/config_parser.hpp"
#include "config/config_validator.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "../../bpf/common.h"

#include <cassert>
#include <iostream>
#include <arpa/inet.h>

using namespace pktgate;

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry { const char* name; void (*fn)(); };
static std::vector<TestEntry> tests;

static auto mock_resolver = [](const std::string&) -> uint32_t { return 99; };

// ═══════════════════════════════════════════════════════════
// Full pipeline round-trip
// ═══════════════════════════════════════════════════════════

static const char* FULL_CONFIG = R"({
    "device_info": { "interface": "Gi-0/1", "capacity": "10Gbps" },
    "objects": {
        "subnets": {
            "trusted": "10.0.0.0/8",
            "blocked": "192.0.2.0/24"
        },
        "mac_groups": {
            "routers": ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]
        },
        "port_groups": {
            "web": [80, 443],
            "dns": [53]
        }
    },
    "pipeline": {
        "layer_3": [
            {
                "rule_id": 100,
                "match": { "src_ip": "object:blocked" },
                "action": "drop"
            },
            {
                "rule_id": 110,
                "match": { "src_ip": "object:trusted" },
                "action": "allow",
                "next_layer": "layer_4"
            }
        ],
        "layer_4": [
            {
                "rule_id": 1000,
                "match": { "protocol": "TCP", "dst_port": "object:web" },
                "action": "allow"
            },
            {
                "rule_id": 1001,
                "match": { "protocol": "UDP", "dst_port": "object:dns" },
                "action": "tag",
                "action_params": { "dscp": "EF", "cos": 5 }
            }
        ]
    },
    "default_behavior": "drop"
})";

TEST(roundtrip_parse_succeeds) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    assert(cfg.has_value());
    assert(cfg->interface == "Gi-0/1");
    assert(cfg->default_behavior == config::Action::Drop);
}

TEST(roundtrip_validate_succeeds) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    assert(cfg.has_value());

    auto vr = config::validate_config(*cfg);
    assert(vr.has_value());
}

TEST(roundtrip_compile_objects_succeeds) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    assert(cfg.has_value());

    auto co = compiler::compile_objects(cfg->objects);
    assert(co.has_value());
    assert(co->macs.size() == 2);
    assert(co->subnets.size() == 2);
    assert(co->port_groups.size() == 2);
}

TEST(roundtrip_compile_rules_succeeds) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    assert(cfg.has_value());

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.size() == 2);
    // web=[80,443] + dns=[53] = 3 L4 rules
    assert(cr->l4_rules.size() == 3);
}

TEST(roundtrip_l3_blocked_subnet_bytes) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);
    assert(cr.has_value());

    // rule_id=100 is "blocked" = 192.0.2.0/24
    auto& r0 = cr->l3_rules[0];
    assert(r0.rule.rule_id == 100);
    assert(r0.rule.action == ACT_DROP);
    assert(r0.subnet_key.prefixlen == 24);

    uint32_t expected;
    inet_pton(AF_INET, "192.0.2.0", &expected);
    assert(r0.subnet_key.addr == expected);
}

TEST(roundtrip_l3_trusted_subnet_with_next_layer) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);

    auto& r1 = cr->l3_rules[1];
    assert(r1.rule.rule_id == 110);
    assert(r1.rule.action == ACT_ALLOW);
    assert(r1.rule.has_next_layer == 1);
    assert(r1.subnet_key.prefixlen == 8);

    uint32_t expected;
    inet_pton(AF_INET, "10.0.0.0", &expected);
    assert(r1.subnet_key.addr == expected);
}

TEST(roundtrip_l4_web_ports_expanded) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);

    // First two L4 rules from "object:web" = TCP:80, TCP:443
    assert(cr->l4_rules[0].match.protocol == 6);
    assert(cr->l4_rules[0].match.dst_port == 80);
    assert(cr->l4_rules[0].rule.rule_id == 1000);
    assert(cr->l4_rules[0].rule.action == ACT_ALLOW);

    assert(cr->l4_rules[1].match.protocol == 6);
    assert(cr->l4_rules[1].match.dst_port == 443);
    assert(cr->l4_rules[1].rule.rule_id == 1000);
}

TEST(roundtrip_l4_dns_tag_params) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);

    // Third L4 rule: UDP:53 TAG
    auto& dns = cr->l4_rules[2];
    assert(dns.match.protocol == 17);
    assert(dns.match.dst_port == 53);
    assert(dns.rule.action == ACT_TAG);
    assert(dns.rule.dscp == 46); // EF
    assert(dns.rule.cos == 5);
}

TEST(roundtrip_mac_objects_compiled) {
    auto cfg = config::parse_config_string(FULL_CONFIG);
    auto co = compiler::compile_objects(cfg->objects);

    // Two MACs in "routers" group
    assert(co->macs.size() == 2);
    assert(co->macs[0].key.addr[0] == 0xAA);
    assert(co->macs[0].key.addr[5] == 0x01);
    assert(co->macs[1].key.addr[5] == 0x02);
    assert(co->macs[0].value == 1);
    assert(co->macs[1].value == 1);
}

// ═══════════════════════════════════════════════════════════
// Error paths in round-trip
// ═══════════════════════════════════════════════════════════

TEST(roundtrip_invalid_json_fails_early) {
    auto cfg = config::parse_config_string("{broken");
    assert(!cfg.has_value());
}

TEST(roundtrip_unknown_action_fails) {
    auto cfg = config::parse_config_string(R"({
        "pipeline": { "layer_3": [{"rule_id":1, "action":"nuke"}] }
    })");
    assert(!cfg.has_value());
}

TEST(roundtrip_dangling_object_ref_caught_by_compiler) {
    auto cfg = config::parse_config_string(R"({
        "pipeline": {
            "layer_3": [{"rule_id":1, "action":"drop", "match":{"src_ip":"object:nonexistent"}}]
        }
    })");
    assert(cfg.has_value());

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);
    assert(!cr.has_value()); // object not found
}

TEST(roundtrip_dangling_port_group_caught) {
    auto cfg = config::parse_config_string(R"({
        "pipeline": {
            "layer_4": [{
                "rule_id":1, "action":"allow",
                "match":{"protocol":"TCP","dst_port":"object:ghost_ports"}
            }]
        }
    })");
    assert(cfg.has_value());

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);
    assert(!cr.has_value());
}

TEST(roundtrip_missing_protocol_in_l4) {
    auto cfg = config::parse_config_string(R"({
        "pipeline": {
            "layer_4": [{"rule_id":1, "action":"allow", "match":{"dst_port":"80"}}]
        }
    })");
    assert(cfg.has_value());

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);
    assert(!cr.has_value());
}

TEST(roundtrip_missing_dst_port_in_l4) {
    auto cfg = config::parse_config_string(R"({
        "pipeline": {
            "layer_4": [{"rule_id":1, "action":"allow", "match":{"protocol":"TCP"}}]
        }
    })");
    assert(cfg.has_value());

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);
    assert(!cr.has_value());
}

// ═══════════════════════════════════════════════════════════
// Edge: empty / minimal configs
// ═══════════════════════════════════════════════════════════

TEST(roundtrip_empty_pipeline_compiles) {
    auto cfg = config::parse_config_string(R"({
        "default_behavior": "allow"
    })");
    assert(cfg.has_value());

    auto co = compiler::compile_objects(cfg->objects);
    assert(co.has_value());
    assert(co->macs.empty());
    assert(co->subnets.empty());

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.empty());
    assert(cr->l4_rules.empty());
}

TEST(roundtrip_single_rule_minimal) {
    auto cfg = config::parse_config_string(R"({
        "pipeline": {
            "layer_3": [{"rule_id":1, "action":"drop", "match":{"src_ip":"0.0.0.0/0"}}]
        }
    })");
    assert(cfg.has_value());

    auto cr = compiler::compile_rules(cfg->pipeline, cfg->objects, mock_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.size() == 1);
    assert(cr->l3_rules[0].subnet_key.prefixlen == 0);
    assert(cr->l3_rules[0].subnet_key.addr == 0);
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
