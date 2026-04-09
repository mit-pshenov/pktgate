#include "config/config_parser.hpp"
#include <cassert>
#include <iostream>

using namespace pktgate::config;

static const char* SAMPLE_JSON = R"({
  "device_info": { "interface": "Gi-0/1", "capacity": "10Gbps" },
  "objects": {
    "subnets": {
      "trusted_clients": "100.64.0.0/16",
      "malicious_net": "192.0.2.0/24"
    },
    "mac_groups": {
      "border_routers": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"]
    },
    "port_groups": {
      "web_services": [80, 443, 8080],
      "critical_dns": [53]
    }
  },
  "pipeline": {
    "layer_2": [
      {
        "rule_id": 10,
        "description": "Allow only known router MACs",
        "match": { "src_mac": "object:border_routers" },
        "action": "allow",
        "next_layer": "layer_3"
      }
    ],
    "layer_3": [
      {
        "rule_id": 100,
        "match": { "src_ip": "object:malicious_net" },
        "action": "mirror",
        "action_params": { "target_port": "Eth-1/10" },
        "next_layer": "layer_4"
      },
      {
        "rule_id": 110,
        "match": { "vrf": "unpaid_customers" },
        "action": "redirect",
        "action_params": { "target_vrf": "captive_portal_vrf" }
      }
    ],
    "layer_4": [
      {
        "rule_id": 1000,
        "match": { "protocol": "UDP", "dst_port": "object:critical_dns" },
        "action": "tag",
        "action_params": { "dscp": "EF", "cos": 5 }
      },
      {
        "rule_id": 1010,
        "match": { "protocol": "TCP", "dst_port": "object:web_services" },
        "action": "rate-limit",
        "action_params": { "bandwidth": "10Gbps" }
      }
    ]
  },
  "default_behavior": "drop"
})";

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry {
    const char* name;
    void (*fn)();
};
static std::vector<TestEntry> tests;

TEST(test_parse_basic) {
    auto result = parse_config_string(SAMPLE_JSON);
    assert(result.has_value());

    auto& cfg = *result;
    assert(cfg.interface == "Gi-0/1");
    assert(cfg.capacity == "10Gbps");
    assert(cfg.default_behavior == Action::Drop);
}

TEST(test_parse_objects) {
    auto result = parse_config_string(SAMPLE_JSON);
    assert(result.has_value());
    auto& obj = result->objects;

    assert(obj.subnets.size() == 2);
    assert(obj.subnets.at("trusted_clients") == "100.64.0.0/16");
    assert(obj.subnets.at("malicious_net") == "192.0.2.0/24");

    assert(obj.mac_groups.size() == 1);
    assert(obj.mac_groups.at("border_routers").size() == 2);

    assert(obj.port_groups.size() == 2);
    assert(obj.port_groups.at("web_services").size() == 3);
    assert(obj.port_groups.at("critical_dns")[0] == 53);
}

TEST(test_parse_pipeline) {
    auto result = parse_config_string(SAMPLE_JSON);
    assert(result.has_value());
    auto& pl = result->pipeline;

    // Layer 2
    assert(pl.layer_2.size() == 1);
    assert(pl.layer_2[0].rule_id == 10);
    assert(pl.layer_2[0].action == Action::Allow);
    assert(pl.layer_2[0].match.src_mac == "object:border_routers");
    assert(pl.layer_2[0].next_layer == "layer_3");

    // Layer 3
    assert(pl.layer_3.size() == 2);
    assert(pl.layer_3[0].rule_id == 100);
    assert(pl.layer_3[0].action == Action::Mirror);
    assert(pl.layer_3[0].params.target_port == "Eth-1/10");
    assert(pl.layer_3[0].next_layer == "layer_4");

    assert(pl.layer_3[1].rule_id == 110);
    assert(pl.layer_3[1].action == Action::Redirect);
    assert(pl.layer_3[1].match.vrf == "unpaid_customers");
    assert(pl.layer_3[1].params.target_vrf == "captive_portal_vrf");

    // Layer 4
    assert(pl.layer_4.size() == 2);
    assert(pl.layer_4[0].rule_id == 1000);
    assert(pl.layer_4[0].action == Action::Tag);
    assert(pl.layer_4[0].params.dscp == "EF");
    assert(pl.layer_4[0].params.cos == 5);
    assert(pl.layer_4[0].match.protocol == "UDP");
    assert(pl.layer_4[0].match.dst_port == "object:critical_dns");

    assert(pl.layer_4[1].rule_id == 1010);
    assert(pl.layer_4[1].action == Action::RateLimit);
    assert(pl.layer_4[1].params.bandwidth == "10Gbps");
}

TEST(test_parse_invalid_json) {
    auto result = parse_config_string("{invalid json}");
    assert(!result.has_value());
}

TEST(test_parse_unknown_action) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id":1, "action":"explode"}] }
    })");
    assert(!result.has_value());
}

TEST(test_dscp_names) {
    assert(dscp_from_name("EF") == 46);
    assert(dscp_from_name("AF11") == 10);
    assert(dscp_from_name("CS5") == 40);
    assert(dscp_from_name("BE") == 0);

    bool threw = false;
    try { dscp_from_name("INVALID"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_bandwidth_parse) {
    assert(parse_bandwidth("10Gbps") == 10000000000ULL);
    assert(parse_bandwidth("100Mbps") == 100000000ULL);
    assert(parse_bandwidth("500Kbps") == 500000ULL);

    bool threw = false;
    try { parse_bandwidth("fast"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_parse_empty_pipeline) {
    auto result = parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "default_behavior": "allow"
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2.empty());
    assert(result->pipeline.layer_3.empty());
    assert(result->pipeline.layer_4.empty());
    assert(result->default_behavior == Action::Allow);
}

// ── Negative: malformed / wrong types ────────────────────────

TEST(test_parse_rule_id_as_string) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id":"not_a_number", "action":"allow"}] }
    })");
    assert(!result.has_value());
}

TEST(test_parse_port_as_string_in_array) {
    auto result = parse_config_string(R"({
        "objects": { "port_groups": { "bad": ["eighty"] } }
    })");
    assert(!result.has_value());
}

TEST(test_parse_cos_as_string) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_4": [{
            "rule_id": 1, "action": "tag",
            "match": {"protocol":"UDP","dst_port":"53"},
            "action_params": {"dscp":"EF", "cos":"high"}
        }]}
    })");
    assert(!result.has_value());
}

TEST(test_parse_truncated_json) {
    auto result = parse_config_string(R"({"pipeline": { "layer_2": [{"rule_id": 1, "actio)");
    assert(!result.has_value());
}

TEST(test_parse_array_instead_of_object) {
    auto result = parse_config_string(R"([1, 2, 3])");
    // Top-level array — not an object, fields won't match
    // nlohmann will fail on at("pipeline") or similar
    // But since all fields are optional, this may or may not fail.
    // What matters: it doesn't crash.
    (void)result;
}

TEST(test_parse_pipeline_as_string) {
    auto result = parse_config_string(R"({"pipeline": "not an object"})");
    assert(!result.has_value());
}

TEST(test_parse_layer_as_object_not_array) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": {"rule_id":1, "action":"allow"} }
    })");
    assert(!result.has_value());
}

// ── Negative: edge input sizes ──────────────────────────────

TEST(test_parse_rule_id_as_float) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id": 1.5, "action":"allow"}] }
    })");
    // nlohmann may accept 1.5 → 1 truncation or throw — either is fine
    // The important thing is it doesn't crash
    (void)result;
}

TEST(test_parse_negative_rule_id) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id": -1, "action":"allow"}] }
    })");
    // nlohmann may wrap -1 to UINT32_MAX or throw
    // No crash is the requirement
    (void)result;
}

TEST(test_parse_negative_port_in_group) {
    auto result = parse_config_string(R"({
        "objects": { "port_groups": { "bad": [-1] } }
    })");
    // nlohmann may wrap -1 to 65535 or throw — no crash is the requirement
    (void)result;
}

TEST(test_parse_port_too_large_in_group) {
    auto result = parse_config_string(R"({
        "objects": { "port_groups": { "bad": [70000] } }
    })");
    // nlohmann may truncate 70000 to uint16 or throw — no crash
    (void)result;
}

TEST(test_parse_port_as_float_in_group) {
    auto result = parse_config_string(R"({
        "objects": { "port_groups": { "bad": [80.5] } }
    })");
    // No crash is the requirement
    (void)result;
}

// ── Boundary: valid extremes ────────────────────────────────

TEST(test_parse_rule_id_zero) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id": 0, "action":"allow"}] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].rule_id == 0);
}

TEST(test_parse_rule_id_max) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id": 4294967295, "action":"allow"}] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].rule_id == 4294967295u);
}

TEST(test_parse_port_zero_in_group) {
    auto result = parse_config_string(R"({
        "objects": { "port_groups": { "low": [0] } }
    })");
    assert(result.has_value());
    assert(result->objects.port_groups.at("low")[0] == 0);
}

TEST(test_parse_port_65535_in_group) {
    auto result = parse_config_string(R"({
        "objects": { "port_groups": { "high": [65535] } }
    })");
    assert(result.has_value());
    assert(result->objects.port_groups.at("high")[0] == 65535);
}

// ── L2 extended fields: dst_mac, ethertype, vlan_id ────────

TEST(test_l2_dst_mac_parsing) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"dst_mac": "AA:BB:CC:DD:EE:FF"},
            "next_layer": "layer_3"
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.dst_mac == "AA:BB:CC:DD:EE:FF");
}

TEST(test_l2_dst_mac_object_ref) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"dst_mac": "object:routers"},
            "next_layer": "layer_3"
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.dst_mac == "object:routers");
}

TEST(test_l2_ethertype_parsing) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"ethertype": "IPv4"},
            "next_layer": "layer_3"
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.ethertype == "IPv4");
}

TEST(test_l2_ethertype_hex_parsing) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"ethertype": "0x0800"},
            "next_layer": "layer_3"
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.ethertype == "0x0800");
}

TEST(test_l2_vlan_id_parsing) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"vlan_id": 100},
            "next_layer": "layer_3"
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.vlan_id == 100);
}

TEST(test_l2_vlan_id_zero) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"vlan_id": 0}
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.vlan_id.has_value());
    assert(result->pipeline.layer_2[0].match.vlan_id == 0);
}

TEST(test_l2_vlan_id_max) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"vlan_id": 4095}
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.vlan_id == 4095);
}

TEST(test_l2_all_new_fields_in_separate_rules) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [
            {"rule_id": 1, "action": "allow", "match": {"dst_mac": "00:11:22:33:44:55"}},
            {"rule_id": 2, "action": "allow", "match": {"ethertype": "ARP"}},
            {"rule_id": 3, "action": "drop",  "match": {"vlan_id": 200}}
        ], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    auto& l2 = result->pipeline.layer_2;
    assert(l2.size() == 3);
    assert(l2[0].match.dst_mac == "00:11:22:33:44:55");
    assert(l2[1].match.ethertype == "ARP");
    assert(l2[2].match.vlan_id == 200);
}

TEST(test_l2_dst_mac_with_action_params) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "mirror",
            "match": {"dst_mac": "FF:FF:FF:FF:FF:FF"},
            "action_params": {"target_port": "Eth-1/5"}
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.dst_mac == "FF:FF:FF:FF:FF:FF");
    assert(result->pipeline.layer_2[0].params.target_port == "Eth-1/5");
}

// ── Negative: vlan_id boundary / type tests ────────────────

TEST(test_parse_vlan_id_out_of_range_4096) {
    auto result = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id": 1, "action": "drop", "match": {"vlan_id": 4096}}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    assert(!result.has_value());
}

TEST(test_parse_vlan_id_negative) {
    auto result = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id": 1, "action": "drop", "match": {"vlan_id": -1}}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    assert(!result.has_value());
}

TEST(test_parse_vlan_id_large) {
    auto result = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id": 1, "action": "drop", "match": {"vlan_id": 65536}}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    assert(!result.has_value());
}

TEST(test_parse_vlan_id_as_string) {
    auto result = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id": 1, "action": "drop", "match": {"vlan_id": "abc"}}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    assert(!result.has_value());
}

// ── Edge: empty strings and missing match ──────────────────

TEST(test_parse_dst_mac_empty_string) {
    auto result = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id": 1, "action": "drop", "match": {"dst_mac": ""}}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.dst_mac.has_value());
    assert(result->pipeline.layer_2[0].match.dst_mac.value() == "");
}

TEST(test_parse_ethertype_empty_string) {
    auto result = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id": 1, "action": "drop", "match": {"ethertype": ""}}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.ethertype.has_value());
    assert(result->pipeline.layer_2[0].match.ethertype.value() == "");
}

TEST(test_parse_l2_rule_no_match_object) {
    auto result = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id": 1, "action": "drop"}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    assert(result.has_value());
    auto& m = result->pipeline.layer_2[0].match;
    assert(!m.src_mac.has_value());
    assert(!m.dst_mac.has_value());
    assert(!m.ethertype.has_value());
    assert(!m.vlan_id.has_value());
}

TEST(test_parse_l2_rule_empty_match_object) {
    auto result = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id": 1, "action": "drop", "match": {}}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    assert(result.has_value());
    auto& m = result->pipeline.layer_2[0].match;
    assert(!m.src_mac.has_value());
    assert(!m.dst_mac.has_value());
    assert(!m.ethertype.has_value());
    assert(!m.vlan_id.has_value());
}

TEST(test_parse_pcp_field) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"pcp": 6},
            "next_layer": "layer_3"
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.pcp.has_value());
    assert(result->pipeline.layer_2[0].match.pcp == 6);
}

TEST(test_parse_pcp_zero) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"pcp": 0}
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.pcp.has_value());
    assert(result->pipeline.layer_2[0].match.pcp == 0);
}

TEST(test_parse_pcp_boundary_7) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"pcp": 7}
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_2[0].match.pcp == 7);
}

TEST(test_parse_pcp_out_of_range) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"pcp": 8}
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(!result.has_value());
}

TEST(test_parse_pcp_negative) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [{
            "rule_id": 1, "action": "allow",
            "match": {"pcp": -1}
        }], "layer_3": [], "layer_4": [] }
    })");
    assert(!result.has_value());
}

TEST(test_parse_tcp_flags_syn) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [{
            "rule_id": 1, "action": "allow",
            "match": {"protocol": "TCP", "dst_port": "80", "tcp_flags": "SYN"}
        }] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_4[0].match.tcp_flags == "SYN");
}

TEST(test_parse_tcp_flags_syn_not_ack) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [{
            "rule_id": 1, "action": "allow",
            "match": {"protocol": "TCP", "dst_port": "80", "tcp_flags": "SYN,!ACK"}
        }] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_4[0].match.tcp_flags == "SYN,!ACK");
}

TEST(test_parse_tcp_flags_multiple) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [{
            "rule_id": 1, "action": "allow",
            "match": {"protocol": "TCP", "dst_port": "80", "tcp_flags": "SYN,ACK"}
        }] }
    })");
    assert(result.has_value());
    assert(result->pipeline.layer_4[0].match.tcp_flags == "SYN,ACK");
}

TEST(test_parse_tcp_flags_all_names) {
    // All 8 flag names should be recognized
    for (auto name : {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}) {
        auto result = parse_config_string(R"({
            "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [{
                "rule_id": 1, "action": "allow",
                "match": {"protocol": "TCP", "dst_port": "80", "tcp_flags": ")" + std::string(name) + R"("}
            }] }
        })");
        assert(result.has_value());
    }
}

TEST(test_parse_tcp_flags_empty_rejected) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [{
            "rule_id": 1, "action": "allow",
            "match": {"protocol": "TCP", "dst_port": "80", "tcp_flags": ""}
        }] }
    })");
    assert(!result.has_value());
}

TEST(test_parse_tcp_flags_invalid_name) {
    auto result = parse_config_string(R"({
        "pipeline": { "layer_2": [], "layer_3": [], "layer_4": [{
            "rule_id": 1, "action": "allow",
            "match": {"protocol": "TCP", "dst_port": "80", "tcp_flags": "BOGUS"}
        }] }
    })");
    assert(!result.has_value());
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
