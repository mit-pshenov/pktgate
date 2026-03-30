#include "config/config_parser.hpp"
#include <cassert>
#include <iostream>
#include <vector>

using namespace pktgate::config;

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry {
    const char* name;
    void (*fn)();
};
static std::vector<TestEntry> tests;

// ── Missing / malformed fields ──────────────────────────────

TEST(test_missing_rule_id) {
    auto r = parse_config_string(R"({
        "pipeline": { "layer_2": [{"action":"allow", "match":{"src_mac":"AA:BB:CC:DD:EE:FF"}}] }
    })");
    assert(!r.has_value());
}

TEST(test_missing_action) {
    auto r = parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id": 1}] }
    })");
    assert(!r.has_value());
}

TEST(test_null_json) {
    auto r = parse_config_string("null");
    // null is valid JSON but should produce empty/default config or fail
    // It actually parses fine since all fields are optional
    // The important thing is it doesn't crash
    (void)r;
}

TEST(test_empty_object) {
    auto r = parse_config_string("{}");
    assert(r.has_value());
    assert(r->pipeline.layer_2.empty());
    assert(r->pipeline.layer_3.empty());
    assert(r->pipeline.layer_4.empty());
}

TEST(test_empty_string_input) {
    auto r = parse_config_string("");
    assert(!r.has_value());
}

TEST(test_deeply_nested_invalid) {
    auto r = parse_config_string(R"({
        "pipeline": {
            "layer_3": [{
                "rule_id": 100,
                "action": "mirror",
                "action_params": { "target_port": 12345 }
            }]
        }
    })");
    // target_port should be string, not int — should fail
    assert(!r.has_value());
}

// ── Default behavior variations ─────────────────────────────

TEST(test_default_behavior_allow) {
    auto r = parse_config_string(R"({"default_behavior": "allow"})");
    assert(r.has_value());
    assert(r->default_behavior == Action::Allow);
}

TEST(test_default_behavior_drop) {
    auto r = parse_config_string(R"({"default_behavior": "drop"})");
    assert(r.has_value());
    assert(r->default_behavior == Action::Drop);
}

TEST(test_default_behavior_invalid) {
    auto r = parse_config_string(R"({"default_behavior": "panic"})");
    assert(!r.has_value());
}

TEST(test_default_behavior_absent) {
    auto r = parse_config_string(R"({})");
    assert(r.has_value());
    assert(r->default_behavior == Action::Drop); // default
}

// ── Object store edge cases ─────────────────────────────────

TEST(test_empty_mac_group) {
    auto r = parse_config_string(R"({
        "objects": { "mac_groups": { "empty_group": [] } }
    })");
    assert(r.has_value());
    assert(r->objects.mac_groups.at("empty_group").empty());
}

TEST(test_empty_port_group) {
    auto r = parse_config_string(R"({
        "objects": { "port_groups": { "empty": [] } }
    })");
    assert(r.has_value());
    assert(r->objects.port_groups.at("empty").empty());
}

TEST(test_single_port_in_group) {
    auto r = parse_config_string(R"({
        "objects": { "port_groups": { "single": [443] } }
    })");
    assert(r.has_value());
    assert(r->objects.port_groups.at("single").size() == 1);
    assert(r->objects.port_groups.at("single")[0] == 443);
}

TEST(test_multiple_subnet_objects) {
    auto r = parse_config_string(R"({
        "objects": {
            "subnets": {
                "net1": "10.0.0.0/8",
                "net2": "172.16.0.0/12",
                "net3": "192.168.0.0/16"
            }
        }
    })");
    assert(r.has_value());
    assert(r->objects.subnets.size() == 3);
}

// ── Pipeline layer variants ─────────────────────────────────

TEST(test_all_action_types_in_pipeline) {
    auto r = parse_config_string(R"({
        "pipeline": {
            "layer_2": [
                {"rule_id":1, "action":"allow", "match":{"src_mac":"AA:BB:CC:DD:EE:FF"}}
            ],
            "layer_3": [
                {"rule_id":10, "action":"drop", "match":{"src_ip":"10.0.0.0/8"}},
                {"rule_id":11, "action":"mirror", "match":{"src_ip":"192.0.2.0/24"}, "action_params":{"target_port":"eth1"}},
                {"rule_id":12, "action":"redirect", "match":{"vrf":"test"}, "action_params":{"target_vrf":"other"}}
            ],
            "layer_4": [
                {"rule_id":100, "action":"tag", "match":{"protocol":"UDP","dst_port":"53"}, "action_params":{"dscp":"EF","cos":5}},
                {"rule_id":101, "action":"rate-limit", "match":{"protocol":"TCP","dst_port":"80"}, "action_params":{"bandwidth":"1Gbps"}}
            ]
        }
    })");
    assert(r.has_value());
    assert(r->pipeline.layer_2.size() == 1);
    assert(r->pipeline.layer_3.size() == 3);
    assert(r->pipeline.layer_4.size() == 2);
}

TEST(test_rule_with_description) {
    auto r = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{
                "rule_id": 1,
                "description": "Allow border routers",
                "action": "allow",
                "match": {"src_mac": "AA:BB:CC:DD:EE:FF"}
            }]
        }
    })");
    assert(r.has_value());
    assert(r->pipeline.layer_2[0].description == "Allow border routers");
}

TEST(test_rule_without_match) {
    // A rule with no match criteria — should parse OK (match all)
    auto r = parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id":1, "action":"drop"}] }
    })");
    assert(r.has_value());
    assert(!r->pipeline.layer_2[0].match.src_mac.has_value());
    assert(!r->pipeline.layer_2[0].match.src_ip.has_value());
}

TEST(test_next_layer_chaining) {
    auto r = parse_config_string(R"({
        "pipeline": {
            "layer_2": [{"rule_id":1, "action":"allow", "next_layer":"layer_3"}],
            "layer_3": [{"rule_id":10, "action":"allow", "match":{"src_ip":"0.0.0.0/0"}, "next_layer":"layer_4"}],
            "layer_4": [{"rule_id":100, "action":"allow", "match":{"protocol":"TCP","dst_port":"80"}}]
        }
    })");
    assert(r.has_value());
    assert(r->pipeline.layer_2[0].next_layer == "layer_3");
    assert(r->pipeline.layer_3[0].next_layer == "layer_4");
    assert(!r->pipeline.layer_4[0].next_layer.has_value());
}

// ── DSCP/bandwidth edge cases ───────────────────────────────

TEST(test_all_dscp_af_classes) {
    assert(dscp_from_name("AF11") == 10);
    assert(dscp_from_name("AF12") == 12);
    assert(dscp_from_name("AF13") == 14);
    assert(dscp_from_name("AF21") == 18);
    assert(dscp_from_name("AF22") == 20);
    assert(dscp_from_name("AF23") == 22);
    assert(dscp_from_name("AF31") == 26);
    assert(dscp_from_name("AF32") == 28);
    assert(dscp_from_name("AF33") == 30);
    assert(dscp_from_name("AF41") == 34);
    assert(dscp_from_name("AF42") == 36);
    assert(dscp_from_name("AF43") == 38);
}

TEST(test_all_dscp_cs_classes) {
    assert(dscp_from_name("CS0") == 0);
    assert(dscp_from_name("CS1") == 8);
    assert(dscp_from_name("CS2") == 16);
    assert(dscp_from_name("CS3") == 24);
    assert(dscp_from_name("CS4") == 32);
    assert(dscp_from_name("CS5") == 40);
    assert(dscp_from_name("CS6") == 48);
    assert(dscp_from_name("CS7") == 56);
}

TEST(test_bandwidth_bps) {
    assert(parse_bandwidth("1000bps") == 1000ULL);
}

TEST(test_bandwidth_kbps) {
    assert(parse_bandwidth("64Kbps") == 64000ULL);
    assert(parse_bandwidth("64kbps") == 64000ULL);
}

TEST(test_bandwidth_mbps) {
    assert(parse_bandwidth("100Mbps") == 100000000ULL);
    assert(parse_bandwidth("100mbps") == 100000000ULL);
}

TEST(test_bandwidth_gbps) {
    assert(parse_bandwidth("10Gbps") == 10000000000ULL);
    assert(parse_bandwidth("100Gbps") == 100000000000ULL);
    assert(parse_bandwidth("10gbps") == 10000000000ULL);
}

TEST(test_bandwidth_zero) {
    assert(parse_bandwidth("0Gbps") == 0ULL);
}

TEST(test_bandwidth_invalid_unit) {
    bool threw = false;
    try { parse_bandwidth("10Tbps"); } catch (...) { threw = true; }
    assert(threw);
}

TEST(test_bandwidth_no_number) {
    bool threw = false;
    try { parse_bandwidth("Gbps"); } catch (...) { threw = true; }
    assert(threw);
}

// ── File-based parsing ──────────────────────────────────────

TEST(test_parse_nonexistent_file) {
    auto r = parse_config("/tmp/nonexistent_filter_config_12345.json");
    assert(!r.has_value());
}

// ── Action parsing ──────────────────────────────────────────

TEST(test_parse_all_actions) {
    assert(parse_action("allow") == Action::Allow);
    assert(parse_action("drop") == Action::Drop);
    assert(parse_action("mirror") == Action::Mirror);
    assert(parse_action("redirect") == Action::Redirect);
    assert(parse_action("tag") == Action::Tag);
    assert(parse_action("rate-limit") == Action::RateLimit);
    assert(parse_action("userspace") == Action::Userspace);
}

TEST(test_parse_unknown_action_throws) {
    bool threw = false;
    try { parse_action("block"); } catch (...) { threw = true; }
    assert(threw);
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
