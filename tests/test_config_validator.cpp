#include "config/config_validator.hpp"
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

static bool has_error(const std::vector<ValidationError>& errs, const std::string& substr) {
    for (auto& e : errs)
        if (e.message.find(substr) != std::string::npos)
            return true;
    return false;
}

// ── Valid config passes ─────────────────────────────────────

TEST(test_valid_full_config) {
    auto cfg = parse_config_string(R"({
        "device_info": {"interface": "eth0", "capacity": "10Gbps"},
        "objects": {
            "subnets": {"net": "10.0.0.0/8"},
            "mac_groups": {"routers": ["AA:BB:CC:DD:EE:FF"]},
            "port_groups": {"web": [80, 443]}
        },
        "pipeline": {
            "layer_2": [{"rule_id":1, "action":"allow", "match":{"src_mac":"object:routers"}, "next_layer":"layer_3"}],
            "layer_3": [{"rule_id":10, "action":"allow", "match":{"src_ip":"object:net"}, "next_layer":"layer_4"}],
            "layer_4": [{"rule_id":100, "action":"rate-limit", "match":{"protocol":"TCP","dst_port":"object:web"}, "action_params":{"bandwidth":"1Gbps"}}]
        },
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());
    auto r = validate_config(*cfg);
    assert(r.has_value());
}

TEST(test_valid_empty_config) {
    Config cfg;
    auto r = validate_config(cfg);
    assert(r.has_value());
}

TEST(test_empty_interface_with_rules) {
    Config cfg;
    // interface is empty but rules exist → should fail
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.src_mac = "AA:BB:CC:DD:EE:FF";
    cfg.pipeline.layer_2.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "interface must not be empty"));
}

// ── Duplicate rule_id ───────────────────────────────────────

TEST(test_duplicate_rule_id_l2) {
    Config cfg;
    Rule r1, r2;
    r1.rule_id = 10; r1.action = Action::Allow;
    r2.rule_id = 10; r2.action = Action::Drop;
    cfg.pipeline.layer_2 = {r1, r2};

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "duplicate rule_id 10"));
}

TEST(test_duplicate_rule_id_l3) {
    Config cfg;
    cfg.objects.subnets["n1"] = "10.0.0.0/8";
    cfg.objects.subnets["n2"] = "172.16.0.0/12";

    Rule r1, r2;
    r1.rule_id = 100; r1.action = Action::Drop;
    r1.match.src_ip = "object:n1";
    r2.rule_id = 100; r2.action = Action::Drop;
    r2.match.src_ip = "object:n2";
    cfg.pipeline.layer_3 = {r1, r2};

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "duplicate rule_id 100"));
}

TEST(test_same_rule_id_different_layers_ok) {
    Config cfg;
    cfg.interface = "eth0";
    cfg.objects.subnets["net"] = "10.0.0.0/8";

    Rule r1;
    r1.rule_id = 1; r1.action = Action::Allow;
    cfg.pipeline.layer_2.push_back(r1);

    Rule r2;
    r2.rule_id = 1; r2.action = Action::Drop;
    r2.match.src_ip = "object:net";
    cfg.pipeline.layer_3.push_back(r2);

    auto result = validate_config(cfg);
    assert(result.has_value()); // Same ID in different layers is OK
}

// ── Unknown object references ───────────────────────────────

TEST(test_unknown_mac_ref) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.src_mac = "object:nonexistent";
    cfg.pipeline.layer_2.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "unknown mac_group object: nonexistent"));
}

TEST(test_unknown_subnet_ref) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Drop;
    r.match.src_ip = "object:ghost_net";
    cfg.pipeline.layer_3.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "unknown subnet object: ghost_net"));
}

TEST(test_unknown_port_group_ref) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "object:ghost_ports";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "unknown port_group object: ghost_ports"));
}

// ── L4 missing fields ───────────────────────────────────────

TEST(test_l4_missing_protocol) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.dst_port = "80";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "L4 rule requires protocol"));
}

TEST(test_l4_missing_dst_port) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.protocol = "TCP";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "L4 rule requires dst_port"));
}

TEST(test_l4_unsupported_protocol) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.protocol = "ICMP";
    r.match.dst_port = "80";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "unsupported protocol: ICMP"));
}

// ── Port validation ─────────────────────────────────────────

TEST(test_l4_port_out_of_range) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "70000";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "port out of range"));
}

TEST(test_l4_negative_port) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "-1";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "port out of range") ||
           has_error(result.error(), "invalid port"));
}

TEST(test_l4_non_numeric_port) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "http";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "invalid port"));
}

// ── Action-param consistency ────────────────────────────────

TEST(test_mirror_without_target) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Mirror;
    r.match.src_ip = "10.0.0.0/8";
    cfg.pipeline.layer_3.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "mirror action requires target_port"));
}

TEST(test_redirect_without_target_vrf) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Redirect;
    r.match.vrf = "guest";
    cfg.pipeline.layer_3.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "redirect action requires target_vrf"));
}

TEST(test_rate_limit_without_bandwidth) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::RateLimit;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "rate-limit action requires bandwidth"));
}

TEST(test_rate_limit_invalid_bandwidth) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::RateLimit;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    r.params.bandwidth = "fast";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "invalid bandwidth"));
}

TEST(test_rate_limit_bandwidth_overflow) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::RateLimit;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    r.params.bandwidth = "99999999999Gbps"; // overflows uint64_t
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "invalid bandwidth"));
}

// ── DSCP/CoS validation ─────────────────────────────────────

TEST(test_tag_unknown_dscp) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Tag;
    r.match.protocol = "UDP";
    r.match.dst_port = "53";
    r.params.dscp = "INVALID_DSCP";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "unknown DSCP name"));
}

TEST(test_tag_cos_out_of_range) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Tag;
    r.match.protocol = "UDP";
    r.match.dst_port = "53";
    r.params.dscp = "EF";
    r.params.cos = 8; // max is 7
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "CoS must be 0-7"));
}

// ── next_layer validation ───────────────────────────────────

TEST(test_l2_invalid_next_layer) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.next_layer = "layer_5";
    cfg.pipeline.layer_2.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "invalid next_layer"));
}

TEST(test_l3_invalid_next_layer) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Drop;
    r.match.src_ip = "10.0.0.0/8";
    r.next_layer = "layer_2"; // can't go backwards
    cfg.pipeline.layer_3.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "invalid next_layer"));
}

TEST(test_l4_no_next_layer_allowed) {
    Config cfg;
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    r.next_layer = "layer_5";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    assert(has_error(result.error(), "layer_4 cannot have next_layer"));
}

// ── Multiple errors ─────────────────────────────────────────

TEST(test_multiple_errors_reported) {
    Config cfg;

    // L4 rule with multiple problems
    Rule r1;
    r1.rule_id = 1; r1.action = Action::RateLimit;
    // Missing protocol, port, bandwidth
    cfg.pipeline.layer_4.push_back(r1);

    Rule r2;
    r2.rule_id = 1; r2.action = Action::Tag;
    r2.match.protocol = "SCTP";
    r2.match.dst_port = "abc";
    r2.params.dscp = "NOPE";
    r2.params.cos = 10;
    cfg.pipeline.layer_4.push_back(r2);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    // Should have at least 5 errors
    assert(result.error().size() >= 5);
}

// ── Literal refs don't trigger object checks ────────────────

TEST(test_literal_mac_no_check) {
    Config cfg;
    cfg.interface = "eth0";
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.src_mac = "AA:BB:CC:DD:EE:FF"; // literal, not object ref
    cfg.pipeline.layer_2.push_back(r);

    auto result = validate_config(cfg);
    assert(result.has_value());
}

TEST(test_literal_subnet_no_check) {
    Config cfg;
    cfg.interface = "eth0";
    Rule r;
    r.rule_id = 1; r.action = Action::Drop;
    r.match.src_ip = "10.0.0.0/8"; // literal CIDR
    cfg.pipeline.layer_3.push_back(r);

    auto result = validate_config(cfg);
    assert(result.has_value());
}

TEST(test_literal_port_no_check) {
    Config cfg;
    cfg.interface = "eth0";
    Rule r;
    r.rule_id = 1; r.action = Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "443"; // literal port
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(result.has_value());
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
