#include "config/config_parser.hpp"
#include "config/config_validator.hpp"
#include "compiler/rule_compiler.hpp"
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

// ── Action parsing ─────────────────────────────────────────────

TEST(test_parse_userspace_action) {
    assert(parse_action("userspace") == Action::Userspace);
}

TEST(test_parse_userspace_in_rule) {
    auto r = parse_config_string(R"({
        "pipeline": {
            "layer_3": [{
                "rule_id": 1,
                "action": "userspace",
                "match": {"src_ip": "10.0.0.0/8"}
            }]
        }
    })");
    assert(r.has_value());
    assert(r->pipeline.layer_3[0].action == Action::Userspace);
}

// ── AfXdpConfig parsing ───────────────────────────────────────

TEST(test_parse_afxdp_defaults) {
    auto r = parse_config_string(R"({})");
    assert(r.has_value());
    assert(!r->afxdp.enabled);
    assert(r->afxdp.queues == 0);
    assert(!r->afxdp.zero_copy);
    assert(r->afxdp.frame_size == 4096);
    assert(r->afxdp.num_frames == 4096);
}

TEST(test_parse_afxdp_enabled) {
    auto r = parse_config_string(R"({
        "afxdp": {
            "enabled": true,
            "queues": 4,
            "zero_copy": true,
            "frame_size": 2048,
            "num_frames": 8192
        }
    })");
    assert(r.has_value());
    assert(r->afxdp.enabled);
    assert(r->afxdp.queues == 4);
    assert(r->afxdp.zero_copy);
    assert(r->afxdp.frame_size == 2048);
    assert(r->afxdp.num_frames == 8192);
}

TEST(test_parse_afxdp_partial) {
    auto r = parse_config_string(R"({
        "afxdp": { "enabled": true }
    })");
    assert(r.has_value());
    assert(r->afxdp.enabled);
    assert(r->afxdp.queues == 0);  // default
    assert(r->afxdp.frame_size == 4096);  // default
}

// ── Validation ─────────────────────────────────────────────────

TEST(test_userspace_requires_afxdp_enabled) {
    Config cfg;
    cfg.interface = "eth0";
    cfg.afxdp.enabled = false;
    Rule r;
    r.rule_id = 1;
    r.action = Action::Userspace;
    r.match.src_ip = "10.0.0.0/8";
    cfg.pipeline.layer_3.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
    bool found = false;
    for (auto& e : result.error()) {
        if (e.message.find("afxdp.enabled") != std::string::npos)
            found = true;
    }
    assert(found);
}

TEST(test_userspace_ok_with_afxdp_enabled) {
    Config cfg;
    cfg.interface = "eth0";
    cfg.afxdp.enabled = true;
    Rule r;
    r.rule_id = 1;
    r.action = Action::Userspace;
    r.match.src_ip = "10.0.0.0/8";
    cfg.pipeline.layer_3.push_back(r);

    auto result = validate_config(cfg);
    assert(result.has_value());
}

TEST(test_userspace_cannot_be_default) {
    Config cfg;
    cfg.interface = "eth0";
    cfg.default_behavior = Action::Userspace;
    cfg.afxdp.enabled = true;

    auto result = validate_config(cfg);
    assert(!result.has_value());
    bool found = false;
    for (auto& e : result.error()) {
        if (e.message.find("default") != std::string::npos)
            found = true;
    }
    assert(found);
}

TEST(test_userspace_l4_requires_afxdp) {
    Config cfg;
    cfg.interface = "eth0";
    cfg.afxdp.enabled = false;
    Rule r;
    r.rule_id = 1;
    r.action = Action::Userspace;
    r.match.protocol = "TCP";
    r.match.dst_port = "80";
    cfg.pipeline.layer_4.push_back(r);

    auto result = validate_config(cfg);
    assert(!result.has_value());
}

// ── Rule compiler ──────────────────────────────────────────────

TEST(test_compile_userspace_l3) {
    Pipeline pipeline;
    ObjectStore objects;
    Rule r;
    r.rule_id = 42;
    r.action = Action::Userspace;
    r.match.src_ip = "192.168.1.0/24";
    pipeline.layer_3.push_back(r);

    auto resolver = [](const std::string&) -> uint32_t { return 1; };
    auto result = pktgate::compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    assert(result->l3_rules.size() == 1);
    assert(result->l3_rules[0].rule.action == 6);  // ACT_USERSPACE
}

TEST(test_compile_userspace_l4) {
    Pipeline pipeline;
    ObjectStore objects;
    Rule r;
    r.rule_id = 99;
    r.action = Action::Userspace;
    r.match.protocol = "UDP";
    r.match.dst_port = "5000";
    pipeline.layer_4.push_back(r);

    auto resolver = [](const std::string&) -> uint32_t { return 1; };
    auto result = pktgate::compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    assert(result->l4_rules.size() == 1);
    assert(result->l4_rules[0].rule.action == 6);  // ACT_USERSPACE
}

// ── Full pipeline round-trip ───────────────────────────────────

TEST(test_parse_validate_userspace_full) {
    auto r = parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "afxdp": {"enabled": true, "queues": 2},
        "pipeline": {
            "layer_3": [{
                "rule_id": 1,
                "action": "userspace",
                "match": {"src_ip": "10.0.0.0/8"},
                "next_layer": "layer_4"
            }],
            "layer_4": [{
                "rule_id": 10,
                "action": "userspace",
                "match": {"protocol": "TCP", "dst_port": "443"}
            }]
        }
    })");
    assert(r.has_value());
    assert(r->afxdp.enabled);
    assert(r->afxdp.queues == 2);
    assert(r->pipeline.layer_3[0].action == Action::Userspace);
    assert(r->pipeline.layer_4[0].action == Action::Userspace);

    auto v = validate_config(*r);
    assert(v.has_value());
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
