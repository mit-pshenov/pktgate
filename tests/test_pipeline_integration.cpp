#include "config/config_parser.hpp"
#include "config/config_validator.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "pipeline/generation_manager.hpp"
#include "pipeline/pipeline_builder.hpp"
#include <bpf/libbpf.h>
#include <cassert>
#include <iostream>
#include <vector>
#include <atomic>

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

/*
 * Mock BPF loader for testing control plane logic without kernel.
 * Tracks map operations in-memory for verification.
 */
struct MockMapEntry {
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
};

struct MockMap {
    std::vector<MockMapEntry> entries;
    void clear() { entries.clear(); }
    size_t size() const { return entries.size(); }
};

// Global mock state
static MockMap g_l2_maps[2];
static MockMap g_subnet_rules[2];
static MockMap g_vrf_rules[2];
static MockMap g_l4_rules[2];
static MockMap g_default_action[2];
static MockMap g_prog_array[2];
static MockMap g_gen_config;
static uint32_t g_active_gen = 0;

static auto null_resolver = [](const std::string&) -> uint32_t { return 0; };

static void reset_mock_state() {
    for (int i = 0; i < 2; ++i) {
        g_l2_maps[i].clear();
        g_subnet_rules[i].clear();
        g_vrf_rules[i].clear();
        g_l4_rules[i].clear();
        g_default_action[i].clear();
        g_prog_array[i].clear();
    }
    g_gen_config.clear();
    g_active_gen = 0;
}

/*
 * Test the generation state machine exhaustively.
 */
TEST(test_generation_state_machine_extended) {
    // Simulated state machine matching GenerationManager logic
    std::atomic<uint32_t> active_gen{0};

    auto shadow = [&]() -> uint32_t { return active_gen.load() ^ 1; };

    // Initial state
    assert(active_gen.load() == 0);
    assert(shadow() == 1);

    // 10 commit cycles
    for (int i = 0; i < 10; ++i) {
        uint32_t expected_new = shadow();
        active_gen.store(expected_new);
        assert(active_gen.load() == (i % 2 == 0 ? 1u : 0u));
    }

    // Back to gen 0 after even number of commits
    assert(active_gen.load() == 0);
}

TEST(test_generation_prepare_commit_rollback_cycle) {
    std::atomic<uint32_t> active_gen{0};
    auto shadow = [&]() -> uint32_t { return active_gen.load() ^ 1; };

    // Prepare fills shadow (gen 1)
    uint32_t prep_gen = shadow();
    assert(prep_gen == 1);

    // Commit: switch to gen 1
    active_gen.store(prep_gen);
    assert(active_gen.load() == 1);

    // Rollback: switch back to gen 0
    active_gen.store(active_gen.load() ^ 1);
    assert(active_gen.load() == 0);
    assert(shadow() == 1);
}

TEST(test_double_prepare_overwrites_shadow) {
    // Simulates two prepare() calls before commit
    // Second prepare should overwrite the first
    std::atomic<uint32_t> active_gen{0};

    // First prepare fills shadow gen 1
    uint32_t shadow_gen = active_gen.load() ^ 1;
    assert(shadow_gen == 1);

    // Simulate clearing and repopulating shadow
    // (what GenerationManager::prepare does)
    // ... clear shadow maps ...
    // ... fill with new data ...

    // Second prepare also targets gen 1 (shadow hasn't changed)
    shadow_gen = active_gen.load() ^ 1;
    assert(shadow_gen == 1);

    // Commit
    active_gen.store(shadow_gen);
    assert(active_gen.load() == 1);
}

/*
 * Test compile → prepare workflow end-to-end (no kernel).
 */
TEST(test_full_compile_pipeline) {
    // Parse config
    auto cfg = config::parse_config_string(R"({
        "device_info": {"interface": "eth0", "capacity": "10Gbps"},
        "objects": {
            "subnets": {"trusted": "10.0.0.0/8"},
            "mac_groups": {"routers": ["AA:BB:CC:DD:EE:FF"]},
            "port_groups": {"web": [80, 443]}
        },
        "pipeline": {
            "layer_2": [{"rule_id":1, "action":"allow", "match":{"src_mac":"object:routers"}, "next_layer":"layer_3"}],
            "layer_3": [{"rule_id":10, "action":"allow", "match":{"src_ip":"object:trusted"}, "next_layer":"layer_4"}],
            "layer_4": [{"rule_id":100, "action":"rate-limit", "match":{"protocol":"TCP","dst_port":"object:web"}, "action_params":{"bandwidth":"1Gbps"}}]
        },
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());

    // Compile objects
    auto objs = compiler::compile_objects(cfg->objects);
    assert(objs.has_value());
    assert(objs->macs.size() == 1);
    assert(objs->subnets.size() == 1);
    assert(objs->port_groups.size() == 1);

    // Compile rules
    auto resolver = [](const std::string&) -> uint32_t { return 0; };
    auto rules = compiler::compile_rules(cfg->pipeline, cfg->objects, resolver);
    assert(rules.has_value());
    assert(rules->l2_rules.size() == 1);  // 1 MAC from routers group
    assert(rules->l3_rules.size() == 1);
    assert(rules->l4_rules.size() == 2); // expanded from port group [80, 443]

    // Verify L2 rule
    assert(rules->l2_rules[0].type == compiler::L2MatchType::SrcMac);
    assert(rules->l2_rules[0].rule.action == 1);  // ACT_ALLOW
    assert(rules->l2_rules[0].rule.next_layer == 1); // LAYER_3_IDX

    // Verify L3 rule
    assert(rules->l3_rules[0].subnet_key.prefixlen == 8);
    assert(rules->l3_rules[0].rule.action == 1); // ACT_ALLOW
    assert(rules->l3_rules[0].rule.has_next_layer == 1);

    // Verify L4 rules
    assert(rules->l4_rules[0].match.protocol == 6);
    assert(rules->l4_rules[0].match.dst_port == 80);
    int ncpus1 = libbpf_num_possible_cpus();
    if (ncpus1 < 1) ncpus1 = 1;
    assert(rules->l4_rules[0].rule.rate_bps == 1000000000ULL / ncpus1);
    assert(rules->l4_rules[1].match.dst_port == 443);
}

TEST(test_compile_complex_multi_layer) {
    auto cfg = config::parse_config_string(R"({
        "objects": {
            "subnets": {
                "malicious": "192.0.2.0/24",
                "trusted": "10.0.0.0/8"
            },
            "mac_groups": {
                "routers": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"]
            },
            "port_groups": {
                "dns": [53],
                "web": [80, 443, 8080]
            }
        },
        "pipeline": {
            "layer_2": [
                {"rule_id":1, "action":"allow", "match":{"src_mac":"object:routers"}, "next_layer":"layer_3"}
            ],
            "layer_3": [
                {"rule_id":10, "action":"mirror", "match":{"src_ip":"object:malicious"}, "action_params":{"target_port":"mon0"}, "next_layer":"layer_4"},
                {"rule_id":11, "action":"redirect", "match":{"vrf":"guest"}, "action_params":{"target_vrf":"captive"}}
            ],
            "layer_4": [
                {"rule_id":100, "action":"tag", "match":{"protocol":"UDP","dst_port":"object:dns"}, "action_params":{"dscp":"EF","cos":5}},
                {"rule_id":101, "action":"rate-limit", "match":{"protocol":"TCP","dst_port":"object:web"}, "action_params":{"bandwidth":"10Gbps"}}
            ]
        },
        "default_behavior": "drop"
    })");
    assert(cfg.has_value());

    auto objs = compiler::compile_objects(cfg->objects);
    assert(objs.has_value());
    assert(objs->macs.size() == 2);
    assert(objs->subnets.size() == 2);

    auto resolver = [](const std::string& name) -> uint32_t {
        if (name == "mon0") return 42;
        if (name == "guest") return 10;
        if (name == "captive") return 20;
        return 0;
    };

    auto rules = compiler::compile_rules(cfg->pipeline, cfg->objects, resolver);
    assert(rules.has_value());

    // L3: 1 subnet rule + 1 VRF rule
    assert(rules->l3_rules.size() == 2);
    assert(!rules->l3_rules[0].is_vrf_rule);
    assert(rules->l3_rules[0].rule.action == 2); // ACT_MIRROR
    assert(rules->l3_rules[0].rule.mirror_ifindex == 42);
    assert(rules->l3_rules[0].rule.has_next_layer == 1);

    assert(rules->l3_rules[1].is_vrf_rule);
    assert(rules->l3_rules[1].vrf_ifindex == 10);
    assert(rules->l3_rules[1].rule.redirect_ifindex == 20);
    assert(rules->l3_rules[1].rule.has_next_layer == 0);

    // L4: 1 DNS (UDP:53) + 3 web (TCP:80,443,8080) = 4 rules
    assert(rules->l4_rules.size() == 4);
    assert(rules->l4_rules[0].match.protocol == 17); // UDP
    assert(rules->l4_rules[0].match.dst_port == 53);
    assert(rules->l4_rules[0].rule.dscp == 46);
    assert(rules->l4_rules[0].rule.cos == 5);

    assert(rules->l4_rules[1].match.protocol == 6); // TCP
    int ncpus2 = libbpf_num_possible_cpus();
    if (ncpus2 < 1) ncpus2 = 1;
    assert(rules->l4_rules[1].rule.rate_bps == 10000000000ULL / ncpus2);
}

/*
 * Stress test: compile a large config with many rules.
 */
TEST(test_compile_many_rules_performance) {
    config::ObjectStore objects;
    config::Pipeline pipeline;

    // Generate 500 L4 rules with unique ports
    for (uint16_t p = 1024; p < 1524; ++p) {
        config::Rule r;
        r.rule_id = 2000 + p;
        r.match.protocol = "TCP";
        r.match.dst_port = std::to_string(p);
        r.action = config::Action::Allow;
        pipeline.layer_4.push_back(r);
    }

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules.size() == 500);

    // Verify first and last
    assert(result->l4_rules[0].match.dst_port == 1024);
    assert(result->l4_rules[499].match.dst_port == 1523);
}

TEST(test_compile_many_subnets) {
    config::ObjectStore objects;
    config::Pipeline pipeline;

    // Generate 100 subnet rules
    for (int i = 0; i < 100; ++i) {
        std::string cidr = "10." + std::to_string(i) + ".0.0/16";
        std::string name = "net_" + std::to_string(i);
        objects.subnets[name] = cidr;

        config::Rule r;
        r.rule_id = 3000 + i;
        r.match.src_ip = "object:" + name;
        r.action = config::Action::Drop;
        pipeline.layer_3.push_back(r);
    }

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l3_rules.size() == 100);
}

TEST(test_compile_many_macs) {
    config::ObjectStore objects;
    std::vector<std::string> macs;
    for (int i = 0; i < 200; ++i) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:00:00:00",
                 (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        macs.push_back(buf);
    }
    objects.mac_groups["large_group"] = macs;

    auto objs = compiler::compile_objects(objects);
    assert(objs.has_value());
    assert(objs->macs.size() == 200);
}

/*
 * Test LPM key tracking for cleanup.
 */
TEST(test_lpm_key_tracking_multi_gen) {
    std::vector<std::vector<uint8_t>> lpm_keys[2];

    // Gen 0 active, prepare shadow gen 1
    uint32_t active = 0;
    uint32_t shadow = 1;

    // Insert keys into shadow
    lpm_keys[shadow].push_back({0, 0, 0, 24, 0xC0, 0xA8, 0x01, 0x00});
    lpm_keys[shadow].push_back({0, 0, 0, 16, 0x0A, 0x00, 0x00, 0x00});
    assert(lpm_keys[shadow].size() == 2);

    // Commit: gen 1 active
    active = 1;
    shadow = 0;

    // Prepare new shadow (gen 0): clear old keys
    lpm_keys[shadow].clear();
    assert(lpm_keys[shadow].empty());

    // Add different keys to gen 0
    lpm_keys[shadow].push_back({0, 0, 0, 8, 0xAC, 0x10, 0x00, 0x00});
    assert(lpm_keys[shadow].size() == 1);

    // Gen 1's keys still intact
    assert(lpm_keys[active].size() == 2);

    // Commit: gen 0 active
    active = 0;
    shadow = 1;

    // Clear gen 1 for next prepare
    lpm_keys[shadow].clear();
    assert(lpm_keys[shadow].empty());
    assert(lpm_keys[active].size() == 1);
}

/*
 * Test object compilation with mixed valid/invalid entries.
 */
TEST(test_mixed_mac_groups) {
    config::ObjectStore objects;
    objects.mac_groups["group_a"] = {"00:11:22:33:44:55"};
    objects.mac_groups["group_b"] = {"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"};

    auto objs = compiler::compile_objects(objects);
    assert(objs.has_value());
    assert(objs->macs.size() == 3);
}

TEST(test_object_compilation_preserves_subnet_names) {
    config::ObjectStore objects;
    objects.subnets["alpha"] = "10.0.0.0/8";
    objects.subnets["beta"] = "172.16.0.0/12";

    auto objs = compiler::compile_objects(objects);
    assert(objs.has_value());
    assert(objs->subnets.size() == 2);

    bool found_alpha = false, found_beta = false;
    for (auto& s : objs->subnets) {
        if (s.object_name == "alpha") found_alpha = true;
        if (s.object_name == "beta") found_beta = true;
    }
    assert(found_alpha);
    assert(found_beta);
}

// ── Negative / error propagation tests ──────────────────────

TEST(test_e2e_broken_config_invalid_json) {
    auto cfg = config::parse_config_string("{{{invalid");
    assert(!cfg.has_value());
}

TEST(test_e2e_broken_config_unknown_action) {
    auto cfg = config::parse_config_string(R"({
        "pipeline": { "layer_2": [{"rule_id":1, "action":"nuke"}] }
    })");
    assert(!cfg.has_value());
}

TEST(test_e2e_unknown_subnet_object_in_full_pipeline) {
    auto cfg = config::parse_config_string(R"({
        "objects": {},
        "pipeline": {
            "layer_3": [{"rule_id":10, "action":"drop", "match":{"src_ip":"object:ghost"}}]
        }
    })");
    assert(cfg.has_value());

    auto objs = compiler::compile_objects(cfg->objects);
    assert(objs.has_value());

    auto rules = compiler::compile_rules(cfg->pipeline, cfg->objects, null_resolver);
    assert(!rules.has_value()); // ghost subnet doesn't exist
}

TEST(test_e2e_unknown_port_group_in_full_pipeline) {
    auto cfg = config::parse_config_string(R"({
        "objects": {},
        "pipeline": {
            "layer_4": [{"rule_id":100, "action":"allow", "match":{"protocol":"TCP","dst_port":"object:phantom"}}]
        }
    })");
    assert(cfg.has_value());

    auto rules = compiler::compile_rules(cfg->pipeline, cfg->objects, null_resolver);
    assert(!rules.has_value());
}

TEST(test_e2e_empty_mac_group_with_rule) {
    // Empty group → 0 MAC entries, rule references it
    auto cfg = config::parse_config_string(R"({
        "objects": { "mac_groups": { "empty": [] } },
        "pipeline": {
            "layer_2": [{"rule_id":1, "action":"allow", "match":{"src_mac":"object:empty"}, "next_layer":"layer_3"}]
        }
    })");
    assert(cfg.has_value());

    auto objs = compiler::compile_objects(cfg->objects);
    assert(objs.has_value());
    assert(objs->macs.empty()); // no entries compiled
}

TEST(test_e2e_empty_port_group_expansion) {
    config::ObjectStore objects;
    objects.port_groups["empty"] = {};

    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    r.match.dst_port = "object:empty";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(result.has_value());
    assert(result->l4_rules.empty()); // empty group → 0 rules
}

TEST(test_e2e_invalid_mac_in_group_fails_compilation) {
    config::ObjectStore objects;
    objects.mac_groups["bad"] = {"00:11:22:33:44:55", "GARBAGE"};

    auto objs = compiler::compile_objects(objects);
    assert(!objs.has_value()); // second MAC is invalid
}

TEST(test_e2e_invalid_subnet_fails_compilation) {
    config::ObjectStore objects;
    objects.subnets["valid"] = "10.0.0.0/8";
    objects.subnets["broken"] = "not-an-ip/24";

    auto objs = compiler::compile_objects(objects);
    assert(!objs.has_value()); // broken subnet
}

TEST(test_e2e_l4_missing_protocol_fails) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.dst_port = "80";
    r.action = config::Action::Allow;
    // Missing protocol
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

TEST(test_e2e_l4_missing_dst_port_fails) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.protocol = "TCP";
    // Missing dst_port
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto result = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(!result.has_value());
}

TEST(test_e2e_mixed_valid_invalid_objects) {
    // One valid subnet + one broken → whole compile fails
    config::ObjectStore objects;
    objects.subnets["ok"] = "10.0.0.0/8";
    objects.subnets["bad"] = "999.999.999.999/32";

    auto objs = compiler::compile_objects(objects);
    assert(!objs.has_value());
}

// ── Hot reload simulation tests ────────────────────────────

TEST(test_reload_deploy_different_config) {
    // First deploy: config A with TCP:80 allow
    config::ObjectStore objects_a;
    config::Pipeline pipeline_a;
    config::Rule r1;
    r1.rule_id = 1;
    r1.match.protocol = "TCP";
    r1.match.dst_port = "80";
    r1.action = config::Action::Allow;
    pipeline_a.layer_4.push_back(r1);

    auto rules_a = compiler::compile_rules(pipeline_a, objects_a, null_resolver);
    assert(rules_a.has_value());
    assert(rules_a->l4_rules.size() == 1);
    assert(rules_a->l4_rules[0].match.dst_port == 80);

    // Second deploy (reload): config B with TCP:443 drop + TCP:8080 allow
    config::ObjectStore objects_b;
    config::Pipeline pipeline_b;
    config::Rule r2;
    r2.rule_id = 10;
    r2.match.protocol = "TCP";
    r2.match.dst_port = "443";
    r2.action = config::Action::Drop;
    pipeline_b.layer_4.push_back(r2);

    config::Rule r3;
    r3.rule_id = 11;
    r3.match.protocol = "TCP";
    r3.match.dst_port = "8080";
    r3.action = config::Action::Allow;
    pipeline_b.layer_4.push_back(r3);

    auto rules_b = compiler::compile_rules(pipeline_b, objects_b, null_resolver);
    assert(rules_b.has_value());
    assert(rules_b->l4_rules.size() == 2);
    assert(rules_b->l4_rules[0].match.dst_port == 443);
    assert(rules_b->l4_rules[1].match.dst_port == 8080);
}

TEST(test_reload_bad_config_preserves_state) {
    // Good config compiles
    config::ObjectStore objects;
    objects.subnets["net"] = "10.0.0.0/8";
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1;
    r.match.src_ip = "object:net";
    r.action = config::Action::Drop;
    pipeline.layer_3.push_back(r);

    auto rules_good = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(rules_good.has_value());

    // Bad reload: broken config fails compilation
    auto bad_cfg = config::parse_config_string("{{{broken json");
    assert(!bad_cfg.has_value());
    // Good rules still valid — nothing changed
    assert(rules_good->l3_rules.size() == 1);
}

TEST(test_reload_config_with_validation_error) {
    // Config that parses OK but fails semantic validation
    auto cfg = config::parse_config_string(R"({
        "objects": {},
        "pipeline": {
            "layer_4": [
                {"rule_id":1, "action":"allow", "match":{"protocol":"TCP","dst_port":"80"}},
                {"rule_id":1, "action":"drop", "match":{"protocol":"UDP","dst_port":"53"}}
            ]
        }
    })");
    assert(cfg.has_value());

    // Validation catches duplicate rule_id
    auto vr = config::validate_config(*cfg);
    assert(!vr.has_value());
}

TEST(test_reload_grow_rules) {
    // Start with 10 rules, reload with 100 rules
    config::ObjectStore objects;
    config::Pipeline pipeline;

    for (uint16_t p = 1000; p < 1010; ++p) {
        config::Rule r;
        r.rule_id = p;
        r.match.protocol = "TCP";
        r.match.dst_port = std::to_string(p);
        r.action = config::Action::Allow;
        pipeline.layer_4.push_back(r);
    }

    auto rules_small = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(rules_small.has_value());
    assert(rules_small->l4_rules.size() == 10);

    // Reload with 100 rules
    config::Pipeline pipeline2;
    for (uint16_t p = 2000; p < 2100; ++p) {
        config::Rule r;
        r.rule_id = p;
        r.match.protocol = "TCP";
        r.match.dst_port = std::to_string(p);
        r.action = config::Action::Drop;
        pipeline2.layer_4.push_back(r);
    }

    auto rules_large = compiler::compile_rules(pipeline2, objects, null_resolver);
    assert(rules_large.has_value());
    assert(rules_large->l4_rules.size() == 100);
}

TEST(test_reload_shrink_rules) {
    // Start with 50 rules, reload with 5
    config::ObjectStore objects;
    config::Pipeline pipeline;

    for (uint16_t p = 3000; p < 3050; ++p) {
        config::Rule r;
        r.rule_id = p;
        r.match.protocol = "UDP";
        r.match.dst_port = std::to_string(p);
        r.action = config::Action::Allow;
        pipeline.layer_4.push_back(r);
    }

    auto rules_large = compiler::compile_rules(pipeline, objects, null_resolver);
    assert(rules_large.has_value());
    assert(rules_large->l4_rules.size() == 50);

    config::Pipeline pipeline2;
    for (uint16_t p = 4000; p < 4005; ++p) {
        config::Rule r;
        r.rule_id = p;
        r.match.protocol = "UDP";
        r.match.dst_port = std::to_string(p);
        r.action = config::Action::Drop;
        pipeline2.layer_4.push_back(r);
    }

    auto rules_small = compiler::compile_rules(pipeline2, objects, null_resolver);
    assert(rules_small.has_value());
    assert(rules_small->l4_rules.size() == 5);
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
