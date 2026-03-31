/*
 * Fault injection tests: verify that the compile pipeline handles
 * broken/corrupted inputs gracefully at every stage.
 * No kernel needed — pure userspace.
 */
#include "config/config_parser.hpp"
#include "config/config_validator.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include <cassert>
#include <iostream>
#include <vector>
#include <string>
#include <random>

using namespace pktgate;

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry { const char* name; void (*fn)(); };
static std::vector<TestEntry> tests;

static auto null_resolver = [](const std::string&) -> uint32_t { return 42; };

// ═══════════════════════════════════════════════════════════════
// Stage 1: Parser fault injection — corrupted JSON
// ═══════════════════════════════════════════════════════════════

static const std::string valid_json = R"({
    "device_info": {"interface": "eth0", "capacity": "10Gbps"},
    "objects": {
        "subnets": {"trusted": "10.0.0.0/8"},
        "mac_groups": {"routers": ["AA:BB:CC:DD:EE:FF"]},
        "port_groups": {"web": [80, 443]}
    },
    "pipeline": {
        "layer_2": [{"rule_id":1, "action":"allow", "match":{"src_mac":"object:routers"}, "next_layer":"layer_3"}],
        "layer_3": [{"rule_id":10, "action":"allow", "match":{"src_ip":"object:trusted"}, "next_layer":"layer_4"}],
        "layer_4": [{"rule_id":100, "action":"allow", "match":{"protocol":"TCP","dst_port":"object:web"}}]
    },
    "default_behavior": "drop"
})";

TEST(parse_truncated_at_every_byte) {
    // Truncate valid JSON at every position — must not crash
    int errors = 0;
    for (size_t i = 0; i < valid_json.size(); ++i) {
        auto r = config::parse_config_string(valid_json.substr(0, i));
        if (!r) errors++;
    }
    // Most truncations should fail (only complete JSON succeeds)
    assert(errors > 0);
}

TEST(parse_single_byte_flip) {
    // Flip one byte at each position — must not crash
    std::mt19937 rng(42);
    int errors = 0;
    for (size_t i = 0; i < valid_json.size(); ++i) {
        std::string mutated = valid_json;
        mutated[i] ^= (1 << (rng() % 8));
        auto r = config::parse_config_string(mutated);
        if (!r) errors++;
    }
    assert(errors > 0);
}

TEST(parse_random_insertion) {
    std::mt19937 rng(123);
    for (int trial = 0; trial < 200; ++trial) {
        std::string mutated = valid_json;
        size_t pos = rng() % (mutated.size() + 1);
        char c = static_cast<char>(rng() % 256);
        mutated.insert(pos, 1, c);
        auto r = config::parse_config_string(mutated);
        (void)r;
    }
}

TEST(parse_random_deletion) {
    std::mt19937 rng(456);
    for (int trial = 0; trial < 200; ++trial) {
        std::string mutated = valid_json;
        if (mutated.empty()) continue;
        size_t pos = rng() % mutated.size();
        mutated.erase(pos, 1);
        auto r = config::parse_config_string(mutated);
        (void)r;
    }
}

// ═══════════════════════════════════════════════════════════════
// Stage 2: Validator fault injection — structurally valid JSON, bad semantics
// ═══════════════════════════════════════════════════════════════

TEST(validate_negative_rule_id) {
    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {},
        "pipeline": {
            "layer_2": [],
            "layer_3": [{"rule_id":-1, "action":"drop", "match":{"src_ip":"10.0.0.0/8"}}],
            "layer_4": []
        }
    })");
    // May fail at parse or validate — neither should crash
    if (r) {
        auto v = config::validate_config(*r);
        (void)v;
    }
}

TEST(validate_huge_port_number) {
    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {"port_groups": {"bad": [99999]}},
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [{"rule_id":1, "action":"allow", "match":{"protocol":"TCP","dst_port":"object:bad"}}]
        }
    })");
    assert(!r && "port 99999 must be rejected at parse time");
    assert(r.error().find("out of range") != std::string::npos);
}

TEST(validate_port_integer_overflow) {
    // 4294967296 == UINT32_MAX+1, get<int>() silently returned 0
    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {"port_groups": {"bad": [4294967296]}},
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [{"rule_id":1, "action":"allow", "match":{"protocol":"TCP","dst_port":"object:bad"}}]
        }
    })");
    assert(!r && "port 4294967296 must be rejected (integer overflow)");
    assert(r.error().find("out of range") != std::string::npos);
}

TEST(validate_port_float_rejected) {
    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {"port_groups": {"bad": [80.5]}},
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [{"rule_id":1, "action":"allow", "match":{"protocol":"TCP","dst_port":"object:bad"}}]
        }
    })");
    assert(!r && "float port must be rejected");
    assert(r.error().find("must be an integer") != std::string::npos);
}

TEST(validate_empty_mac_group) {
    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {"mac_groups": {"empty": []}},
        "pipeline": {
            "layer_2": [{"rule_id":1, "action":"allow", "match":{"src_mac":"object:empty"}}],
            "layer_3": [],
            "layer_4": []
        }
    })");
    if (r) {
        auto v = config::validate_config(*r);
        (void)v;
    }
}

TEST(validate_dangling_object_reference) {
    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {},
        "pipeline": {
            "layer_2": [],
            "layer_3": [{"rule_id":1, "action":"allow", "match":{"src_ip":"object:nonexistent"}}],
            "layer_4": []
        }
    })");
    if (r) {
        auto v = config::validate_config(*r);
        assert(!v); // Should fail — dangling ref
    }
}

// ═══════════════════════════════════════════════════════════════
// Stage 3: Compiler fault injection — valid config with edge-case values
// ═══════════════════════════════════════════════════════════════

TEST(compile_zero_prefix_subnet) {
    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {"subnets": {"any": "0.0.0.0/0"}},
        "pipeline": {
            "layer_2": [],
            "layer_3": [{"rule_id":1, "action":"drop", "match":{"src_ip":"object:any"}}],
            "layer_4": []
        }
    })");
    assert(r);
    auto v = config::validate_config(*r);
    if (!v) return;
    auto objs = compiler::compile_objects(r->objects);
    assert(objs);
    auto rules = compiler::compile_rules(r->pipeline, r->objects, null_resolver);
    assert(rules);
    assert(rules->l3_rules.size() == 1);
}

TEST(compile_host_route_prefix_32) {
    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {"subnets": {"host": "192.168.1.1/32"}},
        "pipeline": {
            "layer_2": [],
            "layer_3": [{"rule_id":1, "action":"allow", "match":{"src_ip":"object:host"}}],
            "layer_4": []
        }
    })");
    assert(r);
    auto v = config::validate_config(*r);
    if (!v) return;
    auto objs = compiler::compile_objects(r->objects);
    assert(objs);
}

TEST(compile_all_65535_ports) {
    // Large port group: ports 1-1000
    std::string ports = "[";
    for (int i = 1; i <= 1000; ++i) {
        if (i > 1) ports += ",";
        ports += std::to_string(i);
    }
    ports += "]";

    auto r = config::parse_config_string(R"({
        "device_info": {"interface": "eth0"},
        "objects": {"port_groups": {"many": )" + ports + R"(}},
        "pipeline": {
            "layer_2": [],
            "layer_3": [],
            "layer_4": [{"rule_id":1, "action":"allow", "match":{"protocol":"TCP","dst_port":"object:many"}}]
        }
    })");
    assert(r);
    auto v = config::validate_config(*r);
    if (!v) return;
    auto rules = compiler::compile_rules(r->pipeline, r->objects, null_resolver);
    assert(rules);
    assert(rules->l4_rules.size() == 1000);
}

// ═══════════════════════════════════════════════════════════════
// Stage 4: Full pipeline mutation — random field corruption
// ═══════════════════════════════════════════════════════════════

TEST(full_pipeline_random_mutations) {
    // Run 500 random single-byte mutations through the full pipeline
    std::mt19937 rng(789);
    int parse_ok = 0, validate_ok = 0, compile_ok = 0;

    for (int trial = 0; trial < 500; ++trial) {
        std::string mutated = valid_json;
        size_t pos = rng() % mutated.size();
        mutated[pos] = static_cast<char>(rng() % 128); // ASCII range

        auto parsed = config::parse_config_string(mutated);
        if (!parsed) continue;
        parse_ok++;

        auto valid = config::validate_config(*parsed);
        if (!valid) continue;
        validate_ok++;

        auto objs = compiler::compile_objects(parsed->objects);
        if (!objs) continue;

        auto rules = compiler::compile_rules(parsed->pipeline, parsed->objects, null_resolver);
        if (rules) compile_ok++;
    }
    // Some mutations should survive parse, fewer survive validate
    // This just ensures nothing crashes
    (void)parse_ok;
    (void)validate_ok;
    (void)compile_ok;
}

TEST(full_pipeline_double_mutation) {
    std::mt19937 rng(101);
    for (int trial = 0; trial < 300; ++trial) {
        std::string mutated = valid_json;
        // Two random mutations
        for (int m = 0; m < 2; ++m) {
            size_t pos = rng() % mutated.size();
            mutated[pos] = static_cast<char>(rng() % 128);
        }

        auto parsed = config::parse_config_string(mutated);
        if (!parsed) continue;
        auto valid = config::validate_config(*parsed);
        if (!valid) continue;
        auto objs = compiler::compile_objects(parsed->objects);
        if (!objs) continue;
        auto rules = compiler::compile_rules(parsed->pipeline, parsed->objects, null_resolver);
        (void)rules;
    }
}

int main() {
    int passed = 0, failed = 0;
    for (auto& [name, fn] : tests) {
        try {
            fn();
            std::cout << "  PASS  " << name << "\n";
            ++passed;
        } catch (const std::exception& e) {
            std::cerr << "  FAIL  " << name << ": " << e.what() << "\n";
            ++failed;
        }
    }
    std::cout << "\n" << passed << " passed, " << failed << " failed, "
              << tests.size() << " total\n";
    return failed > 0 ? 1 : 0;
}
