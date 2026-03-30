/*
 * Stress tests for the compiler: large rule counts, many subnets, big port groups.
 * Verifies no crash, no excessive allocation, reasonable performance.
 */
#include "config/config_parser.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "../../bpf/common.h"

#include <cassert>
#include <chrono>
#include <iostream>
#include <sstream>

using namespace pktgate;

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry { const char* name; void (*fn)(); };
static std::vector<TestEntry> tests;

static auto null_resolver = [](const std::string&) -> uint32_t { return 1; };

// Helper to generate N L3 rules with distinct /32 subnets
static config::Pipeline make_l3_pipeline(size_t n) {
    config::Pipeline pl;
    pl.layer_3.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        config::Rule r;
        r.rule_id = static_cast<uint32_t>(i);
        r.action = config::Action::Drop;
        // Generate unique /32: 10.x.y.z
        uint32_t addr = 0x0A000000u + static_cast<uint32_t>(i);
        std::ostringstream cidr;
        cidr << ((addr >> 24) & 0xFF) << "."
             << ((addr >> 16) & 0xFF) << "."
             << ((addr >> 8) & 0xFF) << "."
             << (addr & 0xFF) << "/32";
        r.match.src_ip = cidr.str();
        pl.layer_3.push_back(std::move(r));
    }
    return pl;
}

// Helper to generate N L4 rules with distinct ports
static config::Pipeline make_l4_pipeline(size_t n) {
    config::Pipeline pl;
    pl.layer_4.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        config::Rule r;
        r.rule_id = static_cast<uint32_t>(i);
        r.action = config::Action::Allow;
        r.match.protocol = "TCP";
        r.match.dst_port = std::to_string(i % 65536);
        pl.layer_4.push_back(std::move(r));
    }
    return pl;
}

// ═══════════════════════════════════════════════════════════
// L3 rule scaling
// ═══════════════════════════════════════════════════════════

TEST(stress_l3_100_rules) {
    auto pl = make_l3_pipeline(100);
    config::ObjectStore objs;
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l3_rules.size() == 100);
}

TEST(stress_l3_4096_rules) {
    auto pl = make_l3_pipeline(4096);
    config::ObjectStore objs;

    auto t0 = std::chrono::steady_clock::now();
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    auto t1 = std::chrono::steady_clock::now();

    assert(cr.has_value());
    assert(cr->l3_rules.size() == 4096);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "    [perf] 4096 L3 rules compiled in " << ms << " ms\n";
    assert(ms < 5000); // should be well under 5 seconds
}

TEST(stress_l3_16384_rules) {
    auto pl = make_l3_pipeline(16384);
    config::ObjectStore objs;

    auto t0 = std::chrono::steady_clock::now();
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    auto t1 = std::chrono::steady_clock::now();

    assert(cr.has_value());
    assert(cr->l3_rules.size() == 16384);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "    [perf] 16384 L3 rules compiled in " << ms << " ms\n";
    assert(ms < 10000);
}

// ═══════════════════════════════════════════════════════════
// L4 rule scaling
// ═══════════════════════════════════════════════════════════

TEST(stress_l4_4096_rules) {
    auto pl = make_l4_pipeline(4096);
    config::ObjectStore objs;

    auto t0 = std::chrono::steady_clock::now();
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    auto t1 = std::chrono::steady_clock::now();

    assert(cr.has_value());
    assert(cr->l4_rules.size() == 4096);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "    [perf] 4096 L4 rules compiled in " << ms << " ms\n";
    assert(ms < 5000);
}

// ═══════════════════════════════════════════════════════════
// Port group expansion stress
// ═══════════════════════════════════════════════════════════

TEST(stress_port_group_1000_ports) {
    config::ObjectStore objs;
    std::vector<uint16_t> ports;
    ports.reserve(1000);
    for (uint16_t i = 0; i < 1000; ++i)
        ports.push_back(i + 1);
    objs.port_groups["big"] = ports;

    config::Pipeline pl;
    config::Rule r;
    r.rule_id = 1;
    r.action = config::Action::Allow;
    r.match.protocol = "TCP";
    r.match.dst_port = "object:big";
    pl.layer_4.push_back(r);

    auto t0 = std::chrono::steady_clock::now();
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    auto t1 = std::chrono::steady_clock::now();

    assert(cr.has_value());
    assert(cr->l4_rules.size() == 1000);

    // Verify ports are in correct order
    for (uint16_t i = 0; i < 1000; ++i)
        assert(cr->l4_rules[i].match.dst_port == i + 1);

    auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    std::cout << "    [perf] 1000-port expansion in " << us << " us\n";
}

TEST(stress_multiple_large_port_groups) {
    config::ObjectStore objs;
    // 4 port groups, 500 ports each = 2000 total L4 rules
    for (int g = 0; g < 4; ++g) {
        std::vector<uint16_t> ports;
        for (uint16_t p = 0; p < 500; ++p)
            ports.push_back(static_cast<uint16_t>(g * 500 + p + 1));
        objs.port_groups["group" + std::to_string(g)] = ports;
    }

    config::Pipeline pl;
    for (int g = 0; g < 4; ++g) {
        config::Rule r;
        r.rule_id = static_cast<uint32_t>(g);
        r.action = config::Action::Allow;
        r.match.protocol = "TCP";
        r.match.dst_port = "object:group" + std::to_string(g);
        pl.layer_4.push_back(r);
    }

    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    assert(cr.has_value());
    assert(cr->l4_rules.size() == 2000);
}

// ═══════════════════════════════════════════════════════════
// Object compiler scaling
// ═══════════════════════════════════════════════════════════

TEST(stress_compile_4096_macs) {
    config::ObjectStore objs;
    std::vector<std::string> macs;
    macs.reserve(4096);
    for (int i = 0; i < 4096; ++i) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF,
                 0xAA, 0xBB, 0xCC);
        macs.push_back(buf);
    }
    objs.mac_groups["all"] = macs;

    auto t0 = std::chrono::steady_clock::now();
    auto co = compiler::compile_objects(objs);
    auto t1 = std::chrono::steady_clock::now();

    assert(co.has_value());
    assert(co->macs.size() == 4096);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "    [perf] 4096 MACs compiled in " << ms << " ms\n";
    assert(ms < 2000);
}

TEST(stress_compile_16384_subnets) {
    config::ObjectStore objs;
    for (int i = 0; i < 16384; ++i) {
        uint32_t addr = 0x0A000000u + static_cast<uint32_t>(i);
        std::ostringstream cidr;
        cidr << ((addr >> 24) & 0xFF) << "."
             << ((addr >> 16) & 0xFF) << "."
             << ((addr >> 8) & 0xFF) << "."
             << (addr & 0xFF) << "/32";
        objs.subnets["net" + std::to_string(i)] = cidr.str();
    }

    auto t0 = std::chrono::steady_clock::now();
    auto co = compiler::compile_objects(objs);
    auto t1 = std::chrono::steady_clock::now();

    assert(co.has_value());
    assert(co->subnets.size() == 16384);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "    [perf] 16384 subnets compiled in " << ms << " ms\n";
    assert(ms < 5000);
}

// ═══════════════════════════════════════════════════════════
// Mixed large config
// ═══════════════════════════════════════════════════════════

TEST(stress_mixed_large_config) {
    config::ObjectStore objs;

    // 100 MACs
    std::vector<std::string> macs;
    for (int i = 0; i < 100; ++i) {
        char buf[18];
        snprintf(buf, sizeof(buf), "AA:BB:CC:%02X:%02X:%02X",
                 (i >> 8) & 0xFF, i & 0xFF, 0x00);
        macs.push_back(buf);
    }
    objs.mac_groups["many"] = macs;

    // 500 subnets
    for (int i = 0; i < 500; ++i) {
        uint32_t addr = 0x0A000000u + static_cast<uint32_t>(i * 256);
        std::ostringstream cidr;
        cidr << ((addr >> 24) & 0xFF) << "."
             << ((addr >> 16) & 0xFF) << "."
             << ((addr >> 8) & 0xFF) << "."
             << "0/24";
        objs.subnets["s" + std::to_string(i)] = cidr.str();
    }

    // Port group with 200 ports
    std::vector<uint16_t> ports;
    for (uint16_t p = 8000; p < 8200; ++p)
        ports.push_back(p);
    objs.port_groups["services"] = ports;

    // Pipeline: 500 L3 + 1 L4 (expanding to 200)
    config::Pipeline pl;
    for (int i = 0; i < 500; ++i) {
        config::Rule r;
        r.rule_id = static_cast<uint32_t>(i);
        r.action = (i % 2 == 0) ? config::Action::Drop : config::Action::Allow;
        r.match.src_ip = "object:s" + std::to_string(i);
        if (i % 2 == 1) r.next_layer = "layer_4";
        pl.layer_3.push_back(std::move(r));
    }

    config::Rule l4r;
    l4r.rule_id = 9000;
    l4r.action = config::Action::Allow;
    l4r.match.protocol = "TCP";
    l4r.match.dst_port = "object:services";
    pl.layer_4.push_back(l4r);

    auto t0 = std::chrono::steady_clock::now();
    auto co = compiler::compile_objects(objs);
    auto cr = compiler::compile_rules(pl, objs, null_resolver);
    auto t1 = std::chrono::steady_clock::now();

    assert(co.has_value());
    assert(cr.has_value());
    assert(co->macs.size() == 100);
    assert(cr->l3_rules.size() == 500);
    assert(cr->l4_rules.size() == 200);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    std::cout << "    [perf] mixed config (100 MAC + 500 L3 + 200 L4) compiled in " << ms << " ms\n";
    assert(ms < 3000);
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
