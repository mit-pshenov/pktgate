#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "config/config_parser.hpp"
#include <bpf/libbpf.h>
#include <cassert>
#include <iostream>
#include <cstring>
#include <arpa/inet.h>

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

TEST(test_compile_macs) {
    config::ObjectStore objects;
    objects.mac_groups["routers"] = {"00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"};

    auto result = compiler::compile_objects(objects);
    assert(result.has_value());
    assert(result->macs.size() == 2);

    // Check first MAC
    assert(result->macs[0].key.addr[0] == 0x00);
    assert(result->macs[0].key.addr[1] == 0x11);
    assert(result->macs[0].key.addr[5] == 0x55);
    assert(result->macs[0].value == 1);

    // Check second MAC
    assert(result->macs[1].key.addr[0] == 0xAA);
    assert(result->macs[1].key.addr[5] == 0xFF);
}

TEST(test_compile_subnets) {
    config::ObjectStore objects;
    objects.subnets["test_net"] = "192.168.1.0/24";

    auto result = compiler::compile_objects(objects);
    assert(result.has_value());
    assert(result->subnets.size() == 1);
    assert(result->subnets[0].key.prefixlen == 24);
    assert(result->subnets[0].object_name == "test_net");

    // Verify network byte order: 192.168.1.0
    uint32_t expected_nbo;
    inet_pton(AF_INET, "192.168.1.0", &expected_nbo);
    assert(result->subnets[0].key.addr == expected_nbo);
}

TEST(test_compile_ports) {
    config::ObjectStore objects;
    objects.port_groups["web"] = {80, 443, 8080};

    auto result = compiler::compile_objects(objects);
    assert(result.has_value());
    assert(result->port_groups.size() == 1);
    assert(result->port_groups[0].group_name == "web");
    assert(result->port_groups[0].ports.size() == 3);
    assert(result->port_groups[0].ports[0] == 80);
}

TEST(test_compile_invalid_mac) {
    config::ObjectStore objects;
    objects.mac_groups["bad"] = {"ZZZZZZZZZZZZZZZZ"};

    auto result = compiler::compile_objects(objects);
    assert(!result.has_value());
}

TEST(test_compile_invalid_subnet) {
    config::ObjectStore objects;
    objects.subnets["bad"] = "not_an_ip/24";

    auto result = compiler::compile_objects(objects);
    assert(!result.has_value());
}

// --- Rule compiler tests ---

TEST(test_compile_l3_rules) {
    config::ObjectStore objects;
    objects.subnets["malicious_net"] = "192.0.2.0/24";

    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 100;
    r.match.src_ip = "object:malicious_net";
    r.action = config::Action::Mirror;
    r.params.target_port = "eth1";
    r.next_layer = "layer_4";
    pipeline.layer_3.push_back(r);

    // Mock resolver
    auto resolver = [](const std::string& name) -> uint32_t {
        if (name == "eth1") return 42;
        return 0;
    };

    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    assert(result->l3_rules.size() == 1);
    assert(result->l3_rules[0].rule.rule_id == 100);
    assert(result->l3_rules[0].rule.action == 2); // ACT_MIRROR
    assert(result->l3_rules[0].rule.mirror_ifindex == 42);
    assert(result->l3_rules[0].rule.has_next_layer == 1);
    assert(result->l3_rules[0].subnet_key.prefixlen == 24);
}

TEST(test_compile_l3_vrf_rule) {
    config::ObjectStore objects;
    config::Pipeline pipeline;

    config::Rule r;
    r.rule_id = 110;
    r.match.vrf = "unpaid_customers";
    r.action = config::Action::Redirect;
    r.params.target_vrf = "captive_portal_vrf";
    pipeline.layer_3.push_back(r);

    auto resolver = [](const std::string& name) -> uint32_t {
        if (name == "unpaid_customers") return 10;
        if (name == "captive_portal_vrf") return 20;
        return 0;
    };

    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    assert(result->l3_rules.size() == 1);
    assert(result->l3_rules[0].is_vrf_rule);
    assert(result->l3_rules[0].vrf_ifindex == 10);
    assert(result->l3_rules[0].rule.redirect_ifindex == 20);
}

TEST(test_compile_l4_rules_expanded) {
    config::ObjectStore objects;
    objects.port_groups["web"] = {80, 443, 8080};

    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1010;
    r.match.protocol = "TCP";
    r.match.dst_port = "object:web";
    r.action = config::Action::RateLimit;
    r.params.bandwidth = "10Gbps";
    pipeline.layer_4.push_back(r);

    auto resolver = [](const std::string&) -> uint32_t { return 0; };

    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    // Should expand to 3 rules (one per port)
    assert(result->l4_rules.size() == 3);

    assert(result->l4_rules[0].match.protocol == 6);  // TCP
    assert(result->l4_rules[0].match.dst_port == 80);
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1) ncpus = 1;
    assert(result->l4_rules[0].rule.rate_bps == 10000000000ULL / ncpus);

    assert(result->l4_rules[1].match.dst_port == 443);
    assert(result->l4_rules[2].match.dst_port == 8080);
}

TEST(test_compile_l4_tag) {
    config::ObjectStore objects;
    objects.port_groups["dns"] = {53};

    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 1000;
    r.match.protocol = "UDP";
    r.match.dst_port = "object:dns";
    r.action = config::Action::Tag;
    r.params.dscp = "EF";
    r.params.cos = 5;
    pipeline.layer_4.push_back(r);

    auto resolver = [](const std::string&) -> uint32_t { return 0; };

    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(result.has_value());
    assert(result->l4_rules.size() == 1);
    assert(result->l4_rules[0].match.protocol == 17); // UDP
    assert(result->l4_rules[0].match.dst_port == 53);
    assert(result->l4_rules[0].rule.dscp == 46);       // EF
    assert(result->l4_rules[0].rule.cos == 5);
}

TEST(test_compile_mac_invalid_separator) {
    config::ObjectStore objects;
    objects.mac_groups["bad"] = {"00X11X22X33X44X55"};
    auto result = compiler::compile_objects(objects);
    assert(!result.has_value());
}

TEST(test_compile_mac_dash_separator) {
    config::ObjectStore objects;
    objects.mac_groups["ok"] = {"00-11-22-33-44-55"};
    auto result = compiler::compile_objects(objects);
    assert(result.has_value());
    assert(result->macs.size() == 1);
    assert(result->macs[0].key.addr[0] == 0x00);
}

TEST(test_compile_l4_port_out_of_range) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 99;
    r.match.protocol = "TCP";
    r.match.dst_port = "70000";
    r.action = config::Action::Allow;
    pipeline.layer_4.push_back(r);

    auto resolver = [](const std::string&) -> uint32_t { return 0; };
    auto result = compiler::compile_rules(pipeline, objects, resolver);
    assert(!result.has_value());
}

TEST(test_struct_layout_l4_rule) {
    // Verify l4_rule layout matches between C and C++
    static_assert(sizeof(struct l4_rule) == 24, "l4_rule should be 24 bytes");
    static_assert(offsetof(struct l4_rule, rate_bps) == 16, "rate_bps at offset 16");
}

TEST(test_compile_l4_missing_protocol) {
    config::ObjectStore objects;
    config::Pipeline pipeline;
    config::Rule r;
    r.rule_id = 99;
    r.match.dst_port = "80";
    r.action = config::Action::Allow;
    // No protocol set
    pipeline.layer_4.push_back(r);

    auto resolver = [](const std::string&) -> uint32_t { return 0; };
    auto result = compiler::compile_rules(pipeline, objects, resolver);
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
