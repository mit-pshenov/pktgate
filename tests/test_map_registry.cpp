#include "loader/map_registry.hpp"
#include <cassert>
#include <cstdio>

using pktgate::loader::MapRegistry;

static int passed = 0;

#define TEST(name) static void test_##name()
#define RUN(name) do { \
    std::printf("  %-40s", #name); \
    test_##name(); \
    std::printf(" OK\n"); \
    ++passed; \
} while(0)

TEST(generational_lookup) {
    MapRegistry r;
    r.register_map("mac_allow", 0, 10);
    r.register_map("mac_allow", 1, 11);
    assert(r.mac_allow_fd(0) == 10);
    assert(r.mac_allow_fd(1) == 11);
}

TEST(shared_lookup) {
    MapRegistry r;
    r.register_map("stats_map", MapRegistry::SHARED, 42);
    assert(r.stats_map_fd() == 42);
    assert(r.map_fd("stats_map") == 42);
}

TEST(unknown_returns_minus1) {
    MapRegistry r;
    assert(r.map_fd("nonexistent", 0) == -1);
    assert(r.map_fd("nonexistent") == -1);
    assert(r.prog_fd("nonexistent") == -1);
}

TEST(prog_fd_lookup) {
    MapRegistry r;
    r.register_prog("layer2", 100);
    r.register_prog("layer3", 101);
    assert(r.layer2_prog_fd() == 100);
    assert(r.layer3_prog_fd() == 101);
    assert(r.entry_prog_fd() == -1); // not registered
}

TEST(overwrite) {
    MapRegistry r;
    r.register_map("gen_config", MapRegistry::SHARED, 5);
    assert(r.gen_config_fd() == 5);
    r.register_map("gen_config", MapRegistry::SHARED, 99);
    assert(r.gen_config_fd() == 99);
}

TEST(all_convenience_accessors) {
    MapRegistry r;
    // Gen-aware
    r.register_map("mac_allow", 0, 1);
    r.register_map("subnet_rules", 0, 2);
    r.register_map("subnet6_rules", 1, 3);
    r.register_map("vrf_rules", 0, 4);
    r.register_map("l4_rules", 1, 5);
    r.register_map("prog_array", 0, 6);
    r.register_map("default_action", 1, 7);
    // Shared
    r.register_map("gen_config", MapRegistry::SHARED, 8);
    r.register_map("rate_state", MapRegistry::SHARED, 9);
    r.register_map("stats_map", MapRegistry::SHARED, 10);
    r.register_map("xsks_map", MapRegistry::SHARED, 11);

    assert(r.mac_allow_fd(0) == 1);
    assert(r.subnet_rules_fd(0) == 2);
    assert(r.subnet6_rules_fd(1) == 3);
    assert(r.vrf_rules_fd(0) == 4);
    assert(r.l4_rules_fd(1) == 5);
    assert(r.prog_array_fd(0) == 6);
    assert(r.default_action_fd(1) == 7);
    assert(r.gen_config_fd() == 8);
    assert(r.rate_state_fd() == 9);
    assert(r.stats_map_fd() == 10);
    assert(r.xsks_map_fd() == 11);
}

int main() {
    std::printf("test_map_registry:\n");
    RUN(generational_lookup);
    RUN(shared_lookup);
    RUN(unknown_returns_minus1);
    RUN(prog_fd_lookup);
    RUN(overwrite);
    RUN(all_convenience_accessors);
    std::printf("All %d tests passed.\n", passed);
    return 0;
}
