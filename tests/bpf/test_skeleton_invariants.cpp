/*
 * Cross-skeleton map identity invariant.
 *
 * Background: pktgate compiles five BPF objects (entry + layer2/3/4 +
 * tc_ingress), each declaring the SAME maps in `bpf/maps.h`. By default
 * libbpf would create separate kernel-level map objects with identical
 * names — populate would write to one, the data-plane lookup would read
 * from another, and the silent divergence makes the filter look alive
 * while every rule misses. `BpfLoader::reuse_xdp_maps()` defuses this
 * by reusing entry's fd into every layer skeleton before load.
 *
 * Risk: any new map added to maps.h that is missed in the REUSE_MAP
 * list reintroduces the divergence — that's exactly how dst_ip support
 * broke functional tests during development (commit 5642d3e). This test
 * is the runtime guardrail: after `BpfLoader::load()`, every shared map
 * MUST have an identical FD across entry and the three layer skeletons.
 * Adding a new map to maps.h without wiring REUSE_MAP fails this test.
 */
#include "loader/bpf_loader.hpp"
#include <bpf/bpf.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace pktgate::loader;

#define TEST(name) \
    static void name(); \
    struct name##_reg { name##_reg() { tests.push_back({#name, name}); } } name##_inst; \
    static void name()

struct TestEntry { const char* name; void (*fn)(); };
static std::vector<TestEntry> tests;

// Maps in maps.h that MUST be reused across all three XDP layer
// skeletons (entry owns them, layer2/3/4 share the fds).
// tc_ingress lives in its own block — it shares only stats_map.
static const std::vector<std::string> kSharedXdpMaps = {
    "gen_config",
    "prog_array_0", "prog_array_1",
    "l2_rules_0", "l2_rules_1",
    "l2_active_masks_0", "l2_active_masks_1",
    "subnet_rules_0", "subnet_rules_1",
    "subnet6_rules_0", "subnet6_rules_1",
    "subnet_rules_dst_0", "subnet_rules_dst_1",
    "subnet6_rules_dst_0", "subnet6_rules_dst_1",
    "vrf_rules_0", "vrf_rules_1",
    "l4_rules_0", "l4_rules_1",
    "default_action_0", "default_action_1",
    "layer_present_0", "layer_present_1",
    "rate_state_map",
    "stats_map",
    "bytes_map",
};

// Two skeletons may hold different FDs onto the same kernel map (reuse
// dup()s the underlying file). Compare by kernel map id, which uniquely
// identifies the object — divergence here means two real maps with the
// same name, the actual bug we're guarding against.
static uint32_t map_id_for_fd(int fd) {
    struct bpf_map_info info{};
    uint32_t info_len = sizeof(info);
    int err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    if (err) return 0;
    return info.id;
}

TEST(test_shared_xdp_maps_have_identical_kernel_id_across_skeletons) {
    BpfLoader loader;
    auto r = loader.load();
    if (!r.has_value()) {
        // Likely a privilege issue (CAP_BPF missing). ctest treats 77 as skip.
        std::cerr << "  [skip] BpfLoader::load failed: " << r.error() << "\n";
        std::exit(77);
    }

    int violations = 0;
    for (const auto& name : kSharedXdpMaps) {
        int entry_fd  = loader.map_fd_in_skel("entry",  name.c_str());
        int l2_fd     = loader.map_fd_in_skel("layer2", name.c_str());
        int l3_fd     = loader.map_fd_in_skel("layer3", name.c_str());
        int l4_fd     = loader.map_fd_in_skel("layer4", name.c_str());

        if (entry_fd < 0) {
            std::cerr << "  FAIL " << name << ": missing from entry skeleton\n";
            ++violations;
            continue;
        }
        uint32_t entry_id = map_id_for_fd(entry_fd);
        uint32_t l2_id    = map_id_for_fd(l2_fd);
        uint32_t l3_id    = map_id_for_fd(l3_fd);
        uint32_t l4_id    = map_id_for_fd(l4_fd);

        if (entry_id == 0) {
            std::cerr << "  FAIL " << name << ": cannot read entry map id\n";
            ++violations;
            continue;
        }
        if (l2_id != entry_id) {
            std::cerr << "  FAIL " << name << ": layer2 map_id=" << l2_id
                      << " != entry map_id=" << entry_id << "\n";
            ++violations;
        }
        if (l3_id != entry_id) {
            std::cerr << "  FAIL " << name << ": layer3 map_id=" << l3_id
                      << " != entry map_id=" << entry_id << "\n";
            ++violations;
        }
        if (l4_id != entry_id) {
            std::cerr << "  FAIL " << name << ": layer4 map_id=" << l4_id
                      << " != entry map_id=" << entry_id << "\n";
            ++violations;
        }
    }
    assert(violations == 0 && "shared XDP maps must reuse entry's kernel map");
}

TEST(test_tc_ingress_shares_stats_map) {
    BpfLoader loader;
    auto r = loader.load();
    if (!r.has_value()) {
        std::cerr << "  [skip] BpfLoader::load failed: " << r.error() << "\n";
        std::exit(77);
    }

    int entry_fd = loader.map_fd_in_skel("entry",      "stats_map");
    int tc_fd    = loader.map_fd_in_skel("tc_ingress", "stats_map");
    assert(entry_fd >= 0);
    assert(tc_fd >= 0);
    assert(map_id_for_fd(entry_fd) == map_id_for_fd(tc_fd) &&
           "tc_ingress must reuse entry's stats_map");
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
