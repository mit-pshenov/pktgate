#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace pktgate::loader {

/// FD registry for BPF maps and programs.
/// Extracted from BpfLoader to separate lifecycle from lookup.
class MapRegistry {
public:
    static constexpr uint32_t SHARED = UINT32_MAX;

    /// Register a map FD.  Use gen=SHARED for non-generational maps.
    void register_map(const std::string& name, uint32_t gen, int fd);

    /// Look up a map FD by name and generation.  Returns -1 if not found.
    int map_fd(const std::string& name, uint32_t gen) const;

    /// Shortcut for non-generational (shared) maps.
    int map_fd(const std::string& name) const { return map_fd(name, SHARED); }

    /// Register / look up program FDs.
    void register_prog(const std::string& name, int fd);
    int prog_fd(const std::string& name) const;

    // ── Convenience accessors (match old BpfLoader API) ──────────

    int mac_allow_fd(uint32_t gen) const      { return map_fd("mac_allow", gen); }
    int subnet_rules_fd(uint32_t gen) const   { return map_fd("subnet_rules", gen); }
    int subnet6_rules_fd(uint32_t gen) const  { return map_fd("subnet6_rules", gen); }
    int vrf_rules_fd(uint32_t gen) const      { return map_fd("vrf_rules", gen); }
    int l4_rules_fd(uint32_t gen) const       { return map_fd("l4_rules", gen); }
    int prog_array_fd(uint32_t gen) const     { return map_fd("prog_array", gen); }
    int default_action_fd(uint32_t gen) const { return map_fd("default_action", gen); }

    int gen_config_fd() const                 { return map_fd("gen_config"); }
    int rate_state_fd() const                 { return map_fd("rate_state"); }
    int stats_map_fd() const                  { return map_fd("stats_map"); }
    int xsks_map_fd() const                   { return map_fd("xsks_map"); }

    int entry_prog_fd() const                 { return prog_fd("entry"); }
    int layer2_prog_fd() const                { return prog_fd("layer2"); }
    int layer3_prog_fd() const                { return prog_fd("layer3"); }
    int layer4_prog_fd() const                { return prog_fd("layer4"); }
    int tc_ingress_prog_fd() const            { return prog_fd("tc_ingress"); }

private:
    static std::string make_key(const std::string& name, uint32_t gen);

    std::unordered_map<std::string, int> map_fds_;
    std::unordered_map<std::string, int> prog_fds_;
};

} // namespace pktgate::loader
