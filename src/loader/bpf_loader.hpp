#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <string>

namespace pktgate::loader {

class BpfLoader {
public:
    BpfLoader();
    ~BpfLoader();

    BpfLoader(const BpfLoader&) = delete;
    BpfLoader& operator=(const BpfLoader&) = delete;

    /// Open, load, and verify all BPF programs.
    std::expected<void, std::string> load();

    /// Attach entry program to the given interface (XDP).
    /// Tries native mode first, falls back to SKB (generic) mode for veth etc.
    std::expected<void, std::string> attach(const std::string& interface);

    /// Detach from interface and close all resources.
    void detach();

    // Map FD accessors (generation-aware)
    int mac_allow_fd(uint32_t gen) const;
    int subnet_rules_fd(uint32_t gen) const;
    int subnet6_rules_fd(uint32_t gen) const;
    int vrf_rules_fd(uint32_t gen) const;
    int l4_rules_fd(uint32_t gen) const;
    int prog_array_fd(uint32_t gen) const;
    int default_action_fd(uint32_t gen) const;
    int gen_config_fd() const;
    int rate_state_fd() const;
    int stats_map_fd() const;

    // Program FD accessors (for inserting into prog_array)
    int entry_prog_fd() const;
    int layer2_prog_fd() const;
    int layer3_prog_fd() const;
    int layer4_prog_fd() const;
    int tc_ingress_prog_fd() const;

    /// Attach TC ingress program to the given interface.
    std::expected<void, std::string> attach_tc(const std::string& interface);

    /// Detach TC ingress program.
    void detach_tc();

    bool is_loaded() const { return loaded_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    bool loaded_ = false;
    bool attached_ = false;
    bool tc_attached_ = false;
    unsigned attach_ifindex_ = 0;
    uint32_t attach_flags_ = 0;
};

} // namespace pktgate::loader
