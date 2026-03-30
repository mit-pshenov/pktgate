#pragma once

#include "loader/map_registry.hpp"

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

    /// Attach TC ingress program to the given interface.
    std::expected<void, std::string> attach_tc(const std::string& interface);

    /// Detach TC ingress program.
    void detach_tc();

    bool is_loaded() const { return loaded_; }

    /// Access the FD registry (populated after load()).
    const MapRegistry& registry() const { return registry_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    MapRegistry registry_;
    bool loaded_ = false;
    bool attached_ = false;
    bool tc_attached_ = false;
    unsigned attach_ifindex_ = 0;
    uint32_t attach_flags_ = 0;
};

} // namespace pktgate::loader
