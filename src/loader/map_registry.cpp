#include "loader/map_registry.hpp"

namespace pktgate::loader {

std::string MapRegistry::make_key(const std::string& name, uint32_t gen) {
    // "mac_allow:0", "mac_allow:1", "stats_map:shared"
    if (gen == SHARED)
        return name + ":shared";
    return name + ":" + std::to_string(gen);
}

void MapRegistry::register_map(const std::string& name, uint32_t gen, int fd) {
    map_fds_[make_key(name, gen)] = fd;
}

int MapRegistry::map_fd(const std::string& name, uint32_t gen) const {
    auto it = map_fds_.find(make_key(name, gen));
    return it != map_fds_.end() ? it->second : -1;
}

void MapRegistry::register_prog(const std::string& name, int fd) {
    prog_fds_[name] = fd;
}

int MapRegistry::prog_fd(const std::string& name) const {
    auto it = prog_fds_.find(name);
    return it != prog_fds_.end() ? it->second : -1;
}

} // namespace pktgate::loader
