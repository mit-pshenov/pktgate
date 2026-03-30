#pragma once

#include "config/config_model.hpp"
#include "../../bpf/common.h"
#include <expected>
#include <string>
#include <vector>

namespace pktgate::compiler {

/* Compiled MAC entries ready for BPF map insertion */
struct CompiledMac {
    struct mac_key key;
    uint32_t       value; // 1 = allowed
};

/* Compiled subnet entries */
struct CompiledSubnet {
    struct lpm_v4_key key;
    std::string       object_name; // which object this came from
};

/* Compiled IPv6 subnet entries */
struct CompiledSubnet6 {
    struct lpm_v6_key key;
    std::string       object_name;
};

/* Compiled port group: expanded list of ports with group name */
struct CompiledPortGroup {
    std::string           group_name;
    std::vector<uint16_t> ports;
};

/* Result of compiling all objects */
struct CompiledObjects {
    std::vector<CompiledMac>       macs;
    std::vector<CompiledSubnet>    subnets;
    std::vector<CompiledSubnet6>   subnets6;
    std::vector<CompiledPortGroup> port_groups;
};

/// Compile config objects into BPF-map-ready entries.
std::expected<CompiledObjects, std::string>
compile_objects(const config::ObjectStore& objects);

} // namespace pktgate::compiler
