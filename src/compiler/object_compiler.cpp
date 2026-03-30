#include "compiler/object_compiler.hpp"
#include "util/net_types.hpp"
#include <cstring>

namespace pktgate::compiler {

std::expected<CompiledObjects, std::string>
compile_objects(const config::ObjectStore& objects)
{
    CompiledObjects result;

    // Compile MAC groups
    for (auto& [name, macs] : objects.mac_groups) {
        for (auto& mac_str : macs) {
            try {
                auto mac = util::MacAddr::parse(mac_str);
                CompiledMac cm{};
                std::memcpy(cm.key.addr, mac.bytes.data(), 6);
                cm.value = 1;
                result.macs.push_back(cm);
            } catch (const std::exception& e) {
                return std::unexpected(
                    "MAC parse error in group '" + name + "': " + e.what());
            }
        }
    }

    // Compile subnets
    for (auto& [name, cidr] : objects.subnets) {
        try {
            auto prefix = util::Ipv4Prefix::parse(cidr);
            CompiledSubnet cs{};
            cs.key.prefixlen = prefix.prefixlen;
            cs.key.addr      = prefix.addr_nbo();
            cs.object_name   = name;
            result.subnets.push_back(cs);
        } catch (const std::exception& e) {
            return std::unexpected(
                "Subnet parse error for '" + name + "': " + e.what());
        }
    }

    // Compile IPv6 subnets
    for (auto& [name, cidr] : objects.subnets6) {
        try {
            auto prefix = util::Ipv6Prefix::parse(cidr);
            CompiledSubnet6 cs{};
            cs.key.prefixlen = prefix.prefixlen;
            std::memcpy(cs.key.addr, prefix.addr.data(), 16);
            cs.object_name   = name;
            result.subnets6.push_back(cs);
        } catch (const std::exception& e) {
            return std::unexpected(
                "IPv6 subnet parse error for '" + name + "': " + e.what());
        }
    }

    // Compile port groups
    for (auto& [name, ports] : objects.port_groups) {
        CompiledPortGroup cpg;
        cpg.group_name = name;
        cpg.ports      = ports;
        result.port_groups.push_back(std::move(cpg));
    }

    return result;
}

} // namespace pktgate::compiler
