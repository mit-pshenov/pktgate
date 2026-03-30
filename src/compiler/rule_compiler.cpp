#include "compiler/rule_compiler.hpp"
#include "util/net_types.hpp"
#include <bpf/libbpf.h>
#include <cstring>
#include <unordered_map>

namespace pktgate::compiler {

static uint32_t action_to_bpf(config::Action a) {
    switch (a) {
        case config::Action::Allow:     return 1; // ACT_ALLOW
        case config::Action::Drop:      return 0; // ACT_DROP
        case config::Action::Mirror:    return 2; // ACT_MIRROR
        case config::Action::Redirect:  return 3; // ACT_REDIRECT
        case config::Action::Tag:       return 4; // ACT_TAG
        case config::Action::RateLimit: return 5; // ACT_RATE_LIMIT
    }
    return 0;
}

static uint8_t protocol_to_num(const std::string& proto) {
    if (proto == "TCP" || proto == "tcp") return 6;
    if (proto == "UDP" || proto == "udp") return 17;
    throw std::invalid_argument("Unknown protocol: " + proto);
}

/// Resolve "object:xxx" to the actual subnet CIDR string.
static std::string resolve_object_subnet(const std::string& ref,
                                          const config::ObjectStore& objects) {
    if (ref.starts_with("object:")) {
        auto name = ref.substr(7);
        auto it = objects.subnets.find(name);
        if (it == objects.subnets.end())
            throw std::invalid_argument("Unknown subnet object: " + name);
        return it->second;
    }
    return ref; // literal CIDR
}

/// Resolve "object6:xxx" to the actual IPv6 CIDR string.
static std::string resolve_object_subnet6(const std::string& ref,
                                            const config::ObjectStore& objects) {
    if (ref.starts_with("object6:")) {
        auto name = ref.substr(8);
        auto it = objects.subnets6.find(name);
        if (it == objects.subnets6.end())
            throw std::invalid_argument("Unknown subnet6 object: " + name);
        return it->second;
    }
    return ref; // literal IPv6 CIDR
}

/// Resolve "object:xxx" port group to a list of ports.
static std::vector<uint16_t> resolve_object_ports(const std::string& ref,
                                                    const config::ObjectStore& objects) {
    if (ref.starts_with("object:")) {
        auto name = ref.substr(7);
        auto it = objects.port_groups.find(name);
        if (it == objects.port_groups.end())
            throw std::invalid_argument("Unknown port group object: " + name);
        return it->second;
    }
    // Literal single port
    int port = std::stoi(ref);
    if (port < 0 || port > 65535)
        throw std::invalid_argument("Port out of range: " + ref);
    return { static_cast<uint16_t>(port) };
}

std::expected<CompiledRules, std::string>
compile_rules(const config::Pipeline& pipeline,
              const config::ObjectStore& objects,
              IfindexResolver resolver)
{
    CompiledRules result;
    result.l3_rules.reserve(pipeline.layer_3.size());

    // Estimate L4 expansion: each rule may expand to multiple ports
    size_t l4_estimate = 0;
    for (auto& rule : pipeline.layer_4) {
        if (rule.match.dst_port && rule.match.dst_port->starts_with("object:")) {
            auto name = rule.match.dst_port->substr(7);
            auto it = objects.port_groups.find(name);
            l4_estimate += (it != objects.port_groups.end()) ? it->second.size() : 1;
        } else {
            l4_estimate += 1;
        }
    }
    result.l4_rules.reserve(l4_estimate);

    try {
        // Compile Layer 3 rules
        for (auto& rule : pipeline.layer_3) {
            CompiledL3Rule cr{};
            cr.rule.rule_id  = rule.rule_id;
            cr.rule.action   = action_to_bpf(rule.action);
            cr.rule.has_next_layer = rule.next_layer.has_value() ? 1 : 0;

            if (rule.action == config::Action::Redirect && rule.params.target_vrf) {
                cr.rule.redirect_ifindex = resolver(*rule.params.target_vrf);
            }
            if (rule.action == config::Action::Mirror && rule.params.target_port) {
                cr.rule.mirror_ifindex = resolver(*rule.params.target_port);
            }

            if (rule.match.src_ip6) {
                // IPv6 rule — goes into l3v6_rules
                auto cidr6 = resolve_object_subnet6(*rule.match.src_ip6, objects);
                auto prefix6 = util::Ipv6Prefix::parse(cidr6);

                CompiledL3v6Rule cr6{};
                cr6.rule = cr.rule;
                cr6.subnet_key.prefixlen = prefix6.prefixlen;
                std::memcpy(cr6.subnet_key.addr, prefix6.addr.data(), 16);
                result.l3v6_rules.push_back(cr6);
                continue;  // skip v4 push below
            }

            if (rule.match.src_ip) {
                auto cidr = resolve_object_subnet(*rule.match.src_ip, objects);
                auto prefix = util::Ipv4Prefix::parse(cidr);
                cr.subnet_key.prefixlen = prefix.prefixlen;
                cr.subnet_key.addr      = prefix.addr_nbo();
            } else if (rule.match.vrf) {
                cr.is_vrf_rule  = true;
                cr.vrf_ifindex  = resolver(*rule.match.vrf);
            }

            result.l3_rules.push_back(cr);
        }

        // Compile Layer 4 rules
        for (auto& rule : pipeline.layer_4) {
            if (!rule.match.protocol)
                return std::unexpected("L4 rule " + std::to_string(rule.rule_id) +
                                       " missing protocol");

            auto proto_num = protocol_to_num(*rule.match.protocol);

            // Resolve ports (may expand object reference to multiple ports)
            std::vector<uint16_t> ports;
            if (rule.match.dst_port)
                ports = resolve_object_ports(*rule.match.dst_port, objects);
            else
                return std::unexpected("L4 rule " + std::to_string(rule.rule_id) +
                                       " missing dst_port");

            // Create one compiled rule per port
            for (auto port : ports) {
                CompiledL4Rule cr{};
                cr.match.protocol = proto_num;
                cr.match.dst_port = port;

                cr.rule.rule_id = rule.rule_id;
                cr.rule.action  = action_to_bpf(rule.action);

                if (rule.action == config::Action::Tag) {
                    if (rule.params.dscp)
                        cr.rule.dscp = config::dscp_from_name(*rule.params.dscp);
                    if (rule.params.cos)
                        cr.rule.cos = *rule.params.cos;
                }

                if (rule.action == config::Action::RateLimit && rule.params.bandwidth) {
                    auto total_bps = config::parse_bandwidth(*rule.params.bandwidth);
                    /*
                     * rate_state_map is PERCPU — each CPU runs an independent
                     * token bucket.  Divide the configured rate evenly so the
                     * aggregate across all CPUs approximates the user's intent.
                     * Assumes roughly even RSS distribution; worst-case skew
                     * is bounded by single-CPU share.
                     */
                    if (total_bps > 0) {
                        int ncpus = libbpf_num_possible_cpus();
                        if (ncpus < 1) ncpus = 1;
                        cr.rule.rate_bps = total_bps / static_cast<uint64_t>(ncpus);
                        if (cr.rule.rate_bps == 0) cr.rule.rate_bps = 1;
                    }
                }

                result.l4_rules.push_back(cr);
            }
        }
    } catch (const std::exception& e) {
        return std::unexpected(std::string("Rule compilation error: ") + e.what());
    }

    // ── Detect map key collisions ──────────────────────────────

    // L4: duplicate protocol+port → last-write-wins in BPF hash map
    {
        // Key: (protocol << 16) | port → first rule_id that claimed it
        std::unordered_map<uint32_t, uint32_t> seen;
        for (auto& cr : result.l4_rules) {
            uint32_t k = (static_cast<uint32_t>(cr.match.protocol) << 16) | cr.match.dst_port;
            auto [it, inserted] = seen.emplace(k, cr.rule.rule_id);
            if (!inserted) {
                const char* proto = cr.match.protocol == 6 ? "TCP" : "UDP";
                return std::unexpected(
                    "L4 key collision: " + std::string(proto) + ":" +
                    std::to_string(cr.match.dst_port) +
                    " claimed by rule " + std::to_string(it->second) +
                    " and rule " + std::to_string(cr.rule.rule_id));
            }
        }
    }

    // L3 subnet: duplicate LPM key (prefixlen+addr)
    {
        // Key: (prefixlen << 32) | addr
        std::unordered_map<uint64_t, uint32_t> seen;
        for (auto& cr : result.l3_rules) {
            if (cr.is_vrf_rule) continue;
            uint64_t k = (static_cast<uint64_t>(cr.subnet_key.prefixlen) << 32) |
                         cr.subnet_key.addr;
            auto [it, inserted] = seen.emplace(k, cr.rule.rule_id);
            if (!inserted) {
                return std::unexpected(
                    "L3 subnet key collision: same prefix used by rule " +
                    std::to_string(it->second) + " and rule " +
                    std::to_string(cr.rule.rule_id));
            }
        }
    }

    // L3 IPv6 subnet: duplicate LPM key
    {
        // Key: hash of prefixlen + first 8 bytes of addr (collision-resistant enough)
        std::unordered_map<std::string, uint32_t> seen;
        for (auto& cr : result.l3v6_rules) {
            // Build a unique string key from prefixlen + full address
            std::string k(reinterpret_cast<const char*>(&cr.subnet_key),
                          sizeof(cr.subnet_key));
            auto [it, inserted] = seen.emplace(std::move(k), cr.rule.rule_id);
            if (!inserted) {
                return std::unexpected(
                    "L3 IPv6 subnet key collision: same prefix used by rule " +
                    std::to_string(it->second) + " and rule " +
                    std::to_string(cr.rule.rule_id));
            }
        }
    }

    // L3 VRF: duplicate ifindex
    {
        std::unordered_map<uint32_t, uint32_t> seen;
        for (auto& cr : result.l3_rules) {
            if (!cr.is_vrf_rule) continue;
            auto [it, inserted] = seen.emplace(cr.vrf_ifindex, cr.rule.rule_id);
            if (!inserted) {
                return std::unexpected(
                    "L3 VRF key collision: ifindex " +
                    std::to_string(cr.vrf_ifindex) +
                    " used by rule " + std::to_string(it->second) +
                    " and rule " + std::to_string(cr.rule.rule_id));
            }
        }
    }

    return result;
}

} // namespace pktgate::compiler
