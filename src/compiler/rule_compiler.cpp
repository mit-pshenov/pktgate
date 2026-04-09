#include "compiler/rule_compiler.hpp"
#include "util/net_types.hpp"
#include <arpa/inet.h>
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

/// Resolve "object:xxx" mac group to a list of parsed MAC addresses.
static std::vector<util::MacAddr> resolve_object_macs(const std::string& ref,
                                                       const config::ObjectStore& objects) {
    if (ref.starts_with("object:")) {
        auto name = ref.substr(7);
        auto it = objects.mac_groups.find(name);
        if (it == objects.mac_groups.end())
            throw std::invalid_argument("Unknown mac_group object: " + name);
        std::vector<util::MacAddr> result;
        for (auto& mac_str : it->second)
            result.push_back(util::MacAddr::parse(mac_str));
        return result;
    }
    // Literal single MAC
    return { util::MacAddr::parse(ref) };
}

/// Map next_layer config string to BPF layer index.
static uint8_t next_layer_to_idx(const std::optional<std::string>& nl) {
    if (!nl) return 0;
    if (*nl == "layer_3") return 1; // LAYER_3_IDX
    if (*nl == "layer_4") return 2; // LAYER_4_IDX
    return 0;
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
        // Compile Layer 2 rules
        for (auto& rule : pipeline.layer_2) {
            struct l2_rule base{};
            base.rule_id = rule.rule_id;
            base.action  = action_to_bpf(rule.action);
            base.next_layer = next_layer_to_idx(rule.next_layer);

            if (rule.action == config::Action::Redirect && rule.params.target_vrf)
                base.redirect_ifindex = resolver(*rule.params.target_vrf);
            if (rule.action == config::Action::Mirror && rule.params.target_port)
                base.mirror_ifindex = resolver(*rule.params.target_port);

            // Determine primary field by selectivity:
            // src_mac > dst_mac > vlan_id > ethertype > pcp
            L2MatchType primary;
            if (rule.match.src_mac)
                primary = L2MatchType::SrcMac;
            else if (rule.match.dst_mac)
                primary = L2MatchType::DstMac;
            else if (rule.match.vlan_id)
                primary = L2MatchType::Vlan;
            else if (rule.match.ethertype)
                primary = L2MatchType::Ethertype;
            else if (rule.match.pcp)
                primary = L2MatchType::Pcp;
            else
                continue; // no match fields — validator should have caught this

            // Build secondary filter mask + values
            uint8_t filter_mask = 0;
            if (rule.match.ethertype && primary != L2MatchType::Ethertype) {
                filter_mask |= L2_FILTER_ETHERTYPE;
                base.filter_ethertype = htons(config::parse_ethertype(*rule.match.ethertype));
            }
            if (rule.match.vlan_id && primary != L2MatchType::Vlan) {
                filter_mask |= L2_FILTER_VLAN;
                base.filter_vlan_id = *rule.match.vlan_id;
            }
            if (rule.match.pcp && primary != L2MatchType::Pcp) {
                filter_mask |= L2_FILTER_PCP;
                base.filter_pcp = *rule.match.pcp;
            }
            base.filter_mask = filter_mask;

            // Emit compiled entries (MAC types expand object groups)
            auto emit_entry = [&](L2MatchType type) {
                if (type == L2MatchType::SrcMac) {
                    auto macs = resolve_object_macs(*rule.match.src_mac, objects);
                    for (auto& mac : macs) {
                        CompiledL2Rule cr{};
                        cr.type = L2MatchType::SrcMac;
                        std::memcpy(cr.mac.addr, mac.bytes.data(), 6);
                        cr.rule = base;
                        result.l2_rules.push_back(cr);
                    }
                } else if (type == L2MatchType::DstMac) {
                    auto macs = resolve_object_macs(*rule.match.dst_mac, objects);
                    for (auto& mac : macs) {
                        CompiledL2Rule cr{};
                        cr.type = L2MatchType::DstMac;
                        std::memcpy(cr.mac.addr, mac.bytes.data(), 6);
                        cr.rule = base;
                        result.l2_rules.push_back(cr);
                    }
                } else if (type == L2MatchType::Ethertype) {
                    CompiledL2Rule cr{};
                    cr.type = L2MatchType::Ethertype;
                    cr.ether.ethertype = htons(config::parse_ethertype(*rule.match.ethertype));
                    cr.rule = base;
                    result.l2_rules.push_back(cr);
                } else if (type == L2MatchType::Vlan) {
                    CompiledL2Rule cr{};
                    cr.type = L2MatchType::Vlan;
                    cr.vlan.vlan_id = *rule.match.vlan_id;
                    cr.rule = base;
                    result.l2_rules.push_back(cr);
                } else if (type == L2MatchType::Pcp) {
                    CompiledL2Rule cr{};
                    cr.type = L2MatchType::Pcp;
                    cr.pcp.pcp = *rule.match.pcp;
                    cr.rule = base;
                    result.l2_rules.push_back(cr);
                }
            };
            emit_entry(primary);
        }

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

                if (rule.match.tcp_flags) {
                    auto tf = config::parse_tcp_flags(*rule.match.tcp_flags);
                    cr.rule.tcp_flags_set   = tf.flags_set;
                    cr.rule.tcp_flags_unset = tf.flags_unset;
                }

                result.l4_rules.push_back(cr);
            }
        }
    } catch (const std::exception& e) {
        return std::unexpected(std::string("Rule compilation error: ") + e.what());
    }

    // ── Detect map key collisions ──────────────────────────────

    // L2: duplicate keys within each match type
    {
        // src_mac collisions
        std::unordered_map<std::string, uint32_t> src_seen, dst_seen;
        std::unordered_map<uint16_t, uint32_t> ether_seen, vlan_seen;
        std::unordered_map<uint32_t, uint32_t> pcp_seen;

        for (auto& cr : result.l2_rules) {
            std::string mac_str(reinterpret_cast<const char*>(cr.mac.addr), 6);
            switch (cr.type) {
            case L2MatchType::SrcMac: {
                auto [it, ok] = src_seen.emplace(mac_str, cr.rule.rule_id);
                if (!ok)
                    return std::unexpected(
                        "L2 src_mac key collision: same MAC used by rule " +
                        std::to_string(it->second) + " and rule " +
                        std::to_string(cr.rule.rule_id));
                break;
            }
            case L2MatchType::DstMac: {
                auto [it, ok] = dst_seen.emplace(mac_str, cr.rule.rule_id);
                if (!ok)
                    return std::unexpected(
                        "L2 dst_mac key collision: same MAC used by rule " +
                        std::to_string(it->second) + " and rule " +
                        std::to_string(cr.rule.rule_id));
                break;
            }
            case L2MatchType::Ethertype: {
                auto [it, ok] = ether_seen.emplace(cr.ether.ethertype, cr.rule.rule_id);
                if (!ok)
                    return std::unexpected(
                        "L2 ethertype key collision: same ethertype used by rule " +
                        std::to_string(it->second) + " and rule " +
                        std::to_string(cr.rule.rule_id));
                break;
            }
            case L2MatchType::Vlan: {
                auto [it, ok] = vlan_seen.emplace(cr.vlan.vlan_id, cr.rule.rule_id);
                if (!ok)
                    return std::unexpected(
                        "L2 vlan key collision: same vlan_id used by rule " +
                        std::to_string(it->second) + " and rule " +
                        std::to_string(cr.rule.rule_id));
                break;
            }
            case L2MatchType::Pcp: {
                auto [it, ok] = pcp_seen.emplace(cr.pcp.pcp, cr.rule.rule_id);
                if (!ok)
                    return std::unexpected(
                        "L2 pcp key collision: same PCP used by rule " +
                        std::to_string(it->second) + " and rule " +
                        std::to_string(cr.rule.rule_id));
                break;
            }
            }
        }
    }

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
