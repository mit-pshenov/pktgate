#include "config/config_validator.hpp"
#include <unordered_set>
#include <algorithm>

namespace pktgate::config {

static void check_object_ref(const std::string& ref,
                              const std::string& kind,
                              const auto& store,
                              const std::string& ctx,
                              std::vector<ValidationError>& errs) {
    if (!ref.starts_with("object:"))
        return;
    auto name = ref.substr(7);
    if (store.find(name) == store.end())
        errs.push_back({ctx, "unknown " + kind + " object: " + name});
}

static void validate_rule_ids(const std::vector<Rule>& rules,
                               const std::string& layer_name,
                               std::vector<ValidationError>& errs) {
    std::unordered_set<uint32_t> seen;
    for (size_t i = 0; i < rules.size(); ++i) {
        auto& r = rules[i];
        std::string ctx = layer_name + "[" + std::to_string(i) + "]";
        if (!seen.insert(r.rule_id).second)
            errs.push_back({ctx, "duplicate rule_id " + std::to_string(r.rule_id)});
    }
}

// Per-layer "applicable match fields" check. Closes P0-05 from the review:
// the compiler silently dropped fields that didn't apply to a layer, so
// `dst_port` on an L3 rule or `src_mac` on an L4 rule was accepted but had
// no runtime effect. Operator intent diverged from behaviour with no warning.
static void check_field_applicability(const MatchCriteria& m,
                                       int layer,
                                       const std::string& ctx,
                                       std::vector<ValidationError>& errs) {
    auto reject = [&](const char* field) {
        errs.push_back({ctx,
            std::string("field '") + field + "' is not applicable to layer " +
            std::to_string(layer)});
    };
    if (layer != 2) {
        if (m.src_mac)   reject("src_mac");
        if (m.dst_mac)   reject("dst_mac");
        if (m.ethertype) reject("ethertype");
        if (m.vlan_id)   reject("vlan_id");
        if (m.pcp)       reject("pcp");
    }
    if (layer != 3) {
        // dst_ip / dst_ip6 already rejected outright in validate_l3_rules.
        if (m.src_ip)    reject("src_ip");
        if (m.src_ip6)   reject("src_ip6");
        if (m.vrf)       reject("vrf");
    }
    if (layer != 4) {
        if (m.protocol)  reject("protocol");
        if (m.dst_port)  reject("dst_port");
        if (m.tcp_flags) reject("tcp_flags");
    }
}

static void validate_l2_rules(const std::vector<Rule>& rules,
                               const ObjectStore& objects,
                               std::vector<ValidationError>& errs) {
    validate_rule_ids(rules, "layer_2", errs);
    for (size_t i = 0; i < rules.size(); ++i) {
        auto& r = rules[i];
        std::string ctx = "layer_2[" + std::to_string(i) + "]";

        check_field_applicability(r.match, 2, ctx, errs);

        // L2 rule must have at least one match field; src_mac+dst_mac combo is forbidden
        int match_count = 0;
        if (r.match.src_mac)   ++match_count;
        if (r.match.dst_mac)   ++match_count;
        if (r.match.ethertype) ++match_count;
        if (r.match.vlan_id)   ++match_count;
        if (r.match.pcp)       ++match_count;

        if (match_count == 0)
            errs.push_back({ctx, "L2 rule must specify a match field (src_mac, dst_mac, ethertype, vlan_id, or pcp)"});

        if (r.match.src_mac && r.match.dst_mac)
            errs.push_back({ctx, "src_mac and dst_mac cannot be combined in one L2 rule"});

        if (r.match.pcp && *r.match.pcp > 7)
            errs.push_back({ctx, "pcp must be 0-7"});

        if (r.match.src_mac)
            check_object_ref(*r.match.src_mac, "mac_group", objects.mac_groups, ctx, errs);
        if (r.match.dst_mac)
            check_object_ref(*r.match.dst_mac, "mac_group", objects.mac_groups, ctx, errs);

        if (r.match.ethertype) {
            try { parse_ethertype(*r.match.ethertype); }
            catch (...) {
                errs.push_back({ctx, "invalid ethertype: " + *r.match.ethertype});
            }
        }

        if (r.match.vlan_id && *r.match.vlan_id > 4095)
            errs.push_back({ctx, "vlan_id must be 0-4095"});

        if (r.action == Action::Mirror && !r.params.target_port)
            errs.push_back({ctx, "mirror action requires target_port"});

        if (r.action == Action::Redirect && !r.params.target_vrf)
            errs.push_back({ctx, "redirect action requires target_vrf"});

        if (r.next_layer && *r.next_layer != "layer_3" && *r.next_layer != "layer_4")
            errs.push_back({ctx, "invalid next_layer: " + *r.next_layer});
    }
}

static void validate_l3_rules(const std::vector<Rule>& rules,
                               const ObjectStore& objects,
                               std::vector<ValidationError>& errs) {
    validate_rule_ids(rules, "layer_3", errs);
    for (size_t i = 0; i < rules.size(); ++i) {
        auto& r = rules[i];
        std::string ctx = "layer_3[" + std::to_string(i) + "]";

        check_field_applicability(r.match, 3, ctx, errs);

        // dst_ip / dst_ip6 are parsed into the model but no destination LPM
        // trie exists in the data plane. Silently compiling them as a 0.0.0.0/0
        // entry (legacy fall-through in the compiler) turned a narrow drop
        // into a Gi-blackhole. Reject explicitly until destination LPM lands.
        if (r.match.dst_ip)
            errs.push_back({ctx, "dst_ip is not supported as an L3 match field"});
        if (r.match.dst_ip6)
            errs.push_back({ctx, "dst_ip6 is not supported as an L3 match field"});

        // L3 rule must specify at least one supported match field. Mirrors the
        // L2 guard above; without it, a typo (e.g. dst_ip instead of src_ip)
        // produces a rule with no constraints.
        int match_count = 0;
        if (r.match.src_ip)  ++match_count;
        if (r.match.src_ip6) ++match_count;
        if (r.match.vrf)     ++match_count;
        if (match_count == 0)
            errs.push_back({ctx, "L3 rule must specify a match field (src_ip, src_ip6, or vrf)"});

        if (r.match.src_ip)
            check_object_ref(*r.match.src_ip, "subnet", objects.subnets, ctx, errs);

        if (r.match.src_ip6) {
            // Check object6: references against subnets6 store
            if (r.match.src_ip6->starts_with("object6:")) {
                auto name = r.match.src_ip6->substr(8);
                if (objects.subnets6.find(name) == objects.subnets6.end())
                    errs.push_back({ctx, "unknown subnet6 object: " + name});
            }
        }

        if (r.action == Action::Mirror && !r.params.target_port)
            errs.push_back({ctx, "mirror action requires target_port"});

        if (r.action == Action::Redirect && !r.params.target_vrf)
            errs.push_back({ctx, "redirect action requires target_vrf"});

        if (r.next_layer && *r.next_layer != "layer_4")
            errs.push_back({ctx, "invalid next_layer from layer_3: " + *r.next_layer});
    }
}

static void validate_l4_rules(const std::vector<Rule>& rules,
                               const ObjectStore& objects,
                               std::vector<ValidationError>& errs) {
    validate_rule_ids(rules, "layer_4", errs);
    for (size_t i = 0; i < rules.size(); ++i) {
        auto& r = rules[i];
        std::string ctx = "layer_4[" + std::to_string(i) + "]";

        check_field_applicability(r.match, 4, ctx, errs);

        if (!r.match.protocol)
            errs.push_back({ctx, "L4 rule requires protocol"});
        else if (*r.match.protocol != "TCP" && *r.match.protocol != "tcp" &&
                 *r.match.protocol != "UDP" && *r.match.protocol != "udp")
            errs.push_back({ctx, "unsupported protocol: " + *r.match.protocol});

        if (!r.match.dst_port)
            errs.push_back({ctx, "L4 rule requires dst_port"});
        else {
            check_object_ref(*r.match.dst_port, "port_group", objects.port_groups, ctx, errs);

            // Validate literal port
            if (!r.match.dst_port->starts_with("object:")) {
                try {
                    int port = std::stoi(*r.match.dst_port);
                    if (port < 0 || port > 65535)
                        errs.push_back({ctx, "port out of range: " + *r.match.dst_port});
                } catch (...) {
                    errs.push_back({ctx, "invalid port: " + *r.match.dst_port});
                }
            }
        }

        if (r.action == Action::Tag) {
            if (r.params.dscp) {
                try { dscp_from_name(*r.params.dscp); }
                catch (...) {
                    errs.push_back({ctx, "unknown DSCP name: " + *r.params.dscp});
                }
            }
            if (r.params.cos)
                errs.push_back({ctx, "CoS rewrite is not yet supported "
                                     "(needs bpf_skb_vlan_push/pop in TC ingress)"});
        }

        if (r.action == Action::RateLimit) {
            if (!r.params.bandwidth)
                errs.push_back({ctx, "rate-limit action requires bandwidth"});
            else {
                try { parse_bandwidth(*r.params.bandwidth); }
                catch (...) {
                    errs.push_back({ctx, "invalid bandwidth: " + *r.params.bandwidth});
                }
            }
        }

        if (r.match.tcp_flags) {
            if (!r.match.protocol ||
                (*r.match.protocol != "TCP" && *r.match.protocol != "tcp"))
                errs.push_back({ctx, "tcp_flags requires protocol TCP"});
            try { parse_tcp_flags(*r.match.tcp_flags); }
            catch (...) {
                errs.push_back({ctx, "invalid tcp_flags: " + *r.match.tcp_flags});
            }
        }

        if (r.next_layer)
            errs.push_back({ctx, "layer_4 cannot have next_layer"});
    }
}

std::expected<void, std::vector<ValidationError>>
validate_config(const Config& cfg) {
    std::vector<ValidationError> errs;

    bool has_rules = !cfg.pipeline.layer_2.empty() ||
                     !cfg.pipeline.layer_3.empty() ||
                     !cfg.pipeline.layer_4.empty();
    if (has_rules && cfg.interface.empty())
        errs.push_back({"device_info", "interface must not be empty when rules are defined"});

    validate_l2_rules(cfg.pipeline.layer_2, cfg.objects, errs);
    validate_l3_rules(cfg.pipeline.layer_3, cfg.objects, errs);
    validate_l4_rules(cfg.pipeline.layer_4, cfg.objects, errs);

    if (errs.empty())
        return {};
    return std::unexpected(std::move(errs));
}

} // namespace pktgate::config
