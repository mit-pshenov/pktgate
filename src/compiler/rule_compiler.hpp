#pragma once

#include "config/config_model.hpp"
#include "compiler/object_compiler.hpp"
#include "../../bpf/common.h"
#include <expected>
#include <functional>
#include <string>
#include <vector>
#include <cstdint>

namespace pktgate::compiler {

/* ── Layer 2 compiled rules ───────────────────────────────── */

enum class L2MatchType { SrcMac, DstMac, Ethertype, Vlan };

struct CompiledL2Rule {
    L2MatchType          type;
    struct mac_key       mac;    // for SrcMac / DstMac
    struct ethertype_key ether;  // for Ethertype
    struct vlan_key      vlan;   // for Vlan
    struct l2_rule       rule;
};

/* Compiled L3 rule: subnet key → l3_rule */
struct CompiledL3Rule {
    struct lpm_v4_key subnet_key;
    struct l3_rule    rule;
    bool              is_vrf_rule = false;
    uint32_t          vrf_ifindex = 0;
};

/* Compiled L3 IPv6 rule: subnet6 key → l3_rule */
struct CompiledL3v6Rule {
    struct lpm_v6_key subnet_key;
    struct l3_rule    rule;
};

/* Compiled L4 rule: match key → l4_rule */
struct CompiledL4Rule {
    struct l4_match_key match;
    struct l4_rule      rule;
};

struct CompiledRules {
    std::vector<CompiledL2Rule>   l2_rules;
    std::vector<CompiledL3Rule>   l3_rules;
    std::vector<CompiledL3v6Rule> l3v6_rules;
    std::vector<CompiledL4Rule>   l4_rules;
};

/// Interface name → ifindex resolver.
/// Allows injection for testing.
using IfindexResolver = std::function<uint32_t(const std::string&)>;

/// Compile pipeline rules into BPF-map-ready entries.
/// Uses resolver to map interface/VRF names to ifindex.
std::expected<CompiledRules, std::string>
compile_rules(const config::Pipeline& pipeline,
              const config::ObjectStore& objects,
              IfindexResolver resolver);

} // namespace pktgate::compiler
