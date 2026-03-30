#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <unordered_map>

namespace pktgate::config {

/* ── Object store ──────────────────────────────────────────── */

struct ObjectStore {
    // name → IPv4 CIDR string (e.g. "100.64.0.0/16")
    std::unordered_map<std::string, std::string> subnets;

    // name → IPv6 CIDR string (e.g. "2001:db8::/32")
    std::unordered_map<std::string, std::string> subnets6;

    // name → list of MAC strings
    std::unordered_map<std::string, std::vector<std::string>> mac_groups;

    // name → list of ports
    std::unordered_map<std::string, std::vector<uint16_t>> port_groups;
};

/* ── Match / Action ────────────────────────────────────────── */

struct MatchCriteria {
    std::optional<std::string> src_mac;    // literal or "object:xxx"
    std::optional<std::string> src_ip;     // literal IPv4 CIDR or "object:xxx"
    std::optional<std::string> dst_ip;
    std::optional<std::string> src_ip6;    // literal IPv6 CIDR or "object6:xxx"
    std::optional<std::string> dst_ip6;
    std::optional<std::string> vrf;        // VRF name
    std::optional<std::string> protocol;   // "TCP" / "UDP"
    std::optional<std::string> dst_port;   // literal or "object:xxx"
};

enum class Action {
    Allow,
    Drop,
    Mirror,
    Redirect,
    Tag,
    RateLimit,
    Userspace,
};

struct ActionParams {
    std::optional<std::string> target_port; // interface name for mirror
    std::optional<std::string> target_vrf;  // VRF name for redirect
    std::optional<std::string> dscp;        // DSCP name (e.g. "EF")
    std::optional<uint8_t>     cos;         // 0-7
    std::optional<std::string> bandwidth;   // e.g. "10Gbps"
};

/* ── Rule ──────────────────────────────────────────────────── */

struct Rule {
    uint32_t                   rule_id{};
    std::string                description;
    MatchCriteria              match;
    Action                     action{};
    ActionParams               params;
    std::optional<std::string> next_layer; // "layer_3", "layer_4"
};

/* ── Pipeline ──────────────────────────────────────────────── */

struct Pipeline {
    std::vector<Rule> layer_2;
    std::vector<Rule> layer_3;
    std::vector<Rule> layer_4;
};

/* ── Top-level config ──────────────────────────────────────── */

struct AfXdpConfig {
    bool     enabled    = false;
    uint32_t queues     = 0;      // 0 = auto-detect
    bool     zero_copy  = false;
    uint32_t frame_size = 4096;
    uint32_t num_frames = 4096;
};

struct Config {
    std::string  interface;
    std::string  capacity;
    ObjectStore  objects;
    Pipeline     pipeline;
    Action       default_behavior = Action::Drop;
    AfXdpConfig  afxdp;
};

/* ── Helpers ───────────────────────────────────────────────── */

inline Action parse_action(const std::string& s) {
    if (s == "allow")      return Action::Allow;
    if (s == "drop")       return Action::Drop;
    if (s == "mirror")     return Action::Mirror;
    if (s == "redirect")   return Action::Redirect;
    if (s == "tag")        return Action::Tag;
    if (s == "rate-limit") return Action::RateLimit;
    if (s == "userspace")  return Action::Userspace;
    throw std::invalid_argument("Unknown action: " + s);
}

inline uint8_t dscp_from_name(const std::string& name) {
    if (name == "EF")   return 46;
    if (name == "AF11") return 10;
    if (name == "AF12") return 12;
    if (name == "AF13") return 14;
    if (name == "AF21") return 18;
    if (name == "AF22") return 20;
    if (name == "AF23") return 22;
    if (name == "AF31") return 26;
    if (name == "AF32") return 28;
    if (name == "AF33") return 30;
    if (name == "AF41") return 34;
    if (name == "AF42") return 36;
    if (name == "AF43") return 38;
    if (name == "CS0")  return 0;
    if (name == "CS1")  return 8;
    if (name == "CS2")  return 16;
    if (name == "CS3")  return 24;
    if (name == "CS4")  return 32;
    if (name == "CS5")  return 40;
    if (name == "CS6")  return 48;
    if (name == "CS7")  return 56;
    if (name == "BE")   return 0;
    throw std::invalid_argument("Unknown DSCP name: " + name);
}

inline uint64_t parse_bandwidth(const std::string& s) {
    // Parse "10Gbps", "100Mbps", etc.
    size_t pos = 0;
    while (pos < s.size() && (s[pos] >= '0' && s[pos] <= '9'))
        ++pos;
    if (pos == 0)
        throw std::invalid_argument("Invalid bandwidth: " + s);

    uint64_t value = std::stoull(s.substr(0, pos));
    auto unit = s.substr(pos);

    uint64_t multiplier = 0;
    if (unit == "Gbps" || unit == "gbps") multiplier = 1000000000ULL;
    else if (unit == "Mbps" || unit == "mbps") multiplier = 1000000ULL;
    else if (unit == "Kbps" || unit == "kbps") multiplier = 1000ULL;
    else if (unit == "bps") multiplier = 1;
    else throw std::invalid_argument("Unknown bandwidth unit: " + unit);

    if (multiplier > 1 && value > UINT64_MAX / multiplier)
        throw std::overflow_error("Bandwidth overflow: " + s);

    return value * multiplier;
}

} // namespace pktgate::config
