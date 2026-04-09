#include "pipeline/generation_manager.hpp"
#include "loader/map_manager.hpp"
#include "util/log.hpp"
#include "../../bpf/common.h"

#include <bpf/bpf.h>
#include <cstring>
#include <unistd.h>

namespace pktgate::pipeline {

GenerationManager::GenerationManager(loader::BpfLoader& loader)
    : loader_(loader) {}

std::expected<void, std::string>
GenerationManager::install_programs(uint32_t gen) {
    int pa_fd = loader_.prog_array_fd(gen);
    if (pa_fd < 0)
        return std::unexpected("Invalid prog_array fd for gen " + std::to_string(gen));

    uint32_t idx;
    int fd;

    idx = LAYER_2_IDX;
    fd = loader_.layer2_prog_fd();
    if (fd < 0)
        return std::unexpected("Invalid layer2 prog fd");
    auto r = loader::MapManager::update_elem(pa_fd, &idx, &fd, BPF_ANY);
    if (!r) return std::unexpected("prog_array[L2]: " + r.error());

    idx = LAYER_3_IDX;
    fd = loader_.layer3_prog_fd();
    if (fd < 0)
        return std::unexpected("Invalid layer3 prog fd");
    r = loader::MapManager::update_elem(pa_fd, &idx, &fd, BPF_ANY);
    if (!r) return std::unexpected("prog_array[L3]: " + r.error());

    idx = LAYER_4_IDX;
    fd = loader_.layer4_prog_fd();
    if (fd < 0)
        return std::unexpected("Invalid layer4 prog fd");
    r = loader::MapManager::update_elem(pa_fd, &idx, &fd, BPF_ANY);
    if (!r) return std::unexpected("prog_array[L4]: " + r.error());

    LOG_DBG("Programs installed in prog_array gen=%u", gen);
    return {};
}

std::expected<void, std::string>
GenerationManager::clear_shadow_maps(uint32_t gen) {
    // Clear L2 hash maps
    auto r = loader::MapManager::clear_hash_map(loader_.l2_src_mac_fd(gen));
    if (!r) return std::unexpected("clear l2_src_mac: " + r.error());

    r = loader::MapManager::clear_hash_map(loader_.l2_dst_mac_fd(gen));
    if (!r) return std::unexpected("clear l2_dst_mac: " + r.error());

    r = loader::MapManager::clear_hash_map(loader_.l2_ethertype_fd(gen));
    if (!r) return std::unexpected("clear l2_ethertype: " + r.error());

    r = loader::MapManager::clear_hash_map(loader_.l2_vlan_fd(gen));
    if (!r) return std::unexpected("clear l2_vlan: " + r.error());

    r = loader::MapManager::clear_hash_map(loader_.l2_pcp_fd(gen));
    if (!r) return std::unexpected("clear l2_pcp: " + r.error());

    // LPM trie: delete tracked keys explicitly (iteration not supported)
    if (!lpm_keys_[gen].empty()) {
        r = loader::MapManager::delete_keys(
            loader_.subnet_rules_fd(gen), lpm_keys_[gen]);
        if (!r) return std::unexpected("clear subnet_rules: " + r.error());
        lpm_keys_[gen].clear();
    }

    // IPv6 LPM trie
    if (!lpm6_keys_[gen].empty()) {
        r = loader::MapManager::delete_keys(
            loader_.subnet6_rules_fd(gen), lpm6_keys_[gen]);
        if (!r) return std::unexpected("clear subnet6_rules: " + r.error());
        lpm6_keys_[gen].clear();
    }

    r = loader::MapManager::clear_hash_map(loader_.vrf_rules_fd(gen));
    if (!r) return std::unexpected("clear vrf_rules: " + r.error());

    r = loader::MapManager::clear_hash_map(loader_.l4_rules_fd(gen));
    if (!r) return std::unexpected("clear l4_rules: " + r.error());

    return {};
}

std::expected<void, std::string>
GenerationManager::populate_l2_maps(uint32_t gen,
                                     const compiler::CompiledRules& rules) {
    if (rules.l2_rules.empty()) return {};

    for (auto& cr : rules.l2_rules) {
        int fd = -1;
        const void* key = nullptr;

        switch (cr.type) {
        case compiler::L2MatchType::SrcMac:
            fd = loader_.l2_src_mac_fd(gen);
            key = &cr.mac;
            break;
        case compiler::L2MatchType::DstMac:
            fd = loader_.l2_dst_mac_fd(gen);
            key = &cr.mac;
            break;
        case compiler::L2MatchType::Ethertype:
            fd = loader_.l2_ethertype_fd(gen);
            key = &cr.ether;
            break;
        case compiler::L2MatchType::Vlan:
            fd = loader_.l2_vlan_fd(gen);
            key = &cr.vlan;
            break;
        case compiler::L2MatchType::Pcp:
            fd = loader_.l2_pcp_fd(gen);
            key = &cr.pcp;
            break;
        }

        auto r = loader::MapManager::update_elem(fd, key, &cr.rule, BPF_ANY);
        if (!r) return std::unexpected("L2 map insert (rule " +
                                        std::to_string(cr.rule.rule_id) + "): " + r.error());
    }

    LOG_DBG("Populated L2 maps gen=%u: %zu entries", gen, rules.l2_rules.size());
    return {};
}

std::expected<void, std::string>
GenerationManager::populate_subnet_map(uint32_t gen,
                                        const compiler::CompiledRules& rules) {
    int fd = loader_.subnet_rules_fd(gen);
    for (auto& cr : rules.l3_rules) {
        if (cr.is_vrf_rule) continue;
        auto r = loader::MapManager::update_elem(fd, &cr.subnet_key, &cr.rule, BPF_ANY);
        if (!r) return std::unexpected("subnet_rules insert (rule " +
                                        std::to_string(cr.rule.rule_id) + "): " + r.error());
        // Track the key for later deletion
        auto* key_bytes = reinterpret_cast<const uint8_t*>(&cr.subnet_key);
        lpm_keys_[gen].emplace_back(key_bytes, key_bytes + sizeof(cr.subnet_key));
    }
    return {};
}

std::expected<void, std::string>
GenerationManager::populate_subnet6_map(uint32_t gen,
                                         const compiler::CompiledRules& rules) {
    int fd = loader_.subnet6_rules_fd(gen);
    for (auto& cr : rules.l3v6_rules) {
        auto r = loader::MapManager::update_elem(fd, &cr.subnet_key, &cr.rule, BPF_ANY);
        if (!r) return std::unexpected("subnet6_rules insert (rule " +
                                        std::to_string(cr.rule.rule_id) + "): " + r.error());
        auto* key_bytes = reinterpret_cast<const uint8_t*>(&cr.subnet_key);
        lpm6_keys_[gen].emplace_back(key_bytes, key_bytes + sizeof(cr.subnet_key));
    }
    return {};
}

std::expected<void, std::string>
GenerationManager::populate_vrf_map(uint32_t gen,
                                     const compiler::CompiledRules& rules) {
    int fd = loader_.vrf_rules_fd(gen);
    for (auto& cr : rules.l3_rules) {
        if (!cr.is_vrf_rule) continue;
        struct vrf_key vk = { .ifindex = cr.vrf_ifindex };
        auto r = loader::MapManager::update_elem(fd, &vk, &cr.rule, BPF_ANY);
        if (!r) return std::unexpected("vrf_rules insert (rule " +
                                        std::to_string(cr.rule.rule_id) + "): " + r.error());
    }
    return {};
}

std::expected<void, std::string>
GenerationManager::populate_l4_map(uint32_t gen,
                                    const compiler::CompiledRules& rules) {
    if (rules.l4_rules.empty()) return {};
    int fd = loader_.l4_rules_fd(gen);

    // Try batch update first
    std::vector<struct l4_match_key> keys;
    std::vector<struct l4_rule> values;
    keys.reserve(rules.l4_rules.size());
    values.reserve(rules.l4_rules.size());
    for (auto& cr : rules.l4_rules) {
        keys.push_back(cr.match);
        values.push_back(cr.rule);
    }

    auto br = loader::MapManager::batch_update(
        fd, keys.data(), values.data(),
        static_cast<uint32_t>(keys.size()), BPF_ANY);
    if (br.has_value()) {
        LOG_DBG("Batch populated l4_rules gen=%u: %zu entries", gen, keys.size());
        return {};
    }

    // Fallback to sequential
    for (auto& cr : rules.l4_rules) {
        auto r = loader::MapManager::update_elem(fd, &cr.match, &cr.rule, BPF_ANY);
        if (!r) return std::unexpected("l4_rules insert (rule " +
                                        std::to_string(cr.rule.rule_id) + "): " + r.error());
    }
    LOG_DBG("Populated l4_rules gen=%u: %zu entries", gen, rules.l4_rules.size());
    return {};
}

std::expected<void, std::string>
GenerationManager::set_default_action(uint32_t gen, config::Action action) {
    int fd = loader_.default_action_fd(gen);
    uint32_t key = 0;
    uint32_t val;

    switch (action) {
        case config::Action::Drop:  val = ACT_DROP;  break;
        case config::Action::Allow: val = ACT_ALLOW; break;
        default: val = ACT_DROP; break;
    }

    auto r = loader::MapManager::update_elem(fd, &key, &val, BPF_ANY);
    if (!r) return std::unexpected("default_action: " + r.error());
    return {};
}

std::expected<void, std::string>
GenerationManager::prepare(const compiler::CompiledObjects& objects,
                           const compiler::CompiledRules& rules,
                           config::Action default_action) {
    uint32_t gen = shadow_generation();
    LOG_INF("Preparing shadow generation %u", gen);

    // Clear shadow maps
    auto r = clear_shadow_maps(gen);
    if (!r) return r;

    // Populate maps — if any step fails, clear what we've done
    r = populate_l2_maps(gen, rules);
    if (!r) {
        clear_shadow_maps(gen); // best-effort cleanup
        return r;
    }

    r = populate_subnet_map(gen, rules);
    if (!r) {
        clear_shadow_maps(gen);
        return r;
    }

    r = populate_subnet6_map(gen, rules);
    if (!r) {
        clear_shadow_maps(gen);
        return r;
    }

    r = populate_vrf_map(gen, rules);
    if (!r) {
        clear_shadow_maps(gen);
        return r;
    }

    r = populate_l4_map(gen, rules);
    if (!r) {
        clear_shadow_maps(gen);
        return r;
    }

    r = set_default_action(gen, default_action);
    if (!r) {
        clear_shadow_maps(gen);
        return r;
    }

    // Install programs in shadow prog_array
    r = install_programs(gen);
    if (!r) {
        clear_shadow_maps(gen);
        return r;
    }

    LOG_INF("Shadow generation %u ready", gen);
    return {};
}

std::expected<void, std::string>
GenerationManager::commit() {
    uint32_t new_gen = shadow_generation();
    uint32_t key = 0;

    // Atomic switch: update gen_config to point to shadow
    auto r = loader::MapManager::update_elem(
        loader_.gen_config_fd(), &key, &new_gen, BPF_ANY);
    if (!r) return std::unexpected("gen_config update: " + r.error());

    active_gen_.store(new_gen);
    LOG_INF("Committed: active generation is now %u", new_gen);

    /*
     * Brief pause to let in-flight packets on old generation drain.
     * XDP runs to completion per-packet with preemption disabled,
     * so any packet that started before the gen_config update will
     * complete within a few microseconds. 100ms is very conservative.
     */
    usleep(100000);
    return {};
}

std::expected<void, std::string>
GenerationManager::rollback() {
    // Switch back: shadow becomes active again (the old active gen)
    uint32_t old_gen = active_gen_.load() ^ 1;
    uint32_t key = 0;

    auto r = loader::MapManager::update_elem(
        loader_.gen_config_fd(), &key, &old_gen, BPF_ANY);
    if (!r) return std::unexpected("rollback gen_config: " + r.error());

    active_gen_.store(old_gen);
    LOG_INF("Rolled back to generation %u", old_gen);
    return {};
}

} // namespace pktgate::pipeline
