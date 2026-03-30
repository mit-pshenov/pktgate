#pragma once

#include "loader/bpf_loader.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "config/config_model.hpp"
#include <atomic>
#include <expected>
#include <string>
#include <vector>

namespace pktgate::pipeline {

class GenerationManager {
public:
    explicit GenerationManager(loader::BpfLoader& loader);

    /// Prepare shadow generation with new config.
    /// Fills shadow maps with compiled rules and objects.
    std::expected<void, std::string> prepare(
        const compiler::CompiledObjects& objects,
        const compiler::CompiledRules& rules,
        config::Action default_action);

    /// Atomically switch to shadow generation.
    std::expected<void, std::string> commit();

    /// Rollback to previous generation.
    std::expected<void, std::string> rollback();

    uint32_t active_generation() const { return active_gen_.load(); }
    uint32_t shadow_generation() const { return active_gen_.load() ^ 1; }

    /// Install layer programs into a prog_array for a given generation.
    std::expected<void, std::string> install_programs(uint32_t gen);

private:
    std::expected<void, std::string> clear_shadow_maps(uint32_t gen);
    std::expected<void, std::string> populate_mac_map(
        uint32_t gen, const compiler::CompiledObjects& objects);
    std::expected<void, std::string> populate_subnet_map(
        uint32_t gen, const compiler::CompiledRules& rules);
    std::expected<void, std::string> populate_subnet6_map(
        uint32_t gen, const compiler::CompiledRules& rules);
    std::expected<void, std::string> populate_vrf_map(
        uint32_t gen, const compiler::CompiledRules& rules);
    std::expected<void, std::string> populate_l4_map(
        uint32_t gen, const compiler::CompiledRules& rules);
    std::expected<void, std::string> set_default_action(
        uint32_t gen, config::Action action);

    std::atomic<uint32_t> active_gen_{0};
    loader::BpfLoader& loader_;

    // Track inserted LPM keys per generation for explicit deletion
    // (LPM_TRIE does not support iteration)
    std::vector<std::vector<uint8_t>> lpm_keys_[2];
    std::vector<std::vector<uint8_t>> lpm6_keys_[2];
};

} // namespace pktgate::pipeline
