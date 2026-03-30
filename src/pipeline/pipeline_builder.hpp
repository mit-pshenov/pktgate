#pragma once

#include "config/config_model.hpp"
#include "compiler/rule_compiler.hpp"
#include "pipeline/generation_manager.hpp"
#include "pipeline/deploy_stats.hpp"
#include <expected>
#include <optional>
#include <string>

namespace pktgate::pipeline {

class PipelineBuilder {
public:
    explicit PipelineBuilder(GenerationManager& gen_mgr);

    /// Build and deploy a new pipeline from config.
    /// Compiles objects/rules, fills shadow maps, commits.
    std::expected<void, std::string> deploy(
        const config::Config& cfg,
        compiler::IfindexResolver resolver);

    /// Get statistics from the last deploy() call.
    const std::optional<DeployStats>& last_stats() const { return last_stats_; }

private:
    GenerationManager& gen_mgr_;
    std::optional<DeployStats> last_stats_;
};

} // namespace pktgate::pipeline
