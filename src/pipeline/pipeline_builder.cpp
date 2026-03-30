#include "pipeline/pipeline_builder.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include "config/config_validator.hpp"
#include "util/log.hpp"

namespace pktgate::pipeline {

PipelineBuilder::PipelineBuilder(loader::BpfLoader& loader,
                                 GenerationManager& gen_mgr)
    : loader_(loader), gen_mgr_(gen_mgr) {}

std::expected<void, std::string>
PipelineBuilder::deploy(const config::Config& cfg,
                        compiler::IfindexResolver resolver) {
    DeployStats stats;
    ScopedTimer total_timer(stats.total_us);

    // Step 0: Validate config semantics
    {
        ScopedTimer t(stats.validation_us);
        auto vr = config::validate_config(cfg);
        if (!vr) {
            std::string msg = "Config validation failed:";
            for (auto& e : vr.error())
                msg += "\n  " + e.rule_context + ": " + e.message;
            return std::unexpected(std::move(msg));
        }
    }

    // Step 1: Compile objects
    compiler::CompiledObjects objs_val;
    {
        ScopedTimer t(stats.object_compile_us);
        auto objs = compiler::compile_objects(cfg.objects);
        if (!objs)
            return std::unexpected("Object compilation: " + objs.error());
        objs_val = std::move(*objs);
    }
    stats.mac_entries = static_cast<uint32_t>(objs_val.macs.size());
    stats.subnet_entries = static_cast<uint32_t>(objs_val.subnets.size());

    // Step 2: Compile rules
    compiler::CompiledRules rules_val;
    {
        ScopedTimer t(stats.rule_compile_us);
        auto rules = compiler::compile_rules(cfg.pipeline, cfg.objects, resolver);
        if (!rules)
            return std::unexpected("Rule compilation: " + rules.error());
        rules_val = std::move(*rules);
    }
    stats.l3_rules_total = static_cast<uint32_t>(rules_val.l3_rules.size());
    stats.l4_rules_total = static_cast<uint32_t>(rules_val.l4_rules.size());
    stats.l4_entries = stats.l4_rules_total;

    // Count VRF entries
    for (auto& r : rules_val.l3_rules)
        if (r.is_vrf_rule) ++stats.vrf_entries;

    // Step 3: Prepare shadow generation
    {
        ScopedTimer t(stats.map_populate_us);
        auto r = gen_mgr_.prepare(objs_val, rules_val, cfg.default_behavior);
        if (!r)
            return std::unexpected("Prepare: " + r.error());
    }

    // Step 4: Commit (atomic switch)
    {
        ScopedTimer t(stats.commit_us);
        auto r = gen_mgr_.commit();
        if (!r)
            return std::unexpected("Commit: " + r.error());
    }

    stats.target_gen = gen_mgr_.active_generation();
    last_stats_ = stats;
    stats.print();

    LOG_INF("Pipeline deployed: L3 rules=%u, L4 rules=%u, MACs=%u",
            stats.l3_rules_total, stats.l4_rules_total, stats.mac_entries);
    return {};
}

} // namespace pktgate::pipeline
