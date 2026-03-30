#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>

namespace pktgate::pipeline {

/// Deployment timing and rule statistics.
struct DeployStats {
    // Timing
    std::chrono::microseconds validation_us{};
    std::chrono::microseconds object_compile_us{};
    std::chrono::microseconds rule_compile_us{};
    std::chrono::microseconds map_populate_us{};
    std::chrono::microseconds commit_us{};
    std::chrono::microseconds total_us{};

    // Counts
    uint32_t mac_entries     = 0;
    uint32_t subnet_entries  = 0;
    uint32_t vrf_entries     = 0;
    uint32_t l4_entries      = 0;
    uint32_t l3_rules_total  = 0;
    uint32_t l4_rules_total  = 0;
    uint32_t target_gen      = 0;

    void print() const {
        std::fprintf(stderr,
            "[STATS] Deploy gen=%u: total=%lld us\n"
            "  validation:    %6lld us\n"
            "  obj_compile:   %6lld us\n"
            "  rule_compile:  %6lld us\n"
            "  map_populate:  %6lld us\n"
            "  commit:        %6lld us\n"
            "  entries: mac=%u subnet=%u vrf=%u l4=%u\n"
            "  rules: L3=%u L4=%u\n",
            target_gen,
            static_cast<long long>(total_us.count()),
            static_cast<long long>(validation_us.count()),
            static_cast<long long>(object_compile_us.count()),
            static_cast<long long>(rule_compile_us.count()),
            static_cast<long long>(map_populate_us.count()),
            static_cast<long long>(commit_us.count()),
            mac_entries, subnet_entries, vrf_entries, l4_entries,
            l3_rules_total, l4_rules_total);
    }
};

/// RAII timer for measuring a duration into a target field.
class ScopedTimer {
public:
    explicit ScopedTimer(std::chrono::microseconds& target)
        : target_(target), start_(std::chrono::steady_clock::now()) {}

    ~ScopedTimer() {
        auto end = std::chrono::steady_clock::now();
        target_ = std::chrono::duration_cast<std::chrono::microseconds>(end - start_);
    }

    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;

private:
    std::chrono::microseconds& target_;
    std::chrono::steady_clock::time_point start_;
};

} // namespace pktgate::pipeline
