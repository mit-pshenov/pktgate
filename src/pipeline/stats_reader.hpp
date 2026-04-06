#pragma once

#include "loader/bpf_loader.hpp"
#include "../../bpf/common.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdint>
#include <cstdio>
#include <unistd.h>
#include <array>
#include <vector>

namespace pktgate::pipeline {

/// Reads BPF per-CPU stats map and prints aggregated counters.
class StatsReader {
public:
    explicit StatsReader(loader::BpfLoader& loader) : loader_(loader) {}

    /// Read all counters, sum across CPUs, print to stderr.
    void print() const {
        int fd = loader_.stats_map_fd();
        if (fd < 0) {
            std::fprintf(stderr, "[STATS] stats_map not available\n");
            return;
        }

        int ncpus = libbpf_num_possible_cpus();
        if (ncpus <= 0) return;

        // Per-CPU values buffer
        std::vector<uint64_t> values(ncpus);
        std::array<uint64_t, STAT__MAX> totals{};

        for (uint32_t k = 0; k < STAT__MAX; k++) {
            if (bpf_map_lookup_elem(fd, &k, values.data()) == 0) {
                for (int c = 0; c < ncpus; c++)
                    totals[k] += values[c];
            }
        }

        std::fprintf(stderr,
            "\n[STATS] Packet statistics:\n"
            "  packets_total:        %llu\n"
            "\n"
            "  --- Drops ---\n"
            "  entry/no_gen:         %llu\n"
            "  entry/no_meta:        %llu\n"
            "  entry/tail_fail:      %llu\n"
            "  l2/bounds:            %llu\n"
            "  l2/no_meta:           %llu\n"
            "  l2/no_mac:            %llu\n"
            "  l2/tail_fail:         %llu\n"
            "  l3/bounds:            %llu\n"
            "  l3/not_ipv4:          %llu\n"
            "  l3/no_meta:           %llu\n"
            "  l3/rule_drop:         %llu\n"
            "  l3/default_drop:      %llu\n"
            "  l3/redirect_fail:     %llu\n"
            "  l3/tail_fail:         %llu\n"
            "  l4/bounds:            %llu\n"
            "  l4/rule_drop:         %llu\n"
            "  l4/default_drop:      %llu\n"
            "  l4/rate_limited:      %llu\n"
            "  l4/no_meta:           %llu\n"
            "\n"
            "  --- Pass/Actions ---\n"
            "  l3/pass:              %llu\n"
            "  l4/pass:              %llu\n"
            "  redirect:             %llu\n"
            "  mirror:               %llu\n"
            "  tag:                  %llu\n"
            "  rate_limit/pass:      %llu\n"
            "\n"
            "  --- TC Ingress ---\n"
            "  tc/mirror:            %llu\n"
            "  tc/mirror_fail:       %llu\n"
            "  tc/tag:               %llu\n"
            "  tc/noop:              %llu\n"
            "\n"
            "  --- IPv6 ---\n"
            "  l3v6/pass:            %llu\n"
            "  l3v6/rule_drop:       %llu\n"
            "  l3v6/default_drop:    %llu\n"
            "  l3v6/fragment:        %llu\n"
            "  l4/v6_fragment:       %llu\n"
            "\n"
            "  --- Additional ---\n"
            "  l3/fragment:          %llu\n"
            "  l4/not_ipv4:          %llu\n",
            (unsigned long long)totals[STAT_PACKETS_TOTAL],
            (unsigned long long)totals[STAT_DROP_NO_GEN],
            (unsigned long long)totals[STAT_DROP_NO_META],
            (unsigned long long)totals[STAT_DROP_ENTRY_TAIL],
            (unsigned long long)totals[STAT_DROP_L2_BOUNDS],
            (unsigned long long)totals[STAT_DROP_L2_NO_META],
            (unsigned long long)totals[STAT_DROP_L2_NO_MATCH],
            (unsigned long long)totals[STAT_DROP_L2_TAIL],
            (unsigned long long)totals[STAT_DROP_L3_BOUNDS],
            (unsigned long long)totals[STAT_DROP_L3_NOT_IPV4],
            (unsigned long long)totals[STAT_DROP_L3_NO_META],
            (unsigned long long)totals[STAT_DROP_L3_RULE],
            (unsigned long long)totals[STAT_DROP_L3_DEFAULT],
            (unsigned long long)totals[STAT_DROP_L3_REDIRECT_FAIL],
            (unsigned long long)totals[STAT_DROP_L3_TAIL],
            (unsigned long long)totals[STAT_DROP_L4_BOUNDS],
            (unsigned long long)totals[STAT_DROP_L4_RULE],
            (unsigned long long)totals[STAT_DROP_L4_DEFAULT],
            (unsigned long long)totals[STAT_DROP_L4_RATE_LIMIT],
            (unsigned long long)totals[STAT_DROP_L4_NO_META],
            (unsigned long long)totals[STAT_PASS_L3],
            (unsigned long long)totals[STAT_PASS_L4],
            (unsigned long long)totals[STAT_REDIRECT],
            (unsigned long long)totals[STAT_MIRROR],
            (unsigned long long)totals[STAT_TAG],
            (unsigned long long)totals[STAT_RATE_LIMIT_PASS],
            (unsigned long long)totals[STAT_TC_MIRROR],
            (unsigned long long)totals[STAT_TC_MIRROR_FAIL],
            (unsigned long long)totals[STAT_TC_TAG],
            (unsigned long long)totals[STAT_TC_NOOP],
            (unsigned long long)totals[STAT_PASS_L3_V6],
            (unsigned long long)totals[STAT_DROP_L3_V6_RULE],
            (unsigned long long)totals[STAT_DROP_L3_V6_DEFAULT],
            (unsigned long long)totals[STAT_DROP_L3_V6_FRAGMENT],
            (unsigned long long)totals[STAT_DROP_L4_V6_FRAGMENT],
            (unsigned long long)totals[STAT_DROP_L3_FRAGMENT],
            (unsigned long long)totals[STAT_DROP_L4_NOT_IPV4]);
    }

private:
    loader::BpfLoader& loader_;
};

} // namespace pktgate::pipeline
