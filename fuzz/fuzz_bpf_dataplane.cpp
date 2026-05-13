/*
 * Fuzz harness for the XDP data plane.
 *
 * Setup (LLVMFuzzerInitialize): load BpfLoader and deploy a "thick"
 * reference config (L2 mac filter + L3 src/dst + L4 TCP/UDP + rate-limit
 * + DSCP tag + default drop). The deploy stays alive for the entire
 * fuzz run — every iteration shares the same loaded programs and maps.
 *
 * Iteration (LLVMFuzzerTestOneInput): take arbitrary bytes, treat them
 * as a raw L2 frame, run them through entry_prog via BPF_PROG_TEST_RUN,
 * and assert:
 *   - bpf_prog_test_run_opts returned 0 (the BPF syscall itself OK —
 *     a -E* return means the program faulted somewhere)
 *   - retval ∈ {XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT}
 *
 * What this catches: kernel-level OOB reads, verifier-exits that only
 * surface at runtime (unaligned access, packet_end bounds violations),
 * regressions in malformed-packet handling.
 *
 * Privileges: BPF_PROG_TEST_RUN needs CAP_BPF (or root). LLVMFuzzerInitialize
 * exits 77 (ctest "skip") when load fails so the binary is a no-op under
 * unprivileged CI runners. The overnight fuzz job runs as the GH runner
 * user, which has passwordless sudo and effectively CAP_BPF.
 *
 * Coverage non-goal: this is an adversarial input fuzzer, NOT a property
 * fuzzer over compiled rule sets. The config is deliberately fixed so
 * each iteration touches the same code paths under different packet
 * shapes.
 */
#include "config/config_parser.hpp"
#include "loader/bpf_loader.hpp"
#include "pipeline/generation_manager.hpp"
#include "pipeline/pipeline_builder.hpp"
#include "../bpf/common.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

// "Thick" reference config — exercises every action and both IP families.
// Action params resolve through a mock ifindex resolver so resolver=42
// suffices for every name (Mirror target_port, Redirect target_vrf).
static const char* kFuzzConfig = R"({
  "device_info": { "interface": "lo", "capacity": "1Gbps" },
  "objects": {
    "subnets":  {
      "client_v4":  "10.0.0.0/8",
      "blocked_v4": "192.0.2.0/24",
      "dst_block":  "172.16.0.0/16"
    },
    "subnets6": {
      "client_v6":  "fd00::/8",
      "blocked_v6": "2001:db8::/32"
    },
    "mac_groups": {
      "allowed":  ["aa:bb:cc:dd:ee:01"],
      "blocked":  ["00:de:ad:be:ef:00"]
    },
    "port_groups": {
      "web": [80, 443],
      "dns": [53]
    }
  },
  "pipeline": {
    "layer_2": [
      { "rule_id": 1, "match": {"src_mac": "object:allowed"},
        "action": "allow", "next_layer": "layer_3" },
      { "rule_id": 2, "match": {"src_mac": "object:blocked"},
        "action": "drop" },
      { "rule_id": 3, "match": {"vlan_id": 100, "ethertype": "IPv4"},
        "action": "allow", "next_layer": "layer_3" }
    ],
    "layer_3": [
      { "rule_id": 100, "match": {"src_ip":  "object:blocked_v4"},
        "action": "drop" },
      { "rule_id": 101, "match": {"src_ip":  "object:client_v4"},
        "action": "allow", "next_layer": "layer_4" },
      { "rule_id": 102, "match": {"dst_ip":  "object:dst_block"},
        "action": "drop" },
      { "rule_id": 103, "match": {"src_ip6": "object6:blocked_v6"},
        "action": "drop" },
      { "rule_id": 104, "match": {"src_ip6": "object6:client_v6"},
        "action": "allow", "next_layer": "layer_4" }
    ],
    "layer_4": [
      { "rule_id": 1000, "match": {"protocol": "TCP", "dst_port": "object:web"},
        "action": "allow" },
      { "rule_id": 1001, "match": {"protocol": "UDP", "dst_port": "object:dns"},
        "action": "tag",  "action_params": {"dscp": "EF"} },
      { "rule_id": 1002, "match": {"protocol": "TCP", "dst_port": "8080",
                                   "tcp_flags": "SYN,!ACK"},
        "action": "drop" }
    ]
  },
  "default_behavior": "drop"
})";

static std::unique_ptr<pktgate::loader::BpfLoader>          g_loader;
static std::unique_ptr<pktgate::pipeline::GenerationManager> g_gen;
static std::unique_ptr<pktgate::pipeline::PipelineBuilder>   g_builder;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    auto cfg = pktgate::config::parse_config_string(kFuzzConfig);
    if (!cfg) {
        std::fprintf(stderr, "fuzz_bpf_dataplane: kFuzzConfig parse failed: %s\n",
                     cfg.error().c_str());
        std::exit(1);
    }

    g_loader = std::make_unique<pktgate::loader::BpfLoader>();
    auto lr = g_loader->load();
    if (!lr) {
        std::fprintf(stderr,
            "fuzz_bpf_dataplane: BpfLoader::load failed (likely missing CAP_BPF): %s\n",
            lr.error().c_str());
        // exit 77 = ctest "skip"; libFuzzer reports it as harness setup-failure.
        std::exit(77);
    }

    g_gen     = std::make_unique<pktgate::pipeline::GenerationManager>(*g_loader);
    g_builder = std::make_unique<pktgate::pipeline::PipelineBuilder>(*g_loader, *g_gen);

    // Resolver: every name → 42. Tests don't exercise actual ifindex
    // semantics; this just unblocks Mirror / Redirect rule compilation.
    pktgate::compiler::IfindexResolver resolver =
        [](const std::string&) -> uint32_t { return 42; };

    auto dr = g_builder->deploy(*cfg, resolver);
    if (!dr) {
        std::fprintf(stderr, "fuzz_bpf_dataplane: deploy failed: %s\n",
                     dr.error().c_str());
        std::exit(1);
    }
    return 0;
}

// Valid XDP retvals: ABORTED(0), DROP(1), PASS(2), TX(3), REDIRECT(4).
static constexpr __u32 kMaxValidXdpRetval = 4;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum: ETH header (14 bytes). Maximum: typical MTU + slack.
    // BPF_PROG_TEST_RUN rejects out-of-range sizes with -EINVAL.
    if (size < 14 || size > 1500) return 0;

    uint8_t out_buf[2048];
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in       = data,
        .data_out      = out_buf,
        .data_size_in  = static_cast<__u32>(size),
        .data_size_out = sizeof(out_buf),
        .repeat        = 1,
    );

    int err = bpf_prog_test_run_opts(g_loader->entry_prog_fd(), &opts);
    if (err < 0) {
        // -ENOSPC for data_out too small is a harness bug, not a finding.
        // Any other error means the program triggered a kernel-side fault.
        if (err == -ENOSPC) return 0;
        std::fprintf(stderr, "fuzz_bpf_dataplane: PROG_TEST_RUN err=%d (size=%zu)\n",
                     err, size);
        std::abort();
    }

    if (opts.retval > kMaxValidXdpRetval) {
        std::fprintf(stderr,
            "fuzz_bpf_dataplane: invalid XDP retval %u (size=%zu) — outside {0..4}\n",
            opts.retval, size);
        std::abort();
    }
    return 0;
}

#ifdef FUZZ_STANDALONE
#include <iostream>
#include <iterator>
int main(int argc, char** argv) {
    LLVMFuzzerInitialize(&argc, &argv);
    std::string input((std::istreambuf_iterator<char>(std::cin)),
                       std::istreambuf_iterator<char>());
    return LLVMFuzzerTestOneInput(
        reinterpret_cast<const uint8_t*>(input.data()), input.size());
}
#endif
