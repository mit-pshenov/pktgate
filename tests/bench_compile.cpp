#include "config/config_parser.hpp"
#include "config/config_validator.hpp"
#include "compiler/object_compiler.hpp"
#include "compiler/rule_compiler.hpp"
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

using namespace pktgate;
using clk = std::chrono::steady_clock;

static auto null_resolver = [](const std::string&) -> uint32_t { return 0; };

/// Generate a config with N L3 subnet rules and M L4 rules (per port group).
static config::Config generate_config(int n_subnets, int n_l4_rules, int ports_per_group) {
    config::Config cfg;
    cfg.default_behavior = config::Action::Drop;
    cfg.interface = "eth0";

    // Generate subnet objects and L3 rules
    for (int i = 0; i < n_subnets; ++i) {
        std::string name = "net_" + std::to_string(i);
        cfg.objects.subnets[name] =
            std::to_string(10 + (i / 65536)) + "." +
            std::to_string((i / 256) % 256) + "." +
            std::to_string(i % 256) + ".0/24";

        config::Rule r;
        r.rule_id = 100 + i;
        r.match.src_ip = "object:" + name;
        r.action = config::Action::Drop;
        cfg.pipeline.layer_3.push_back(r);
    }

    // Generate port groups
    for (int i = 0; i < n_l4_rules; ++i) {
        std::string gname = "pg_" + std::to_string(i);
        std::vector<uint16_t> ports;
        for (int p = 0; p < ports_per_group; ++p)
            ports.push_back(static_cast<uint16_t>(1024 + i * ports_per_group + p));
        cfg.objects.port_groups[gname] = ports;

        config::Rule r;
        r.rule_id = 10000 + i;
        r.match.protocol = (i % 2 == 0) ? "TCP" : "UDP";
        r.match.dst_port = "object:" + gname;
        r.action = config::Action::RateLimit;
        r.params.bandwidth = "1Gbps";
        cfg.pipeline.layer_4.push_back(r);
    }

    // Generate MAC groups
    std::vector<std::string> macs;
    for (int i = 0; i < 100; ++i) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:00:00:00",
                 (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        macs.push_back(buf);
    }
    cfg.objects.mac_groups["bench_group"] = macs;

    config::Rule l2r;
    l2r.rule_id = 1;
    l2r.action = config::Action::Allow;
    l2r.match.src_mac = "object:bench_group";
    l2r.next_layer = "layer_3";
    cfg.pipeline.layer_2.push_back(l2r);

    return cfg;
}

struct BenchResult {
    const char* label;
    int iterations;
    double total_ms;
    double per_iter_us;
};

template <typename Fn>
static BenchResult bench(const char* label, int iters, Fn&& fn) {
    auto start = clk::now();
    for (int i = 0; i < iters; ++i)
        fn();
    auto end = clk::now();
    double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
    return {label, iters, total_ms, (total_ms * 1000.0) / iters};
}

static void print_result(const BenchResult& r) {
    std::printf("  %-40s %6d iters  %8.2f ms total  %8.2f us/iter\n",
                r.label, r.iterations, r.total_ms, r.per_iter_us);
}

int main() {
    std::printf("=== Control Plane Benchmark Suite ===\n\n");

    // ── Small config (typical) ──────────────────────────────
    {
        std::printf("--- Small config: 5 subnets, 5 L4 rules x 3 ports ---\n");
        auto cfg = generate_config(5, 5, 3);

        print_result(bench("validate_config", 10000, [&] {
            auto r = config::validate_config(cfg);
            (void)r;
        }));

        print_result(bench("compile_objects", 10000, [&] {
            auto r = compiler::compile_objects(cfg.objects);
            (void)r;
        }));

        print_result(bench("compile_rules", 10000, [&] {
            auto r = compiler::compile_rules(cfg.pipeline, cfg.objects, null_resolver);
            (void)r;
        }));

        print_result(bench("full_compile (validate+obj+rules)", 10000, [&] {
            config::validate_config(cfg);
            auto o = compiler::compile_objects(cfg.objects);
            auto r = compiler::compile_rules(cfg.pipeline, cfg.objects, null_resolver);
            (void)o; (void)r;
        }));
    }

    std::printf("\n");

    // ── Medium config ───────────────────────────────────────
    {
        std::printf("--- Medium config: 100 subnets, 50 L4 rules x 5 ports ---\n");
        auto cfg = generate_config(100, 50, 5);

        print_result(bench("validate_config", 1000, [&] {
            auto r = config::validate_config(cfg);
            (void)r;
        }));

        print_result(bench("compile_objects", 1000, [&] {
            auto r = compiler::compile_objects(cfg.objects);
            (void)r;
        }));

        print_result(bench("compile_rules", 1000, [&] {
            auto r = compiler::compile_rules(cfg.pipeline, cfg.objects, null_resolver);
            (void)r;
        }));

        print_result(bench("full_compile", 1000, [&] {
            config::validate_config(cfg);
            auto o = compiler::compile_objects(cfg.objects);
            auto r = compiler::compile_rules(cfg.pipeline, cfg.objects, null_resolver);
            (void)o; (void)r;
        }));
    }

    std::printf("\n");

    // ── Large config (stress) ───────────────────────────────
    {
        std::printf("--- Large config: 1000 subnets, 200 L4 rules x 10 ports ---\n");
        auto cfg = generate_config(1000, 200, 10);

        print_result(bench("validate_config", 100, [&] {
            auto r = config::validate_config(cfg);
            (void)r;
        }));

        print_result(bench("compile_objects", 100, [&] {
            auto r = compiler::compile_objects(cfg.objects);
            (void)r;
        }));

        print_result(bench("compile_rules", 100, [&] {
            auto r = compiler::compile_rules(cfg.pipeline, cfg.objects, null_resolver);
            (void)r;
        }));

        print_result(bench("full_compile", 100, [&] {
            config::validate_config(cfg);
            auto o = compiler::compile_objects(cfg.objects);
            auto r = compiler::compile_rules(cfg.pipeline, cfg.objects, null_resolver);
            (void)o; (void)r;
        }));
    }

    std::printf("\n");

    // ── JSON parsing benchmark ──────────────────────────────
    {
        std::printf("--- JSON parse benchmark ---\n");
        auto cfg = generate_config(100, 50, 5);

        // Serialize to JSON string (manual for benchmark)
        std::string json_str = R"({"device_info":{"interface":"eth0"},"objects":{"subnets":{)";
        for (auto& [k, v] : cfg.objects.subnets)
            json_str += "\"" + k + "\":\"" + v + "\",";
        if (!cfg.objects.subnets.empty()) json_str.pop_back();
        json_str += "},\"mac_groups\":{},\"port_groups\":{";
        for (auto& [k, ports] : cfg.objects.port_groups) {
            json_str += "\"" + k + "\":[";
            for (auto p : ports)
                json_str += std::to_string(p) + ",";
            if (!ports.empty()) json_str.pop_back();
            json_str += "],";
        }
        if (!cfg.objects.port_groups.empty()) json_str.pop_back();
        json_str += "}},\"pipeline\":{\"layer_3\":[";
        for (auto& r : cfg.pipeline.layer_3) {
            json_str += "{\"rule_id\":" + std::to_string(r.rule_id) +
                        ",\"action\":\"drop\",\"match\":{\"src_ip\":\"" +
                        *r.match.src_ip + "\"}},";
        }
        if (!cfg.pipeline.layer_3.empty()) json_str.pop_back();
        json_str += "],\"layer_4\":[";
        for (auto& r : cfg.pipeline.layer_4) {
            json_str += "{\"rule_id\":" + std::to_string(r.rule_id) +
                        ",\"action\":\"rate-limit\",\"match\":{\"protocol\":\"" +
                        *r.match.protocol + "\",\"dst_port\":\"" +
                        *r.match.dst_port + "\"},\"action_params\":{\"bandwidth\":\"1Gbps\"}},";
        }
        if (!cfg.pipeline.layer_4.empty()) json_str.pop_back();
        json_str += "]},\"default_behavior\":\"drop\"}";

        std::printf("  JSON size: %zu bytes\n", json_str.size());

        print_result(bench("parse_config_string", 1000, [&] {
            auto r = config::parse_config_string(json_str);
            (void)r;
        }));
    }

    std::printf("\n=== Benchmark complete ===\n");
    return 0;
}
