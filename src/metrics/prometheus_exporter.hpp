#pragma once

#include "../loader/map_registry.hpp"
#include "../../bpf/common.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

namespace pktgate::metrics {

/// Metric descriptor: maps stat_key enum → Prometheus metric name + labels.
struct MetricDesc {
    uint32_t    key;
    const char* name;
    const char* help;
    const char* type;   // "counter" or "gauge"
};

// All 35 counters mapped to Prometheus metrics with sensible names.
// Using a flat list — simple, fast, no allocations on scrape.
static constexpr MetricDesc kMetrics[] = {
    // ── Global ──
    {STAT_PACKETS_TOTAL,          "pktgate_packets_total",
     "Total packets entering XDP pipeline", "counter"},

    // ── Entry drops ──
    {STAT_DROP_NO_GEN,            "pktgate_drop_total{layer=\"entry\",reason=\"no_gen\"}",
     nullptr, "counter"},
    {STAT_DROP_NO_META,           "pktgate_drop_total{layer=\"entry\",reason=\"no_meta\"}",
     nullptr, "counter"},
    {STAT_DROP_ENTRY_TAIL,        "pktgate_drop_total{layer=\"entry\",reason=\"tail_fail\"}",
     nullptr, "counter"},

    // ── L2 drops ──
    {STAT_DROP_L2_BOUNDS,         "pktgate_drop_total{layer=\"l2\",reason=\"bounds\"}",
     nullptr, "counter"},
    {STAT_DROP_L2_NO_META,        "pktgate_drop_total{layer=\"l2\",reason=\"no_meta\"}",
     nullptr, "counter"},
    {STAT_DROP_L2_NO_MAC,         "pktgate_drop_total{layer=\"l2\",reason=\"no_mac\"}",
     nullptr, "counter"},
    {STAT_DROP_L2_TAIL,           "pktgate_drop_total{layer=\"l2\",reason=\"tail_fail\"}",
     nullptr, "counter"},

    // ── L3 drops ──
    {STAT_DROP_L3_BOUNDS,         "pktgate_drop_total{layer=\"l3\",reason=\"bounds\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_NOT_IPV4,       "pktgate_drop_total{layer=\"l3\",reason=\"not_ipv4\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_NO_META,        "pktgate_drop_total{layer=\"l3\",reason=\"no_meta\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_RULE,           "pktgate_drop_total{layer=\"l3\",reason=\"rule\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_DEFAULT,        "pktgate_drop_total{layer=\"l3\",reason=\"default\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_REDIRECT_FAIL,  "pktgate_drop_total{layer=\"l3\",reason=\"redirect_fail\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_TAIL,           "pktgate_drop_total{layer=\"l3\",reason=\"tail_fail\"}",
     nullptr, "counter"},

    // ── L4 drops ──
    {STAT_DROP_L4_BOUNDS,         "pktgate_drop_total{layer=\"l4\",reason=\"bounds\"}",
     nullptr, "counter"},
    {STAT_DROP_L4_RULE,           "pktgate_drop_total{layer=\"l4\",reason=\"rule\"}",
     nullptr, "counter"},
    {STAT_DROP_L4_DEFAULT,        "pktgate_drop_total{layer=\"l4\",reason=\"default\"}",
     nullptr, "counter"},
    {STAT_DROP_L4_RATE_LIMIT,     "pktgate_drop_total{layer=\"l4\",reason=\"rate_limited\"}",
     nullptr, "counter"},
    {STAT_DROP_L4_NO_META,        "pktgate_drop_total{layer=\"l4\",reason=\"no_meta\"}",
     nullptr, "counter"},

    // ── Pass / Actions ──
    {STAT_PASS_L3,                "pktgate_pass_total{layer=\"l3\"}",
     nullptr, "counter"},
    {STAT_PASS_L4,                "pktgate_pass_total{layer=\"l4\"}",
     nullptr, "counter"},
    {STAT_REDIRECT,               "pktgate_action_total{action=\"redirect\"}",
     nullptr, "counter"},
    {STAT_MIRROR,                 "pktgate_action_total{action=\"mirror\"}",
     nullptr, "counter"},
    {STAT_TAG,                    "pktgate_action_total{action=\"tag\"}",
     nullptr, "counter"},
    {STAT_RATE_LIMIT_PASS,        "pktgate_action_total{action=\"rate_limit_pass\"}",
     nullptr, "counter"},

    // ── TC ingress ──
    {STAT_TC_MIRROR,              "pktgate_tc_total{action=\"mirror\"}",
     nullptr, "counter"},
    {STAT_TC_MIRROR_FAIL,         "pktgate_tc_total{action=\"mirror_fail\"}",
     nullptr, "counter"},
    {STAT_TC_TAG,                 "pktgate_tc_total{action=\"tag\"}",
     nullptr, "counter"},
    {STAT_TC_NOOP,                "pktgate_tc_total{action=\"noop\"}",
     nullptr, "counter"},

    // ── Additional ──
    {STAT_DROP_L3_FRAGMENT,       "pktgate_drop_total{layer=\"l3\",reason=\"fragment\"}",
     nullptr, "counter"},
    {STAT_DROP_L4_NOT_IPV4,       "pktgate_drop_total{layer=\"l4\",reason=\"not_ipv4\"}",
     nullptr, "counter"},

    // ── IPv6 ──
    {STAT_PASS_L3_V6,             "pktgate_pass_total{layer=\"l3v6\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_V6_RULE,        "pktgate_drop_total{layer=\"l3v6\",reason=\"rule\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_V6_DEFAULT,     "pktgate_drop_total{layer=\"l3v6\",reason=\"default\"}",
     nullptr, "counter"},
    {STAT_DROP_L3_V6_FRAGMENT,    "pktgate_drop_total{layer=\"l3v6\",reason=\"fragment\"}",
     nullptr, "counter"},
    {STAT_DROP_L4_V6_FRAGMENT,    "pktgate_drop_total{layer=\"l4\",reason=\"v6_fragment\"}",
     nullptr, "counter"},

    // ── AF_XDP userspace ──
    {STAT_USERSPACE,              "pktgate_action_total{action=\"userspace\"}",
     nullptr, "counter"},
    {STAT_USERSPACE_FAIL,         "pktgate_action_total{action=\"userspace_fail\"}",
     nullptr, "counter"},
};

static_assert(sizeof(kMetrics) / sizeof(kMetrics[0]) == STAT__MAX,
              "kMetrics must cover every stat_key — update after adding new counters");

static constexpr size_t kNumMetrics = sizeof(kMetrics) / sizeof(kMetrics[0]);

/// Minimal HTTP server that serves /metrics in Prometheus text format.
/// Runs in a background thread. Thread-safe: only reads BPF maps (lockless percpu).
class PrometheusExporter {
public:
    PrometheusExporter(const loader::MapRegistry& registry, uint16_t port)
        : registry_(registry), port_(port) {}

    ~PrometheusExporter() { stop(); }

    PrometheusExporter(const PrometheusExporter&) = delete;
    PrometheusExporter& operator=(const PrometheusExporter&) = delete;

    /// Start the HTTP server thread.
    bool start() {
        listen_fd_ = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;

        // Dual-stack: accept both IPv4 and IPv6
        int off = 0;
        setsockopt(listen_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        int on = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        struct sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(port_);
        addr.sin6_addr   = in6addr_any;

        if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        if (::listen(listen_fd_, 8) < 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        running_.store(true, std::memory_order_release);
        thread_ = std::thread(&PrometheusExporter::serve_loop, this);
        return true;
    }

    void stop() {
        running_.store(false, std::memory_order_release);
        if (listen_fd_ >= 0) {
            ::shutdown(listen_fd_, SHUT_RDWR);
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
        if (thread_.joinable())
            thread_.join();
    }

    uint16_t port() const { return port_; }

private:
    void serve_loop() {
        while (running_.load(std::memory_order_acquire)) {
            struct pollfd pfd{listen_fd_, POLLIN, 0};
            int ret = ::poll(&pfd, 1, 500);  // 500ms timeout for clean shutdown
            if (ret <= 0) continue;

            int client = ::accept(listen_fd_, nullptr, nullptr);
            if (client < 0) continue;

            handle_client(client);
            ::close(client);
        }
    }

    void handle_client(int fd) {
        // Read request (just drain it — we serve any GET as /metrics)
        char req[1024];
        ::recv(fd, req, sizeof(req), 0);

        // Build metrics body
        std::string body = build_metrics();

        // HTTP response
        char header[256];
        int hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n",
            body.size());

        ::send(fd, header, hlen, MSG_NOSIGNAL);
        ::send(fd, body.data(), body.size(), MSG_NOSIGNAL);
    }

    std::string build_metrics() {
        int fd = registry_.stats_map_fd();
        if (fd < 0)
            return "# stats_map not available\n";

        int ncpus = libbpf_num_possible_cpus();
        if (ncpus <= 0)
            return "# no CPUs detected\n";

        // Read all counters
        std::vector<uint64_t> percpu(ncpus);
        std::array<uint64_t, STAT__MAX> totals{};

        for (uint32_t k = 0; k < STAT__MAX; k++) {
            if (bpf_map_lookup_elem(fd, &k, percpu.data()) == 0) {
                for (int c = 0; c < ncpus; c++)
                    totals[k] += percpu[c];
            }
        }

        // Format Prometheus text exposition
        std::string out;
        out.reserve(4096);

        // HELP/TYPE headers for metric families
        out += "# HELP pktgate_packets_total Total packets entering XDP pipeline\n";
        out += "# TYPE pktgate_packets_total counter\n";
        out += "# HELP pktgate_drop_total Packets dropped by layer and reason\n";
        out += "# TYPE pktgate_drop_total counter\n";
        out += "# HELP pktgate_pass_total Packets passed by layer\n";
        out += "# TYPE pktgate_pass_total counter\n";
        out += "# HELP pktgate_action_total Action executions by type\n";
        out += "# TYPE pktgate_action_total counter\n";
        out += "# HELP pktgate_tc_total TC ingress actions\n";
        out += "# TYPE pktgate_tc_total counter\n";

        // Metric values
        char line[256];
        for (size_t i = 0; i < kNumMetrics; i++) {
            int n = snprintf(line, sizeof(line), "%s %llu\n",
                             kMetrics[i].name,
                             (unsigned long long)totals[kMetrics[i].key]);
            out.append(line, n);
        }

        return out;
    }

    const loader::MapRegistry& registry_;
    uint16_t port_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

}  // namespace pktgate::metrics
