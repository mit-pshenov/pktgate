#include "../src/metrics/prometheus_exporter.hpp"
#include "../src/loader/bpf_loader.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static int passed = 0;
static int failed = 0;

#define TEST(name) static void name()
#define RUN(name) do { \
    std::printf("  %-50s ", #name); \
    try { name(); std::printf("PASS\n"); passed++; } \
    catch (const std::exception& e) { std::printf("FAIL: %s\n", e.what()); failed++; } \
    catch (...) { std::printf("FAIL: unknown\n"); failed++; } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) throw std::runtime_error("assert: " #cond); } while(0)

/// Fetch HTTP response from localhost:port, return full response.
static std::string http_get(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT(fd >= 0);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc < 0) { ::close(fd); return ""; }

    const char* req = "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
    ::send(fd, req, strlen(req), 0);

    std::string response;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, n);
    }
    ::close(fd);
    return response;
}

// ── Tests ────────────────────────────────────────────────────

// BpfLoader without load() — stats_map_fd() returns -1.
// Exporter handles this gracefully.

TEST(test_exporter_starts_and_stops) {
    pktgate::loader::BpfLoader loader;  // not loaded — fd=-1
    pktgate::metrics::PrometheusExporter exp(loader.registry(),19090);
    ASSERT(exp.start());
    exp.stop();
}

TEST(test_exporter_responds_http) {
    pktgate::loader::BpfLoader loader;
    pktgate::metrics::PrometheusExporter exp(loader.registry(),19091);
    ASSERT(exp.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto resp = http_get(19091);
    ASSERT(!resp.empty());
    ASSERT(resp.find("HTTP/1.1 200 OK") != std::string::npos);
    ASSERT(resp.find("text/plain") != std::string::npos);

    exp.stop();
}

TEST(test_metrics_fallback_no_bpf) {
    pktgate::loader::BpfLoader loader;
    pktgate::metrics::PrometheusExporter exp(loader.registry(),19092);
    ASSERT(exp.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto resp = http_get(19092);
    // Without loaded BPF, stats_map_fd() == -1 → fallback message
    ASSERT(resp.find("stats_map not available") != std::string::npos);

    exp.stop();
}

TEST(test_multiple_scrapes) {
    pktgate::loader::BpfLoader loader;
    pktgate::metrics::PrometheusExporter exp(loader.registry(),19093);
    ASSERT(exp.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    for (int i = 0; i < 5; i++) {
        auto resp = http_get(19093);
        ASSERT(resp.find("200 OK") != std::string::npos);
    }

    exp.stop();
}

TEST(test_port_in_use) {
    pktgate::loader::BpfLoader loader;
    pktgate::metrics::PrometheusExporter exp1(loader.registry(),19094);
    ASSERT(exp1.start());

    pktgate::metrics::PrometheusExporter exp2(loader.registry(),19094);
    ASSERT(!exp2.start());

    exp1.stop();
}

TEST(test_metric_desc_coverage) {
    // Verify all STAT__MAX keys are covered in kMetrics
    bool covered[STAT__MAX] = {};
    for (size_t i = 0; i < pktgate::metrics::kNumMetrics; i++) {
        ASSERT(pktgate::metrics::kMetrics[i].key < STAT__MAX);
        covered[pktgate::metrics::kMetrics[i].key] = true;
    }
    for (uint32_t k = 0; k < STAT__MAX; k++) {
        if (!covered[k]) {
            char msg[128];
            snprintf(msg, sizeof(msg), "stat_key %u not covered by kMetrics", k);
            throw std::runtime_error(msg);
        }
    }
}

TEST(test_concurrent_scrapes) {
    pktgate::loader::BpfLoader loader;
    pktgate::metrics::PrometheusExporter exp(loader.registry(),19095);
    ASSERT(exp.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::vector<std::thread> threads;
    std::atomic<int> ok_count{0};
    for (int i = 0; i < 8; i++) {
        threads.emplace_back([&ok_count]() {
            auto resp = http_get(19095);
            if (resp.find("200 OK") != std::string::npos)
                ok_count.fetch_add(1);
        });
    }
    for (auto& t : threads) t.join();
    ASSERT(ok_count.load() == 8);

    exp.stop();
}

int main() {
    std::printf("test_prometheus (7 tests):\n");
    RUN(test_exporter_starts_and_stops);
    RUN(test_exporter_responds_http);
    RUN(test_metrics_fallback_no_bpf);
    RUN(test_multiple_scrapes);
    RUN(test_port_in_use);
    RUN(test_metric_desc_coverage);
    RUN(test_concurrent_scrapes);

    std::printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
