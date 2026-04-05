#include "config/config_parser.hpp"
#include "loader/bpf_loader.hpp"
#include "pipeline/generation_manager.hpp"
#include "pipeline/pipeline_builder.hpp"
#include "pipeline/stats_reader.hpp"
#include "metrics/prometheus_exporter.hpp"
#include "xdp/xdp_socket_manager.hpp"
#include "util/log.hpp"
#include "util/net_types.hpp"
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <cstring>

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_dump_stats = 0;
static volatile sig_atomic_t g_reload = 0;

static void sig_handler(int) { g_running = 0; }
static void sigusr1_handler(int) { g_dump_stats = 1; }
static void sighup_handler(int) { g_reload = 1; }

/// Attempt to reload config and deploy to shadow generation.
/// On failure, active generation is untouched — traffic keeps flowing.
/// Guard prevents re-entrant calls (SIGHUP arriving during inotify reload).
static void do_reload(const char* config_path,
                      pktgate::pipeline::PipelineBuilder& builder,
                      pktgate::compiler::IfindexResolver& resolver) {
    static bool reloading = false;
    if (reloading) {
        LOG_WRN("Reload already in progress, skipping");
        return;
    }
    reloading = true;
    LOG_INF("Reloading config from %s ...", config_path);

    auto result = pktgate::config::parse_config(config_path);
    if (!result) {
        LOG_ERR("Reload: parse failed: %s", result.error().c_str());
        reloading = false;
        return;
    }

    auto& cfg = *result;
    auto dr = builder.deploy(cfg, resolver);
    if (!dr) {
        LOG_ERR("Reload: deploy failed: %s", dr.error().c_str());
        reloading = false;
        return;
    }

    LOG_INF("Reload: success — L2=%zu, L3=%zu, L4=%zu",
            cfg.pipeline.layer_2.size(),
            cfg.pipeline.layer_3.size(),
            cfg.pipeline.layer_4.size());
    reloading = false;
}

/// Setup inotify watch on config file. Returns inotify fd (or -1 on failure).
static int setup_inotify(const char* config_path) {
    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0) {
        LOG_WRN("inotify_init failed: %s — file watch disabled", std::strerror(errno));
        return -1;
    }

    /*
     * Watch the directory containing the config file, not the file itself.
     * Many editors (vim, sed -i) replace the file atomically: write tmp → rename.
     * This breaks IN_MODIFY on the original inode. Watching the directory for
     * IN_CLOSE_WRITE | IN_MOVED_TO catches both in-place writes and atomic replaces.
     */
    // Extract directory from path
    char* path_copy = strdup(config_path);
    const char* dir = dirname(path_copy);

    int wd = inotify_add_watch(ifd, dir, IN_CLOSE_WRITE | IN_MOVED_TO);
    free(path_copy);

    if (wd < 0) {
        LOG_WRN("inotify_add_watch failed: %s — file watch disabled", std::strerror(errno));
        close(ifd);
        return -1;
    }

    LOG_INF("Watching config directory for changes");
    return ifd;
}

/// Drain inotify events. Returns true if our config file was modified.
static bool drain_inotify(int ifd, const char* config_basename) {
    bool changed = false;
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    for (;;) {
        ssize_t len = read(ifd, buf, sizeof(buf));
        if (len <= 0) break;

        for (char* ptr = buf; ptr < buf + len; ) {
            auto* event = reinterpret_cast<struct inotify_event*>(ptr);
            if (event->len > 0 && strcmp(event->name, config_basename) == 0)
                changed = true;
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }
    return changed;
}

/// Check that file exists and has non-zero size.
static bool file_is_nonempty(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return false;
    return st.st_size > 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: pktgate_ctl [--json] [--debug] [--metrics-port PORT] [--afxdp-queues N] <config.json>\n";
        return 1;
    }

    // Parse CLI flags
    int argi = 1;
    uint16_t metrics_port = 0;  // 0 = disabled
    uint32_t afxdp_queues_override = 0;  // 0 = use config/auto-detect
    while (argi < argc && argv[argi][0] == '-') {
        std::string flag = argv[argi];
        if (flag == "--json")       pktgate::log::set_json(true);
        else if (flag == "--debug") pktgate::log::set_level(pktgate::log::Level::DEBUG);
        else if (flag == "--metrics-port" && argi + 1 < argc) {
            int val = std::atoi(argv[++argi]);
            if (val < 1 || val > 65535) {
                std::cerr << "Invalid metrics port: " << val << " (must be 1-65535)\n";
                return 1;
            }
            metrics_port = static_cast<uint16_t>(val);
        }
        else if (flag == "--afxdp-queues" && argi + 1 < argc) {
            int val = std::atoi(argv[++argi]);
            if (val < 1 || val > 1024) {
                std::cerr << "Invalid afxdp-queues: " << val << " (must be 1-1024)\n";
                return 1;
            }
            afxdp_queues_override = static_cast<uint32_t>(val);
        }
        else {
            std::cerr << "Unknown flag: " << flag << "\n";
            return 1;
        }
        argi++;
    }
    if (argi >= argc) {
        std::cerr << "Usage: pktgate_ctl [--json] [--debug] [--metrics-port PORT] [--afxdp-queues N] <config.json>\n";
        return 1;
    }

    const char* config_path = argv[argi];

    // Extract basename for inotify matching
    char* path_copy = strdup(config_path);
    std::string config_base = basename(path_copy);
    free(path_copy);

    // Parse config
    auto result = pktgate::config::parse_config(config_path);
    if (!result) {
        LOG_ERR("Failed to parse config: %s", result.error().c_str());
        return 1;
    }
    auto& cfg = *result;
    LOG_INF("Config loaded: interface=%s, L2=%zu, L3=%zu, L4=%zu",
            cfg.interface.c_str(),
            cfg.pipeline.layer_2.size(),
            cfg.pipeline.layer_3.size(),
            cfg.pipeline.layer_4.size());

    // Load BPF programs
    pktgate::loader::BpfLoader loader;
    auto lr = loader.load();
    if (!lr) {
        LOG_ERR("BPF load failed: %s", lr.error().c_str());
        return 1;
    }

    // Setup generation manager and deploy
    pktgate::pipeline::GenerationManager gen_mgr(loader.registry());
    pktgate::pipeline::PipelineBuilder builder(gen_mgr);

    // Interface resolver — maps config names to system ifindex
    pktgate::compiler::IfindexResolver resolver = [](const std::string& name) -> uint32_t {
        return pktgate::util::resolve_ifindex(name);
    };

    // Initial deployment: fill gen 0, make it active
    auto dr = builder.deploy(cfg, resolver);
    if (!dr) {
        LOG_ERR("Pipeline deploy failed: %s", dr.error().c_str());
        return 1;
    }

    // Attach XDP to interface
    auto ar = loader.attach(cfg.interface);
    if (!ar) {
        LOG_ERR("XDP attach failed: %s", ar.error().c_str());
        return 1;
    }

    // Attach TC ingress for mirror/tag actions
    auto tr = loader.attach_tc(cfg.interface);
    if (!tr) {
        LOG_ERR("TC attach failed: %s", tr.error().c_str());
        return 1;
    }

    // AF_XDP userspace fast path (non-fatal: fallback to XDP_PASS if bind fails)
    std::unique_ptr<pktgate::xdp::XdpSocketManager> xdp_mgr;
    if (cfg.afxdp.enabled) {
        uint32_t queues = afxdp_queues_override > 0 ? afxdp_queues_override : cfg.afxdp.queues;
        xdp_mgr = std::make_unique<pktgate::xdp::XdpSocketManager>(loader.registry());
        if (!xdp_mgr->init(cfg.interface, queues, cfg.afxdp.zero_copy,
                           cfg.afxdp.frame_size, cfg.afxdp.num_frames)) {
            LOG_WRN("AF_XDP init failed — userspace packets will fallback to kernel stack");
            xdp_mgr.reset();
        } else if (!xdp_mgr->start([](const uint8_t* /*data*/, uint32_t len) {
            LOG_DBG("AF_XDP: received %u bytes", len);
        })) {
            LOG_WRN("AF_XDP start failed — userspace packets will fallback to kernel stack");
            xdp_mgr.reset();
        } else {
            LOG_INF("AF_XDP userspace path active: %u queue(s)", xdp_mgr->socket_count());
        }
    }

    // Stats reader for runtime diagnostics
    pktgate::pipeline::StatsReader stats_reader(loader.registry());

    // Prometheus metrics exporter
    std::unique_ptr<pktgate::metrics::PrometheusExporter> exporter;
    if (metrics_port > 0) {
        exporter = std::make_unique<pktgate::metrics::PrometheusExporter>(loader.registry(), metrics_port);
        if (exporter->start()) {
            LOG_INF("Prometheus metrics on :%u/metrics", metrics_port);
        } else {
            LOG_ERR("Failed to start metrics server on port %u", metrics_port);
            exporter.reset();
        }
    }

    // Setup inotify for automatic config reload
    int inotify_fd = setup_inotify(config_path);

    // Signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sigusr1_handler);
    signal(SIGHUP, sighup_handler);

    LOG_INF("Filter active on %s. SIGHUP=reload, SIGUSR1=stats, Ctrl+C=stop.",
            cfg.interface.c_str());

    // Main event loop — poll on inotify fd (or just signal-driven if inotify unavailable)
    struct pollfd pfd = {};
    if (inotify_fd >= 0) {
        pfd.fd = inotify_fd;
        pfd.events = POLLIN;
    }

    while (g_running) {
        // poll() with timeout — interruptible by signals
        int nfds = (inotify_fd >= 0) ? 1 : 0;
        int ret = poll(nfds ? &pfd : nullptr, nfds, 1000 /* 1s timeout */);

        // Check inotify events — debounce for editors that truncate-then-write
        if (ret > 0 && inotify_fd >= 0 && (pfd.revents & POLLIN)) {
            if (drain_inotify(inotify_fd, config_base.c_str())) {
                // Debounce: wait 150ms for editor to finish writing, then drain again
                poll(nullptr, 0, 150);
                drain_inotify(inotify_fd, config_base.c_str());

                if (!file_is_nonempty(config_path)) {
                    LOG_DBG("Config file empty after change — skipping reload");
                } else {
                    LOG_INF("Config file changed — triggering reload");
                    g_reload = 0;  /* clear pending SIGHUP — will re-set if new signal arrives */
                    do_reload(config_path, builder, resolver);
                }
            }
        }

        // Check signal flags
        if (g_reload) {
            g_reload = 0;
            do_reload(config_path, builder, resolver);
        }
        if (g_dump_stats) {
            g_dump_stats = 0;
            stats_reader.print();
        }
    }

    // Print final stats on shutdown
    LOG_INF("Shutting down...");
    stats_reader.print();
    if (xdp_mgr)
        xdp_mgr->stop();
    if (inotify_fd >= 0)
        close(inotify_fd);
    loader.detach_tc();
    loader.detach();
    return 0;
}
