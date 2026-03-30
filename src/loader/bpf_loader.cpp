#include "loader/bpf_loader.hpp"
#include "util/log.hpp"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/pkt_sched.h>
#include <cerrno>
#include <cstring>

// Include all skeletons
#include "entry.skel.h"
#include "layer2.skel.h"
#include "layer3.skel.h"
#include "layer4.skel.h"
#include "tc_ingress.skel.h"

namespace pktgate::loader {

struct BpfLoader::Impl {
    struct entry_bpf*      entry      = nullptr;
    struct layer2_bpf*     layer2     = nullptr;
    struct layer3_bpf*     layer3     = nullptr;
    struct layer4_bpf*     layer4     = nullptr;
    struct tc_ingress_bpf* tc_ingress = nullptr;
};

BpfLoader::BpfLoader() : impl_(std::make_unique<Impl>()) {}

BpfLoader::~BpfLoader() {
    detach();
    detach_tc();
    if (impl_) {
        if (impl_->entry)      entry_bpf__destroy(impl_->entry);
        if (impl_->layer2)     layer2_bpf__destroy(impl_->layer2);
        if (impl_->layer3)     layer3_bpf__destroy(impl_->layer3);
        if (impl_->layer4)     layer4_bpf__destroy(impl_->layer4);
        if (impl_->tc_ingress) tc_ingress_bpf__destroy(impl_->tc_ingress);
    }
}

std::expected<void, std::string> BpfLoader::load() {
    // Open skeletons
    impl_->entry = entry_bpf__open();
    if (!impl_->entry)
        return std::unexpected("Failed to open entry BPF: " + std::string(std::strerror(errno)));

    impl_->layer2 = layer2_bpf__open();
    if (!impl_->layer2)
        return std::unexpected("Failed to open layer2 BPF: " + std::string(std::strerror(errno)));

    impl_->layer3 = layer3_bpf__open();
    if (!impl_->layer3)
        return std::unexpected("Failed to open layer3 BPF: " + std::string(std::strerror(errno)));

    impl_->layer4 = layer4_bpf__open();
    if (!impl_->layer4)
        return std::unexpected("Failed to open layer4 BPF: " + std::string(std::strerror(errno)));

    impl_->tc_ingress = tc_ingress_bpf__open();
    if (!impl_->tc_ingress)
        return std::unexpected("Failed to open tc_ingress BPF: " + std::string(std::strerror(errno)));

    // Load entry first — it owns all maps
    int err;
    err = entry_bpf__load(impl_->entry);
    if (err)
        return std::unexpected("Failed to load entry BPF: " + std::string(std::strerror(-err)));

    // Reuse entry's maps in XDP layer programs (they share all map definitions)
    auto reuse_xdp_maps = [this](auto* skel, const char* name) -> std::expected<void, std::string> {
        #define REUSE_MAP(map_name) do { \
            int fd = bpf_map__fd(impl_->entry->maps.map_name); \
            if (fd < 0) \
                return std::unexpected(std::string(name) + ": entry map " #map_name " not found"); \
            err = bpf_map__reuse_fd(skel->maps.map_name, fd); \
            if (err) \
                return std::unexpected(std::string(name) + ": reuse " #map_name " failed: " + std::strerror(-err)); \
        } while(0)

        int err;
        REUSE_MAP(gen_config);
        REUSE_MAP(prog_array_0);
        REUSE_MAP(prog_array_1);
        REUSE_MAP(mac_allow_0);
        REUSE_MAP(mac_allow_1);
        REUSE_MAP(subnet_rules_0);
        REUSE_MAP(subnet_rules_1);
        REUSE_MAP(subnet6_rules_0);
        REUSE_MAP(subnet6_rules_1);
        REUSE_MAP(vrf_rules_0);
        REUSE_MAP(vrf_rules_1);
        REUSE_MAP(l4_rules_0);
        REUSE_MAP(l4_rules_1);
        REUSE_MAP(default_action_0);
        REUSE_MAP(default_action_1);
        REUSE_MAP(rate_state_map);
        REUSE_MAP(stats_map);

        #undef REUSE_MAP
        return {};
    };

    auto r2 = reuse_xdp_maps(impl_->layer2, "layer2");
    if (!r2) return std::unexpected(r2.error());

    auto r3 = reuse_xdp_maps(impl_->layer3, "layer3");
    if (!r3) return std::unexpected(r3.error());

    auto r4 = reuse_xdp_maps(impl_->layer4, "layer4");
    if (!r4) return std::unexpected(r4.error());

    // Reuse only stats_map in TC program (pkt_metadata removed — using data_meta)
    {
        #define REUSE_TC_MAP(map_name) do { \
            int fd = bpf_map__fd(impl_->entry->maps.map_name); \
            if (fd < 0) \
                return std::unexpected("tc_ingress: entry map " #map_name " not found"); \
            int err2 = bpf_map__reuse_fd(impl_->tc_ingress->maps.map_name, fd); \
            if (err2) \
                return std::unexpected(std::string("tc_ingress: reuse " #map_name " failed: ") + std::strerror(-err2)); \
        } while(0)

        REUSE_TC_MAP(stats_map);

        #undef REUSE_TC_MAP
    }

    // Now load layer programs (they will use entry's maps)
    err = layer2_bpf__load(impl_->layer2);
    if (err)
        return std::unexpected("Failed to load layer2 BPF: " + std::string(std::strerror(-err)));

    err = layer3_bpf__load(impl_->layer3);
    if (err)
        return std::unexpected("Failed to load layer3 BPF: " + std::string(std::strerror(-err)));

    err = layer4_bpf__load(impl_->layer4);
    if (err)
        return std::unexpected("Failed to load layer4 BPF: " + std::string(std::strerror(-err)));

    err = tc_ingress_bpf__load(impl_->tc_ingress);
    if (err)
        return std::unexpected("Failed to load tc_ingress BPF: " + std::string(std::strerror(-err)));

    loaded_ = true;
    LOG_INF("All BPF programs loaded and verified (XDP + TC)");
    return {};
}

std::expected<void, std::string> BpfLoader::attach(const std::string& interface) {
    if (!loaded_)
        return std::unexpected("BPF programs not loaded");

    unsigned ifidx = if_nametoindex(interface.c_str());
    if (ifidx == 0)
        return std::unexpected("Interface not found: " + interface);

    int prog_fd = bpf_program__fd(impl_->entry->progs.entry_prog);
    if (prog_fd < 0)
        return std::unexpected("Invalid entry prog fd");

    // Try native XDP first
    LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
    int err = bpf_xdp_attach(ifidx, prog_fd, XDP_FLAGS_DRV_MODE, &opts);
    if (err == 0) {
        attach_ifindex_ = ifidx;
        attach_flags_ = XDP_FLAGS_DRV_MODE;
        attached_ = true;
        LOG_INF("XDP attached (native) to %s (ifindex=%u)", interface.c_str(), ifidx);
        return {};
    }

    // Fallback to SKB/generic mode (works on veth, bridge, etc.)
    LOG_INF("Native XDP failed on %s, trying SKB mode...", interface.c_str());
    err = bpf_xdp_attach(ifidx, prog_fd, XDP_FLAGS_SKB_MODE, &opts);
    if (err == 0) {
        attach_ifindex_ = ifidx;
        attach_flags_ = XDP_FLAGS_SKB_MODE;
        attached_ = true;
        LOG_INF("XDP attached (SKB/generic) to %s (ifindex=%u)", interface.c_str(), ifidx);
        return {};
    }

    return std::unexpected("Failed to attach XDP (native and SKB): " +
                           std::string(std::strerror(-err)));
}

std::expected<void, std::string> BpfLoader::attach_tc(const std::string& interface) {
    if (!loaded_)
        return std::unexpected("BPF programs not loaded");

    unsigned ifidx = if_nametoindex(interface.c_str());
    if (ifidx == 0)
        return std::unexpected("TC: interface not found: " + interface);

    int prog_fd = bpf_program__fd(impl_->tc_ingress->progs.tc_ingress_prog);
    if (prog_fd < 0)
        return std::unexpected("Invalid tc_ingress prog fd");

    // Create clsact qdisc (required for TC BPF attachment)
    LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = static_cast<int>(ifidx),
        .attach_point = BPF_TC_INGRESS,
    );

    // Try to create the qdisc — EEXIST is OK (already exists)
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
        return std::unexpected("TC: failed to create clsact qdisc: " +
                               std::string(std::strerror(-err)));

    // Attach TC program
    LIBBPF_OPTS(bpf_tc_opts, tc_opts,
        .prog_fd = prog_fd,
    );
    err = bpf_tc_attach(&hook, &tc_opts);
    if (err)
        return std::unexpected("TC: failed to attach ingress program: " +
                               std::string(std::strerror(-err)));

    tc_attached_ = true;
    LOG_INF("TC ingress attached to %s (ifindex=%u, handle=%u, priority=%u)",
            interface.c_str(), ifidx, tc_opts.handle, tc_opts.priority);
    return {};
}

void BpfLoader::detach() {
    if (attached_ && attach_ifindex_ > 0) {
        LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
        bpf_xdp_attach(attach_ifindex_, -1, attach_flags_, &opts);
        attached_ = false;
        LOG_INF("XDP detached");
    }
}

void BpfLoader::detach_tc() {
    if (tc_attached_ && attach_ifindex_ > 0) {
        LIBBPF_OPTS(bpf_tc_hook, hook,
            .ifindex = static_cast<int>(attach_ifindex_),
            .attach_point = BPF_TC_INGRESS,
        );
        // Destroy the entire clsact qdisc — removes all TC programs
        hook.attach_point = static_cast<enum bpf_tc_attach_point>(
            BPF_TC_INGRESS | BPF_TC_EGRESS);
        bpf_tc_hook_destroy(&hook);
        tc_attached_ = false;
        LOG_INF("TC ingress detached");
    }
    if (!attached_) {
        attach_ifindex_ = 0;
        attach_flags_ = 0;
    }
}

// Map FD accessors
int BpfLoader::mac_allow_fd(uint32_t gen) const {
    if (!impl_->entry) return -1;
    return gen == 0
        ? bpf_map__fd(impl_->entry->maps.mac_allow_0)
        : bpf_map__fd(impl_->entry->maps.mac_allow_1);
}

int BpfLoader::subnet_rules_fd(uint32_t gen) const {
    if (!impl_->entry) return -1;
    return gen == 0
        ? bpf_map__fd(impl_->entry->maps.subnet_rules_0)
        : bpf_map__fd(impl_->entry->maps.subnet_rules_1);
}

int BpfLoader::subnet6_rules_fd(uint32_t gen) const {
    if (!impl_->entry) return -1;
    return gen == 0
        ? bpf_map__fd(impl_->entry->maps.subnet6_rules_0)
        : bpf_map__fd(impl_->entry->maps.subnet6_rules_1);
}

int BpfLoader::vrf_rules_fd(uint32_t gen) const {
    if (!impl_->entry) return -1;
    return gen == 0
        ? bpf_map__fd(impl_->entry->maps.vrf_rules_0)
        : bpf_map__fd(impl_->entry->maps.vrf_rules_1);
}

int BpfLoader::l4_rules_fd(uint32_t gen) const {
    if (!impl_->entry) return -1;
    return gen == 0
        ? bpf_map__fd(impl_->entry->maps.l4_rules_0)
        : bpf_map__fd(impl_->entry->maps.l4_rules_1);
}

int BpfLoader::prog_array_fd(uint32_t gen) const {
    if (!impl_->entry) return -1;
    return gen == 0
        ? bpf_map__fd(impl_->entry->maps.prog_array_0)
        : bpf_map__fd(impl_->entry->maps.prog_array_1);
}

int BpfLoader::default_action_fd(uint32_t gen) const {
    if (!impl_->entry) return -1;
    return gen == 0
        ? bpf_map__fd(impl_->entry->maps.default_action_0)
        : bpf_map__fd(impl_->entry->maps.default_action_1);
}

int BpfLoader::gen_config_fd() const {
    if (!impl_->entry) return -1;
    return bpf_map__fd(impl_->entry->maps.gen_config);
}

int BpfLoader::rate_state_fd() const {
    if (!impl_->entry) return -1;
    return bpf_map__fd(impl_->entry->maps.rate_state_map);
}

int BpfLoader::stats_map_fd() const {
    if (!impl_->entry) return -1;
    return bpf_map__fd(impl_->entry->maps.stats_map);
}

// Program FD accessors
int BpfLoader::entry_prog_fd() const {
    if (!impl_->entry) return -1;
    return bpf_program__fd(impl_->entry->progs.entry_prog);
}

int BpfLoader::layer2_prog_fd() const {
    if (!impl_->layer2) return -1;
    return bpf_program__fd(impl_->layer2->progs.layer2_prog);
}

int BpfLoader::layer3_prog_fd() const {
    if (!impl_->layer3) return -1;
    return bpf_program__fd(impl_->layer3->progs.layer3_prog);
}

int BpfLoader::layer4_prog_fd() const {
    if (!impl_->layer4) return -1;
    return bpf_program__fd(impl_->layer4->progs.layer4_prog);
}

int BpfLoader::tc_ingress_prog_fd() const {
    if (!impl_->tc_ingress) return -1;
    return bpf_program__fd(impl_->tc_ingress->progs.tc_ingress_prog);
}

} // namespace pktgate::loader
