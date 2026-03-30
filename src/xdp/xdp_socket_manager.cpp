#include "xdp/xdp_socket_manager.hpp"
#include "util/log.hpp"

#include <filesystem>
#include <algorithm>

namespace pktgate::xdp {

XdpSocketManager::XdpSocketManager(const loader::MapRegistry& registry)
    : registry_(registry) {}

XdpSocketManager::~XdpSocketManager() {
    stop();
}

uint32_t XdpSocketManager::detect_queue_count(const std::string& interface) {
    namespace fs = std::filesystem;
    std::string path = "/sys/class/net/" + interface + "/queues";
    uint32_t count = 0;
    try {
        for (auto& entry : fs::directory_iterator(path)) {
            if (entry.path().filename().string().starts_with("rx-"))
                count++;
        }
    } catch (...) {
        // Fallback: single queue (veth, loopback, etc.)
    }
    return count > 0 ? count : 1;
}

bool XdpSocketManager::init(const std::string& interface, uint32_t queue_count,
                             bool zero_copy, uint32_t frame_size,
                             uint32_t num_frames) {
    if (queue_count == 0)
        queue_count = detect_queue_count(interface);

    LOG_INF("XdpSocketManager: initializing %u AF_XDP socket(s) on %s",
            queue_count, interface.c_str());

    int xsks_fd = registry_.xsks_map_fd();
    if (xsks_fd < 0) {
        LOG_ERR("XdpSocketManager: xsks_map not available");
        return false;
    }

    sockets_.resize(queue_count);
    for (uint32_t i = 0; i < queue_count; i++) {
        XdpSocketConfig cfg{};
        cfg.frame_size = frame_size;
        cfg.num_frames = num_frames;
        cfg.queue_id   = i;
        cfg.zero_copy  = zero_copy;

        if (!sockets_[i].create(interface, cfg)) {
            LOG_ERR("XdpSocketManager: failed to create socket for queue %u", i);
            sockets_.clear();
            return false;
        }

        if (!sockets_[i].register_in_map(xsks_fd)) {
            LOG_ERR("XdpSocketManager: failed to register socket %u in xsks_map", i);
            sockets_.clear();
            return false;
        }
    }

    LOG_INF("XdpSocketManager: %u socket(s) created and registered", queue_count);
    return true;
}

bool XdpSocketManager::start(PacketCallback callback) {
    if (sockets_.empty()) {
        LOG_ERR("XdpSocketManager: no sockets initialized");
        return false;
    }

    if (running_.load(std::memory_order_acquire)) {
        LOG_ERR("XdpSocketManager: already running");
        return false;
    }

    running_.store(true, std::memory_order_release);

    threads_.reserve(sockets_.size());
    for (uint32_t i = 0; i < sockets_.size(); i++) {
        threads_.emplace_back(&XdpSocketManager::worker_loop, this, i, callback);
    }

    LOG_INF("XdpSocketManager: %zu worker thread(s) started",
            threads_.size());
    return true;
}

void XdpSocketManager::stop() {
    running_.store(false, std::memory_order_release);

    for (auto& t : threads_) {
        if (t.joinable())
            t.join();
    }
    threads_.clear();

    // Unregister from xsks_map before destroying sockets
    int xsks_fd = registry_.xsks_map_fd();
    for (auto& sock : sockets_)
        sock.unregister_from_map(xsks_fd);

    sockets_.clear();
    LOG_INF("XdpSocketManager: stopped");
}

void XdpSocketManager::worker_loop(uint32_t idx, PacketCallback cb) {
    LOG_INF("XdpSocketManager: worker thread for queue %u started", idx);

    while (running_.load(std::memory_order_acquire)) {
        sockets_[idx].poll_rx(200, [&cb](const uint8_t* data, uint32_t len) {
            cb(data, len);
        });
    }

    LOG_INF("XdpSocketManager: worker thread for queue %u exiting", idx);
}

} // namespace pktgate::xdp
