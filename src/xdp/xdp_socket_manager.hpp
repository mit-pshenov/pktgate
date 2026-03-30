#pragma once

#include "xdp/xdp_socket.hpp"
#include "../loader/map_registry.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace pktgate::xdp {

/// Callback type: (packet_data, packet_length)
/// Must be thread-safe — called from per-queue worker threads.
using PacketCallback = std::function<void(const uint8_t*, uint32_t)>;

/// Manages multiple AF_XDP sockets (one per RX queue) with worker threads.
class XdpSocketManager {
public:
    explicit XdpSocketManager(const loader::MapRegistry& registry);
    ~XdpSocketManager();

    XdpSocketManager(const XdpSocketManager&) = delete;
    XdpSocketManager& operator=(const XdpSocketManager&) = delete;

    /// Initialize AF_XDP sockets for the given interface.
    /// queue_count=0 means auto-detect from /sys/class/net/<iface>/queues/.
    bool init(const std::string& interface, uint32_t queue_count,
              bool zero_copy, uint32_t frame_size = 4096,
              uint32_t num_frames = 4096);

    /// Start worker threads. Each thread polls one socket.
    /// The callback is called for every received packet.
    bool start(PacketCallback callback);

    /// Stop worker threads and clean up sockets.
    void stop();

    uint32_t socket_count() const { return static_cast<uint32_t>(sockets_.size()); }
    bool running() const { return running_.load(std::memory_order_acquire); }

private:
    void worker_loop(uint32_t idx, PacketCallback cb);
    uint32_t detect_queue_count(const std::string& interface);

    const loader::MapRegistry& registry_;
    std::vector<XdpSocket>     sockets_;
    std::vector<std::thread>   threads_;
    std::atomic<bool>          running_{false};
};

} // namespace pktgate::xdp
