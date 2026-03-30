#pragma once

#include <cstdint>
#include <string>

#include <poll.h>
#include <linux/if_xdp.h>

namespace pktgate::xdp {

/// Configuration for a single AF_XDP socket.
struct XdpSocketConfig {
    uint32_t frame_size  = 4096;
    uint32_t num_frames  = 4096;
    uint32_t queue_id    = 0;
    bool     zero_copy   = false;
};

/// RAII wrapper around a single AF_XDP socket (UMEM + RX ring + fill ring).
/// Not thread-safe — each socket should be owned by one thread.
class XdpSocket {
public:
    XdpSocket() = default;
    ~XdpSocket();

    XdpSocket(const XdpSocket&) = delete;
    XdpSocket& operator=(const XdpSocket&) = delete;
    XdpSocket(XdpSocket&& other) noexcept;
    XdpSocket& operator=(XdpSocket&& other) noexcept;

    /// Create and bind AF_XDP socket to interface + queue.
    /// Returns false on error (details via errno / log).
    bool create(const std::string& interface, const XdpSocketConfig& cfg);

    /// Register this socket in the BPF xsks_map so XDP can redirect to it.
    bool register_in_map(int xsks_map_fd);

    /// Unregister from xsks_map.
    void unregister_from_map(int xsks_map_fd);

    /// Poll for received packets (blocking, with timeout_ms).
    /// Returns number of packets received (0 on timeout).
    /// Calls callback(data_ptr, length) for each packet.
    template<typename Fn>
    uint32_t poll_rx(int timeout_ms, Fn&& callback);

    /// Refill the fill ring with available frames.
    void refill();

    int fd() const { return sock_fd_; }
    uint32_t queue_id() const { return queue_id_; }

private:
    void destroy();

    // Socket
    int      sock_fd_  = -1;
    uint32_t queue_id_ = 0;
    uint32_t ifindex_  = 0;

    // UMEM
    void*    umem_area_  = nullptr;
    uint64_t umem_size_  = 0;
    uint32_t frame_size_ = 0;
    uint32_t num_frames_ = 0;

    // RX ring
    void*    rx_map_     = nullptr;
    size_t   rx_map_len_ = 0;
    uint32_t rx_size_    = 0;      // number of entries (power of 2)
    uint32_t* rx_producer_ = nullptr;
    uint32_t* rx_consumer_ = nullptr;
    struct xdp_desc* rx_descs_ = nullptr;

    // Fill ring
    void*    fill_map_     = nullptr;
    size_t   fill_map_len_ = 0;
    uint32_t fill_size_    = 0;
    uint32_t* fill_producer_ = nullptr;
    uint32_t* fill_consumer_ = nullptr;
    uint64_t* fill_addrs_   = nullptr;

    // Frame tracking: next frame to use for refill
    uint32_t free_frame_idx_ = 0;
};

// ── Template implementation ──────────────────────────────────

template<typename Fn>
uint32_t XdpSocket::poll_rx(int timeout_ms, Fn&& callback) {
    if (sock_fd_ < 0)
        return 0;

    struct pollfd pfd{sock_fd_, POLLIN, 0};
    int ret = ::poll(&pfd, 1, timeout_ms);
    if (ret <= 0)
        return 0;

    uint32_t prod = __atomic_load_n(rx_producer_, __ATOMIC_ACQUIRE);
    uint32_t cons = __atomic_load_n(rx_consumer_, __ATOMIC_ACQUIRE);
    uint32_t count = prod - cons;
    if (count == 0)
        return 0;

    // Recycle frames as we consume them
    uint32_t batch_start_frame = free_frame_idx_;
    (void)batch_start_frame;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t idx = cons & (rx_size_ - 1);
        uint64_t addr = rx_descs_[idx].addr;
        uint32_t len  = rx_descs_[idx].len;
        cons++;

        auto* data = static_cast<uint8_t*>(umem_area_) + addr;
        callback(data, len);

        // Return frame to free list for refill
        // We reuse the frame address: put it back in fill ring
        uint32_t fill_prod = __atomic_load_n(fill_producer_, __ATOMIC_ACQUIRE);
        uint32_t fill_idx = fill_prod & (fill_size_ - 1);
        fill_addrs_[fill_idx] = addr;
        __atomic_store_n(fill_producer_, fill_prod + 1, __ATOMIC_RELEASE);
    }

    __atomic_store_n(rx_consumer_, cons, __ATOMIC_RELEASE);
    return count;
}

} // namespace pktgate::xdp
