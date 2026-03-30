#include "xdp/xdp_socket.hpp"
#include "util/log.hpp"

#include <bpf/bpf.h>

#include <cerrno>
#include <cstring>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_xdp.h>

// Ring size — must be power of 2
static constexpr uint32_t kRingSize = 2048;

namespace pktgate::xdp {

XdpSocket::~XdpSocket() { destroy(); }

XdpSocket::XdpSocket(XdpSocket&& other) noexcept {
    *this = std::move(other);
}

XdpSocket& XdpSocket::operator=(XdpSocket&& other) noexcept {
    if (this != &other) {
        destroy();
        sock_fd_       = other.sock_fd_;
        queue_id_      = other.queue_id_;
        ifindex_       = other.ifindex_;
        umem_area_     = other.umem_area_;
        umem_size_     = other.umem_size_;
        frame_size_    = other.frame_size_;
        num_frames_    = other.num_frames_;
        rx_map_        = other.rx_map_;
        rx_map_len_    = other.rx_map_len_;
        rx_size_       = other.rx_size_;
        rx_producer_   = other.rx_producer_;
        rx_consumer_   = other.rx_consumer_;
        rx_descs_      = other.rx_descs_;
        fill_map_      = other.fill_map_;
        fill_map_len_  = other.fill_map_len_;
        fill_size_     = other.fill_size_;
        fill_producer_ = other.fill_producer_;
        fill_consumer_ = other.fill_consumer_;
        fill_addrs_    = other.fill_addrs_;
        free_frame_idx_ = other.free_frame_idx_;

        other.sock_fd_    = -1;
        other.umem_area_  = nullptr;
        other.rx_map_     = nullptr;
        other.fill_map_   = nullptr;
    }
    return *this;
}

void XdpSocket::destroy() {
    if (rx_map_ && rx_map_ != MAP_FAILED)
        ::munmap(rx_map_, rx_map_len_);
    if (fill_map_ && fill_map_ != MAP_FAILED)
        ::munmap(fill_map_, fill_map_len_);
    if (sock_fd_ >= 0)
        ::close(sock_fd_);
    if (umem_area_ && umem_area_ != MAP_FAILED)
        ::munmap(umem_area_, umem_size_);

    sock_fd_   = -1;
    umem_area_ = nullptr;
    rx_map_    = nullptr;
    fill_map_  = nullptr;
}

bool XdpSocket::create(const std::string& interface, const XdpSocketConfig& cfg) {
    queue_id_   = cfg.queue_id;
    frame_size_ = cfg.frame_size;
    num_frames_ = cfg.num_frames;

    ifindex_ = ::if_nametoindex(interface.c_str());
    if (ifindex_ == 0) {
        LOG_ERR("XdpSocket: interface %s not found", interface.c_str());
        return false;
    }

    // 1. Allocate UMEM area
    umem_size_ = static_cast<uint64_t>(frame_size_) * num_frames_;
    umem_area_ = ::mmap(nullptr, umem_size_, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (umem_area_ == MAP_FAILED) {
        LOG_ERR("XdpSocket: mmap UMEM failed: %s", std::strerror(errno));
        umem_area_ = nullptr;
        return false;
    }

    // 2. Create AF_XDP socket
    sock_fd_ = ::socket(AF_XDP, SOCK_RAW, 0);
    if (sock_fd_ < 0) {
        LOG_ERR("XdpSocket: socket(AF_XDP) failed: %s", std::strerror(errno));
        return false;
    }

    // 3. Register UMEM
    struct xdp_umem_reg umem_reg{};
    umem_reg.addr       = reinterpret_cast<uint64_t>(umem_area_);
    umem_reg.len        = umem_size_;
    umem_reg.chunk_size = frame_size_;
    umem_reg.headroom   = 0;

    if (::setsockopt(sock_fd_, SOL_XDP, XDP_UMEM_REG,
                     &umem_reg, sizeof(umem_reg)) < 0) {
        LOG_ERR("XdpSocket: UMEM_REG failed: %s", std::strerror(errno));
        return false;
    }

    // 4. Set up fill ring
    uint32_t ring_size = kRingSize;
    if (::setsockopt(sock_fd_, SOL_XDP, XDP_UMEM_FILL_RING,
                     &ring_size, sizeof(ring_size)) < 0) {
        LOG_ERR("XdpSocket: FILL_RING setsockopt failed: %s", std::strerror(errno));
        return false;
    }

    // 5. Set up RX ring
    if (::setsockopt(sock_fd_, SOL_XDP, XDP_RX_RING,
                     &ring_size, sizeof(ring_size)) < 0) {
        LOG_ERR("XdpSocket: RX_RING setsockopt failed: %s", std::strerror(errno));
        return false;
    }

    // 6. Get mmap offsets
    struct xdp_mmap_offsets offsets{};
    socklen_t optlen = sizeof(offsets);
    if (::getsockopt(sock_fd_, SOL_XDP, XDP_MMAP_OFFSETS,
                     &offsets, &optlen) < 0) {
        LOG_ERR("XdpSocket: MMAP_OFFSETS failed: %s", std::strerror(errno));
        return false;
    }

    // 7. mmap RX ring
    rx_size_ = ring_size;
    rx_map_len_ = offsets.rx.desc + ring_size * sizeof(struct xdp_desc);
    rx_map_ = ::mmap(nullptr, rx_map_len_, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, sock_fd_, XDP_PGOFF_RX_RING);
    if (rx_map_ == MAP_FAILED) {
        LOG_ERR("XdpSocket: mmap RX ring failed: %s", std::strerror(errno));
        rx_map_ = nullptr;
        return false;
    }

    rx_producer_ = reinterpret_cast<uint32_t*>(
        static_cast<char*>(rx_map_) + offsets.rx.producer);
    rx_consumer_ = reinterpret_cast<uint32_t*>(
        static_cast<char*>(rx_map_) + offsets.rx.consumer);
    rx_descs_ = reinterpret_cast<struct xdp_desc*>(
        static_cast<char*>(rx_map_) + offsets.rx.desc);

    // 8. mmap fill ring
    fill_size_ = ring_size;
    fill_map_len_ = offsets.fr.desc + ring_size * sizeof(uint64_t);
    fill_map_ = ::mmap(nullptr, fill_map_len_, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, sock_fd_,
                       XDP_UMEM_PGOFF_FILL_RING);
    if (fill_map_ == MAP_FAILED) {
        LOG_ERR("XdpSocket: mmap fill ring failed: %s", std::strerror(errno));
        fill_map_ = nullptr;
        return false;
    }

    fill_producer_ = reinterpret_cast<uint32_t*>(
        static_cast<char*>(fill_map_) + offsets.fr.producer);
    fill_consumer_ = reinterpret_cast<uint32_t*>(
        static_cast<char*>(fill_map_) + offsets.fr.consumer);
    fill_addrs_ = reinterpret_cast<uint64_t*>(
        static_cast<char*>(fill_map_) + offsets.fr.desc);

    // 9. Pre-populate fill ring
    free_frame_idx_ = 0;
    refill();

    // 10. Bind socket to interface + queue
    struct sockaddr_xdp sxdp{};
    sxdp.sxdp_family   = AF_XDP;
    sxdp.sxdp_ifindex  = ifindex_;
    sxdp.sxdp_queue_id = queue_id_;
    sxdp.sxdp_flags    = cfg.zero_copy ? XDP_ZEROCOPY : XDP_COPY;

    if (::bind(sock_fd_, reinterpret_cast<struct sockaddr*>(&sxdp),
               sizeof(sxdp)) < 0) {
        // Try without zero-copy flag if zero_copy failed
        if (cfg.zero_copy && errno == ENOTSUP) {
            LOG_INF("XdpSocket: zero-copy not supported, falling back to copy mode");
            sxdp.sxdp_flags = XDP_COPY;
            if (::bind(sock_fd_, reinterpret_cast<struct sockaddr*>(&sxdp),
                       sizeof(sxdp)) < 0) {
                LOG_ERR("XdpSocket: bind failed (copy fallback): %s",
                        std::strerror(errno));
                return false;
            }
        } else {
            LOG_ERR("XdpSocket: bind failed: %s", std::strerror(errno));
            return false;
        }
    }

    LOG_INF("XdpSocket: created on %s queue=%u frames=%u frame_size=%u %s",
            interface.c_str(), queue_id_, num_frames_, frame_size_,
            cfg.zero_copy ? "zero-copy" : "copy");
    return true;
}

bool XdpSocket::register_in_map(int xsks_map_fd) {
    if (sock_fd_ < 0 || xsks_map_fd < 0)
        return false;

    int fd_val = sock_fd_;
    if (bpf_map_update_elem(xsks_map_fd, &queue_id_, &fd_val, BPF_ANY) < 0) {
        LOG_ERR("XdpSocket: register in xsks_map failed: %s", std::strerror(errno));
        return false;
    }
    LOG_INF("XdpSocket: registered queue=%u in xsks_map", queue_id_);
    return true;
}

void XdpSocket::unregister_from_map(int xsks_map_fd) {
    if (xsks_map_fd >= 0 && queue_id_ < 64)
        bpf_map_delete_elem(xsks_map_fd, &queue_id_);
}

void XdpSocket::refill() {
    if (!fill_producer_ || !fill_addrs_)
        return;

    uint32_t prod = __atomic_load_n(fill_producer_, __ATOMIC_ACQUIRE);

    uint32_t to_fill = fill_size_ / 2;  // refill half at a time
    for (uint32_t i = 0; i < to_fill && free_frame_idx_ < num_frames_; i++) {
        uint32_t idx = prod & (fill_size_ - 1);
        fill_addrs_[idx] = static_cast<uint64_t>(free_frame_idx_) * frame_size_;
        prod++;
        free_frame_idx_++;
    }

    __atomic_store_n(fill_producer_, prod, __ATOMIC_RELEASE);
}

// Template implementation in header — but poll_rx needs the xdp_desc struct
// We provide a non-template helper here and the template calls it.

} // namespace pktgate::xdp
