#include "loader/map_manager.hpp"
#include "util/log.hpp"
#include <bpf/bpf.h>
#include <cerrno>
#include <cstring>

namespace pktgate::loader {

std::expected<void, std::string>
MapManager::update_elem(int map_fd, const void* key, const void* value, uint64_t flags) {
    if (bpf_map_update_elem(map_fd, key, value, flags) < 0)
        return std::unexpected(std::string("map update failed: ") + std::strerror(errno));
    return {};
}

std::expected<void, std::string>
MapManager::delete_elem(int map_fd, const void* key) {
    if (bpf_map_delete_elem(map_fd, key) < 0)
        return std::unexpected(std::string("map delete failed: ") + std::strerror(errno));
    return {};
}

std::expected<void, std::string>
MapManager::clear_hash_map(int map_fd) {
    /*
     * Safe delete-while-iterate pattern for hash maps:
     * After deleting next_key, do NOT advance the cursor (key).
     * The kernel will return the new successor of key on the
     * next get_next_key call.
     */
    char key[256]{};
    char next_key[256]{};
    bool first = true;

    int deleted = 0;
    int errors = 0;

    for (;;) {
        int ret;
        if (first) {
            ret = bpf_map_get_next_key(map_fd, nullptr, next_key);
            first = false;
        } else {
            ret = bpf_map_get_next_key(map_fd, key, next_key);
        }

        if (ret != 0) {
            if (errno != ENOENT) {
                LOG_WRN("clear_hash_map: get_next_key failed: %s", std::strerror(errno));
            }
            break;
        }

        if (bpf_map_delete_elem(map_fd, next_key) < 0) {
            LOG_WRN("clear_hash_map: delete failed: %s", std::strerror(errno));
            errors++;
            // Advance past the key we couldn't delete to avoid infinite loop
            __builtin_memcpy(key, next_key, sizeof(next_key));
            first = false;
            continue;
        }
        deleted++;
        first = true;
    }

    if (errors > 0) {
        return std::unexpected("clear_hash_map: " + std::to_string(errors)
                               + " delete(s) failed out of "
                               + std::to_string(deleted + errors));
    }
    return {};
}

std::expected<void, std::string>
MapManager::batch_update(int map_fd, const void* keys, const void* values,
                          uint32_t count, uint64_t flags) {
    if (count == 0) return {};

    /*
     * Try bpf_map_update_batch first (Linux 5.6+).
     * Falls back to sequential updates if batch is not supported
     * (ENOTSUPP/EINVAL — older kernel or map type doesn't support batch).
     */
    uint32_t cnt = count;
    LIBBPF_OPTS(bpf_map_batch_opts, opts, .elem_flags = flags, .flags = 0);

    int err = bpf_map_update_batch(map_fd, keys, values, &cnt, &opts);
    if (err == 0)
        return {};

    // Batch not supported — fall back to sequential
    if (errno == EINVAL || errno == ENOTSUP || errno == EOPNOTSUPP) {
        /*
         * We don't know key_size/value_size here, so we need the caller
         * to handle sequential fallback. Signal with a specific error.
         */
        return std::unexpected(std::string("batch_not_supported"));
    }

    return std::unexpected(std::string("batch update failed: ") + std::strerror(errno));
}

std::expected<void, std::string>
MapManager::delete_keys(int map_fd, const std::vector<std::vector<uint8_t>>& keys) {
    int errors = 0;
    for (auto& key : keys) {
        if (bpf_map_delete_elem(map_fd, key.data()) < 0) {
            // ENOENT is expected (key already absent) — skip silently
            if (errno != ENOENT) {
                LOG_WRN("delete_keys: delete failed: %s", std::strerror(errno));
                errors++;
            }
        }
    }
    if (errors > 0) {
        return std::unexpected("delete_keys: " + std::to_string(errors)
                               + " unexpected error(s) out of "
                               + std::to_string(keys.size()) + " keys");
    }
    return {};
}

} // namespace pktgate::loader
