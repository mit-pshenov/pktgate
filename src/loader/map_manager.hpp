#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace pktgate::loader {

class MapManager {
public:
    /// Update a single map element.
    static std::expected<void, std::string>
    update_elem(int map_fd, const void* key, const void* value, uint64_t flags);

    /// Batch update multiple elements in a single syscall.
    /// Falls back to sequential update_elem if batch not supported.
    /// keys and values must be contiguous arrays of key_size/value_size each.
    static std::expected<void, std::string>
    batch_update(int map_fd, const void* keys, const void* values,
                 uint32_t count, uint64_t flags);

    /// Delete a single map element.
    static std::expected<void, std::string>
    delete_elem(int map_fd, const void* key);

    /// Delete all elements from a hash map (iterate and delete).
    /// Works for HASH, PERCPU_HASH, LRU_HASH.
    static std::expected<void, std::string>
    clear_hash_map(int map_fd);

    /// Delete specific keys from a map.
    /// Use for LPM_TRIE maps where iteration is not supported.
    static std::expected<void, std::string>
    delete_keys(int map_fd, const std::vector<std::vector<uint8_t>>& keys);
};

} // namespace pktgate::loader
