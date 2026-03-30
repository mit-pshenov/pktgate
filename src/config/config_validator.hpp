#pragma once

#include "config_model.hpp"
#include <expected>
#include <string>
#include <vector>

namespace pktgate::config {

/// Semantic validation errors.
struct ValidationError {
    std::string rule_context; // e.g. "layer_3[0]"
    std::string message;
};

/// Validate a parsed Config for semantic correctness.
/// Checks:
///   - rule_id uniqueness within each layer
///   - object references resolve ("object:xxx" exists in ObjectStore)
///   - port ranges (0-65535)
///   - DSCP values are known names
///   - bandwidth strings are parseable
///   - next_layer references valid layer names
///   - action_params consistency (mirror needs target_port, etc.)
std::expected<void, std::vector<ValidationError>>
validate_config(const Config& cfg);

} // namespace pktgate::config
