#pragma once

#include "config_model.hpp"
#include <string>
#include <expected>

namespace pktgate::config {

/// Parse a JSON configuration file into a Config object.
std::expected<Config, std::string> parse_config(const std::string& json_path);

/// Parse a JSON string into a Config object.
std::expected<Config, std::string> parse_config_string(const std::string& json_str);

} // namespace pktgate::config
