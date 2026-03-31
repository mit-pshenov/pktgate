#include "config/config_parser.hpp"
#include <nlohmann/json.hpp>
#include <fstream>

namespace pktgate::config {

using json = nlohmann::json;

static Rule parse_rule(const json& j) {
    Rule r;
    r.rule_id     = j.at("rule_id").get<uint32_t>();
    r.description = j.value("description", "");

    if (j.contains("match")) {
        auto& m = j["match"];
        if (m.contains("src_mac"))   r.match.src_mac   = m["src_mac"].get<std::string>();
        if (m.contains("src_ip"))    r.match.src_ip    = m["src_ip"].get<std::string>();
        if (m.contains("dst_ip"))    r.match.dst_ip    = m["dst_ip"].get<std::string>();
        if (m.contains("src_ip6"))   r.match.src_ip6   = m["src_ip6"].get<std::string>();
        if (m.contains("dst_ip6"))   r.match.dst_ip6   = m["dst_ip6"].get<std::string>();
        if (m.contains("vrf"))       r.match.vrf       = m["vrf"].get<std::string>();
        if (m.contains("protocol"))  r.match.protocol  = m["protocol"].get<std::string>();
        if (m.contains("dst_port"))  r.match.dst_port  = m["dst_port"].get<std::string>();
    }

    r.action = parse_action(j.at("action").get<std::string>());

    if (j.contains("action_params")) {
        auto& ap = j["action_params"];
        if (ap.contains("target_port")) r.params.target_port = ap["target_port"].get<std::string>();
        if (ap.contains("target_vrf"))  r.params.target_vrf  = ap["target_vrf"].get<std::string>();
        if (ap.contains("dscp"))        r.params.dscp        = ap["dscp"].get<std::string>();
        if (ap.contains("cos"))         r.params.cos         = ap["cos"].get<uint8_t>();
        if (ap.contains("bandwidth"))   r.params.bandwidth   = ap["bandwidth"].get<std::string>();
    }

    if (j.contains("next_layer"))
        r.next_layer = j["next_layer"].get<std::string>();

    return r;
}

static std::expected<Config, std::string> parse_json(const json& j) {
    try {
        Config cfg;

        if (j.contains("device_info")) {
            cfg.interface = j["device_info"].value("interface", "");
            cfg.capacity  = j["device_info"].value("capacity", "");
        }

        if (j.contains("objects")) {
            auto& obj = j["objects"];

            if (obj.contains("subnets")) {
                for (auto& [k, v] : obj["subnets"].items())
                    cfg.objects.subnets[k] = v.get<std::string>();
            }

            if (obj.contains("subnets6")) {
                for (auto& [k, v] : obj["subnets6"].items())
                    cfg.objects.subnets6[k] = v.get<std::string>();
            }

            if (obj.contains("mac_groups")) {
                for (auto& [k, v] : obj["mac_groups"].items()) {
                    std::vector<std::string> macs;
                    for (auto& m : v)
                        macs.push_back(m.get<std::string>());
                    cfg.objects.mac_groups[k] = std::move(macs);
                }
            }

            if (obj.contains("port_groups")) {
                for (auto& [k, v] : obj["port_groups"].items()) {
                    std::vector<uint16_t> ports;
                    for (auto& p : v) {
                        if (!p.is_number_integer())
                            return std::unexpected("objects.port_groups." + k +
                                ": port value must be an integer");
                        auto val = p.get<int64_t>();
                        if (val < 0 || val > 65535)
                            return std::unexpected("objects.port_groups." + k +
                                ": port " + std::to_string(val) + " out of range 0-65535");
                        ports.push_back(static_cast<uint16_t>(val));
                    }
                    cfg.objects.port_groups[k] = std::move(ports);
                }
            }
        }

        if (j.contains("pipeline")) {
            auto& pl = j["pipeline"];
            if (!pl.is_object())
                return std::unexpected("'pipeline' must be an object");
            if (pl.contains("layer_2")) {
                if (!pl["layer_2"].is_array())
                    return std::unexpected("'pipeline.layer_2' must be an array");
                for (auto& r : pl["layer_2"])
                    cfg.pipeline.layer_2.push_back(parse_rule(r));
            }
            if (pl.contains("layer_3")) {
                if (!pl["layer_3"].is_array())
                    return std::unexpected("'pipeline.layer_3' must be an array");
                for (auto& r : pl["layer_3"])
                    cfg.pipeline.layer_3.push_back(parse_rule(r));
            }
            if (pl.contains("layer_4")) {
                if (!pl["layer_4"].is_array())
                    return std::unexpected("'pipeline.layer_4' must be an array");
                for (auto& r : pl["layer_4"])
                    cfg.pipeline.layer_4.push_back(parse_rule(r));
            }
        }

        if (j.contains("default_behavior"))
            cfg.default_behavior = parse_action(j["default_behavior"].get<std::string>());

        if (j.contains("afxdp")) {
            auto& ax = j["afxdp"];
            cfg.afxdp.enabled    = ax.value("enabled", false);
            cfg.afxdp.queues     = ax.value("queues", 0u);
            cfg.afxdp.zero_copy  = ax.value("zero_copy", false);
            cfg.afxdp.frame_size = ax.value("frame_size", 4096u);
            cfg.afxdp.num_frames = ax.value("num_frames", 4096u);
        }

        return cfg;
    } catch (const std::exception& e) {
        return std::unexpected(std::string("Parse error: ") + e.what());
    }
}

std::expected<Config, std::string> parse_config(const std::string& json_path) {
    std::ifstream f(json_path);
    if (!f.is_open())
        return std::unexpected("Cannot open file: " + json_path);

    try {
        json j = json::parse(f);
        return parse_json(j);
    } catch (const json::exception& e) {
        return std::unexpected(std::string("JSON error: ") + e.what());
    }
}

std::expected<Config, std::string> parse_config_string(const std::string& json_str) {
    try {
        json j = json::parse(json_str);
        return parse_json(j);
    } catch (const json::exception& e) {
        return std::unexpected(std::string("JSON error: ") + e.what());
    }
}

} // namespace pktgate::config
