#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace bpb::sub {

bool build_wireguard_zip(const nlohmann::json& s, const nlohmann::json& warp_accounts, bool is_pro,
                         std::string& out_zip, std::string& error);

// Single wg0.conf for server side egress (used by the optional WARP sidecar).
bool build_wireguard_conf(const nlohmann::json& s, const nlohmann::json& warp_accounts,
                          std::string& out_conf, std::string& error);

} // namespace bpb::sub
