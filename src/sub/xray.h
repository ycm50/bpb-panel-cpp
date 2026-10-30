#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace bpb::sub {

// xray subscription generators (parity with src/cores/xray/*)
bool build_xray_custom(const nlohmann::json& s, bool is_fragment, std::string& out_json,
                       std::string& error);
bool build_xray_warp(const nlohmann::json& s, const nlohmann::json& warp_accounts, bool is_pro,
                     bool is_knocker, std::string& out_json, std::string& error);

std::vector<std::string> warp_endpoint_hosts(const nlohmann::json& s);

} // namespace bpb::sub
