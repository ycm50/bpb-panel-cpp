#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace bpb::sub {

bool build_clash_custom(const nlohmann::json& s, std::string& out_json, std::string& error);
bool build_clash_warp(const nlohmann::json& s, const nlohmann::json& warp_accounts, bool is_pro,
                      std::string& out_json, std::string& error);

} // namespace bpb::sub
