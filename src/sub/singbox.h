#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace bpb::sub {

bool build_sb_custom(const nlohmann::json& s, bool is_fragment, std::string& out_json,
                     std::string& error);
bool build_sb_warp(const nlohmann::json& s, const nlohmann::json& warp_accounts,
                   std::string& out_json, std::string& error);

} // namespace bpb::sub
