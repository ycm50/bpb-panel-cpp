#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace bpb::sub {

// Registers fresh Cloudflare WARP accounts (X25519 + POST to api.cloudflareclient.com).
bool fetch_warp_accounts(nlohmann::json& accounts, std::string& error);

} // namespace bpb::sub
