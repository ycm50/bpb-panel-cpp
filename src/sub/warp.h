#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace bpb::sub {

// Registers fresh Cloudflare WARP accounts (X25519 + POST to
// api.cloudflareclient.com).
//
// dry_run = true performs the whole local path - key generation, request body
// construction, account persistence - but never contacts Cloudflare: the body is
// logged and a synthetic account with the same shape is returned. That makes the
// panel button testable end to end without burning registration quota, which
// Cloudflare rate limits per source address.
bool fetch_warp_accounts(nlohmann::json& accounts, std::string& error, bool dry_run = false);

} // namespace bpb::sub
