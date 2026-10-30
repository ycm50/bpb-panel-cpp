#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace bpb::crypto {

std::string random_hex(std::size_t bytes);
std::vector<std::uint8_t> random_bytes(std::size_t len);

std::string sha224_hex(std::string_view data);
std::string sha256_hex(std::string_view data);
std::string hmac_sha256(std::string_view key, std::string_view data);
std::string hmac_sha256_hex(std::string_view key, std::string_view data);

std::string jwt_sign_hs256(std::string_view payload_json, std::string_view secret);
bool jwt_verify_hs256(std::string_view token, std::string_view secret, std::string& payload_json);
std::string jwt_payload(std::string_view token);

bool constant_time_equals(std::string_view a, std::string_view b);

} // namespace bpb::crypto
