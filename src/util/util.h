#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <map>

namespace bpb {

std::string to_lower(std::string_view s);
std::string trim(std::string_view s);
std::vector<std::string> split(std::string_view s, char sep);
bool starts_with(std::string_view s, std::string_view p);
bool ends_with(std::string_view s, std::string_view p);
std::string replace_all(std::string s, std::string_view from, std::string_view to);

std::string base64_encode(const std::uint8_t* data, std::size_t len);
std::string base64_encode(std::string_view s);
std::string base64_decode(std::string_view s);
std::string base64url_encode(const std::uint8_t* data, std::size_t len);
std::string base64url_encode(std::string_view s);

std::string url_decode(std::string_view s);
std::string url_encode(std::string_view s);
std::map<std::string, std::string> parse_query(std::string_view q);

std::string hex_encode(const std::uint8_t* data, std::size_t len);
std::string json_escape(std::string_view s);

bool is_valid_uuid(std::string_view s);
std::string iso_time_now();

} // namespace bpb
