#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace bpb::sub {

struct SubResult {
    int status = 200;
    std::string body;
    std::string content_type = "text/plain; charset=utf-8";
    std::string profile_title;
    std::string dns;
    bool base64_encoded = false;
};

SubResult build_raw_configs(const nlohmann::json& s, const std::string& client);

} // namespace bpb::sub
