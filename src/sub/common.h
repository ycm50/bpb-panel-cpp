#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace bpb::sub {

struct DnsResult {
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
};

bool resolve_dns(const std::string& domain, bool only_ipv4, DnsResult& out, std::string& error);
std::vector<std::string> get_config_addresses(const nlohmann::json& s, const std::string& domain,
                                              bool is_fragment, std::string& error);
std::vector<std::string> get_protocols(const nlohmann::json& s);

std::string generate_remark(const nlohmann::json& s, int index, int port, const std::string& address,
                            const std::string& protocol, const std::string& domain,
                            bool is_fragment, bool is_chain);
// WebSocket path a client must use for this protocol. VMess encodes the
// credential in the path, so the caller has to hand it over.
std::string generate_ws_path(const std::string& protocol, const std::string& credential = "");

std::string random_upper_case(const std::string& in);
std::string get_random_string(int length_min, int length_max);

bool is_domain(const std::string& address);
bool is_ipv4(const std::string& address);
bool is_ipv6(const std::string& address);
bool is_https(const nlohmann::json& s, int port);
bool is_base64(const std::string& str);

struct SniHost {
    std::string host;
    std::string sni;
    bool allow_insecure = false;
};
SniHost select_sni_host(const nlohmann::json& s, const std::string& address, const std::string& domain);

std::vector<std::string> to_string_list(const nlohmann::json& j, const std::string& key);
std::string join(const std::vector<std::string>& parts, const std::string& sep);

} // namespace bpb::sub
