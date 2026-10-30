#include "sub/common.h"
#include "crypto/crypto.h"
#include "net/http_client.h"
#include "util/util.h"

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>
#include <random>

namespace bpb::sub {

static std::mt19937& rng() {
    static std::mt19937 gen(std::random_device{}());
    return gen;
}

std::vector<std::string> to_string_list(const nlohmann::json& j, const std::string& key) {
    std::vector<std::string> out;
    if (!j.contains(key) || !j[key].is_array()) return out;
    for (auto& item : j[key]) {
        if (item.is_string()) out.push_back(item.get<std::string>());
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string random_upper_case(const std::string& in) {
    std::uniform_int_distribution<int> coin(0, 1);
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (coin(rng())) {
            out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        } else {
            out += c;
        }
    }
    return out;
}

std::string get_random_string(int length_min, int length_max) {
    static const char* charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::uniform_int_distribution<int> dist(length_min, length_max);
    std::uniform_int_distribution<int> pick(0, 61);
    int length = dist(rng());
    std::string out;
    out.reserve(static_cast<std::size_t>(length));
    for (int i = 0; i < length; ++i) out += charset[pick(rng())];
    return out;
}

std::string generate_ws_path(const std::string& protocol) {
    std::string proto = (protocol == "vless") ? "vl" : "tr";
    return "/" + proto + "/" + get_random_string(16, 32);
}

bool is_domain(const std::string& address) {
    if (address.empty()) return false;
    if (address.find('.') == std::string::npos) return false;
    for (char c : address) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-')) return false;
    }
    auto labels = split(address, '.');
    if (labels.size() < 2) return false;
    std::string tld = labels.back();
    if (tld.size() < 2 || tld.size() > 63) return false;
    for (char c : tld) {
        if (!std::isalpha(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

bool is_ipv4(const std::string& address) {
    std::string host = address;
    auto slash = host.find('/');
    if (slash != std::string::npos) host = host.substr(0, slash);
    auto parts = split(host, '.');
    if (parts.size() != 4) return false;
    for (auto& p : parts) {
        if (p.empty() || p.size() > 3) return false;
        for (char c : p) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        int v = std::atoi(p.c_str());
        if (v < 0 || v > 255) return false;
    }
    return true;
}

bool is_ipv6(const std::string& address) {
    if (address.size() < 3) return false;
    if (address.front() != '[') return false;
    auto close = address.find(']');
    if (close == std::string::npos) return false;
    std::string inside = address.substr(1, close - 1);
    if (inside.find(':') == std::string::npos) return false;
    for (char c : inside) {
        if (!(std::isxdigit(static_cast<unsigned char>(c)) || c == ':' || c == '.')) return false;
    }
    return true;
}

bool is_base64(const std::string& str) {
    if (str.empty() || str.size() % 4 != 0) return false;
    for (char c : str) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '=' || c == '\r' ||
              c == '\n'))
            return false;
    }
    return true;
}

bool is_https(const nlohmann::json& s, int port) {
    std::vector<int> https_ports = {443, 8443, 2053, 2083, 2087, 2096};
    if (s.contains("ports") && s["ports"].is_array() && !s["ports"].empty()) {
        // keep parity with the TS defaults: https ports come from the runtime, not settings
    }
    for (int p : https_ports) {
        if (p == port) return true;
    }
    return false;
}

std::vector<std::string> get_protocols(const nlohmann::json& s) {
    return split(s.value("protocols", std::string("vless,trojan")), ',');
}

struct CachedDns {
    DnsResult result;
    std::int64_t expires_at = 0;
};

static std::map<std::string, CachedDns>& dns_cache() {
    static std::map<std::string, CachedDns> cache;
    return cache;
}

bool resolve_dns(const std::string& domain, bool only_ipv4, DnsResult& out, std::string& error) {
    std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    std::string cache_key = domain + (only_ipv4 ? "|4" : "|46");
    auto& cache = dns_cache();
    auto it = cache.find(cache_key);
    if (it != cache.end() && it->second.expires_at > now) {
        out = it->second.result;
        return true;
    }
    auto query = [&](const std::string& type, std::vector<std::string>& target) -> bool {
        std::string url = "https://cloudflare-dns.com/dns-query?name=" + url_encode(domain) +
                          "&type=" + type;
        net::httpc::Response res;
        std::string err;
        if (!net::httpc::get(url, res, err, 8000, {{"Accept", "application/dns-json"}})) {
            error = "DoH failed for " + domain + ": " + err;
            return false;
        }
        if (res.status != 200) {
            error = "DoH status " + std::to_string(res.status) + " for " + domain;
            return false;
        }
        try {
            auto j = nlohmann::json::parse(res.body);
            if (!j.contains("Answer") || !j["Answer"].is_array()) return true;
            int want = (type == "A") ? 1 : 28;
            for (auto& rec : j["Answer"]) {
                if (rec.value("type", 0) == want && rec.contains("data") && rec["data"].is_string()) {
                    target.push_back(rec["data"].get<std::string>());
                }
            }
            return true;
        } catch (const std::exception& e) {
            error = std::string("DoH json parse failed: ") + e.what();
            return false;
        }
    };

    if (!query("A", out.ipv4)) return false;
    if (!only_ipv4) {
        if (!query("AAAA", out.ipv6)) return false;
    }
    CachedDns entry;
    entry.result = out;
    entry.expires_at = now + 300;
    cache[cache_key] = entry;
    return true;
}

std::vector<std::string> get_config_addresses(const nlohmann::json& s, const std::string& domain,
                                              bool is_fragment, std::string& error) {
    bool enable_ipv6 = s.value("enableIPv6", false);
    auto clean_ips = to_string_list(s, "cleanIPs");
    auto custom_cdn = to_string_list(s, "customCdnAddrs");

    DnsResult dns;
    if (!resolve_dns(domain, !enable_ipv6, dns, error)) return {};

    std::vector<std::string> addrs;
    addrs.push_back(domain);
    for (auto& ip : dns.ipv4) addrs.push_back(ip);
    for (auto& ip : dns.ipv6) addrs.push_back("[" + ip + "]");
    for (auto& ip : clean_ips) addrs.push_back(ip);
    if (!is_fragment) {
        for (auto& ip : custom_cdn) addrs.push_back(ip);
    }
    return addrs;
}

SniHost select_sni_host(const nlohmann::json& s, const std::string& address,
                        const std::string& domain) {
    auto custom_cdn = to_string_list(s, "customCdnAddrs");
    bool is_custom = false;
    for (auto& a : custom_cdn) {
        if (a == address) {
            is_custom = true;
            break;
        }
    }
    SniHost out;
    if (is_custom) {
        out.sni = s.value("customCdnSni", std::string());
        out.host = s.value("customCdnHost", std::string());
        out.allow_insecure = true;
    } else {
        out.sni = random_upper_case(domain);
        out.host = domain;
        out.allow_insecure = false;
    }
    return out;
}

std::string generate_remark(const nlohmann::json& s, int index, int port, const std::string& address,
                            const std::string& protocol, const std::string& domain,
                            bool is_fragment, bool is_chain) {
    auto clean_ips = to_string_list(s, "cleanIPs");
    auto custom_cdn = to_string_list(s, "customCdnAddrs");
    std::string custom_domain = s.value("customDomain", std::string());
    std::string upstream_server;
    if (s.contains("upstreamParams") && s["upstreamParams"].is_object()) {
        upstream_server = s["upstreamParams"].value("upstreamServer", std::string());
    }

    std::string chain_sign = is_chain ? "\xF0\x9F\x94\x97 " : "";
    std::string proto_sign = (protocol == "vless") ? "VLESS" : "Trojan";
    std::string fragment_sign = is_fragment ? "F " : "";
    std::string custom_domain_sign = (!custom_domain.empty() && domain == custom_domain) ? "D " : "";
    std::string custom_cdn_sign;
    for (auto& a : custom_cdn) {
        if (a == address) custom_cdn_sign = "C ";
    }
    std::string config_type = fragment_sign + custom_domain_sign + custom_cdn_sign;

    std::string address_type;
    bool is_clean = false;
    for (auto& a : clean_ips) {
        if (a == address) is_clean = true;
    }
    if (is_clean) address_type = "Clean IP";
    else if (is_domain(address)) address_type = "Domain";
    else if (is_ipv4(address)) address_type = "IPv4";
    else if (is_ipv6(address)) address_type = "IPv6";

    std::string prefix = "\xF0\x9F\x92\xA6 " + std::to_string(index) + ". " + chain_sign +
                         proto_sign + " " + config_type;
    if (!upstream_server.empty() && address == upstream_server) {
        return prefix + "- Upstream Proxy";
    }
    return prefix + "- " + address_type + " : " + std::to_string(port);
}

} // namespace bpb::sub
