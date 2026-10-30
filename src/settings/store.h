#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace bpb {

struct Config {
    std::string accID = "native";
    std::string accEmail = "admin";
    std::string vlUUID;
    std::string trPass;
    std::string securePath = "securepath";
    std::string mainDomain = "localhost";
    std::string fallback;
    std::string dohUrl = "https://cloudflare-dns.com/dns-query";
    std::string proxyIpMode = "proxyip";
    std::vector<std::string> proxyIPs;
    std::vector<std::string> prefixes;
};

class Store {
public:
    bool load(const std::string& dir, std::string& error);
    bool save(std::string& error);

    const Config& config() const { return cfg_; }
    Config& config() { return cfg_; }

    nlohmann::json& kv() { return kv_; }
    nlohmann::json& telegram() { return telegram_; }
    nlohmann::json& warps() { return warps_; }
    std::string& pwd() { return pwd_; }
    std::string& secret() { return secret_; }
    bool has_pwd() const { return !pwd_.empty(); }

    static nlohmann::json default_kv();

    // merged view used by the panel and subscription generators
    nlohmann::json merged() const;

private:
    std::string dir_;
    Config cfg_;
    nlohmann::json kv_;
    nlohmann::json telegram_ = {{"telegramBotToken", ""}, {"telegramUserId", ""}};
    nlohmann::json warps_ = nlohmann::json::array();
    std::string pwd_;
    std::string secret_;
};

} // namespace bpb
