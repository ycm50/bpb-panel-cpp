#pragma once
#include <nlohmann/json.hpp>
#include <atomic>
#include <string>
#include <vector>

namespace bpb {

struct Config {
    std::string accID = "native";
    std::string accEmail = "admin";
    std::string vlUUID;
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
    const nlohmann::json& kv() const { return kv_; }
    nlohmann::json& warps() { return warps_; }
    std::string& pwd() { return pwd_; }
    std::string& secret() { return secret_; }
    bool has_pwd() const { return !pwd_.empty(); }

    // Transport switches as seen by the connection handlers. They run on their
    // own threads while the panel thread rewrites kv(), so reading the JSON
    // directly would be a data race on a shared object; these two flags are
    // published atomically instead (see Store::set_transport_switches).
    bool enable_xhttp() const { return enable_xhttp_.load(std::memory_order_relaxed); }
    bool enable_grpc() const { return enable_grpc_.load(std::memory_order_relaxed); }
    void set_transport_switches(bool xhttp, bool grpc) {
        enable_xhttp_.store(xhttp, std::memory_order_relaxed);
        enable_grpc_.store(grpc, std::memory_order_relaxed);
    }

    // Data directory the store was loaded from; used to place auxiliary files
    // such as the exported wg0.conf.
    const std::string& dir() const { return dir_; }

    static nlohmann::json default_kv();

    // merged view used by the panel and subscription generators
    nlohmann::json merged() const;

private:
    std::string dir_;
    Config cfg_;
    nlohmann::json kv_;
    nlohmann::json warps_ = nlohmann::json::array();
    std::string pwd_;
    std::string secret_;
    std::atomic<bool> enable_xhttp_{false};
    std::atomic<bool> enable_grpc_{false};
};

} // namespace bpb
