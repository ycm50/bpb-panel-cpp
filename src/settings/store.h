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
    // The public address this installation is reached at, and the port it is
    // reached on. Distinct from mainDomain on purpose: mainDomain is a name that
    // only a Cloudflare edge (or a user's own DNS) can resolve, while these
    // describe where a client dials when there is no tunnel at all. They are
    // written by the panel and default to localhost:<listen port>.
    std::string directHost;
    int directPort = 0;

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
    // JWT signing key. Re-read from settings.json on demand: the file is the
    // only copy that survives a restart, and 'bpb --passwd' rotates it so that
    // every existing session is invalidated the moment the credential changes.
    std::string secret();
    // Replaces the JWT signing key, invalidating every issued session.
    std::string rotate_secret();
    // Whether a credential is configured is answered from <data>/passwd every
    // time, not from a cached copy: the operator changes the password with
    // 'bpb --passwd' while the panel is running, and a flag captured at startup
    // made the running process keep the OLD credential (and keep accepting a
    // password that had already been replaced) until a restart. pwd_ is only the
    // legacy settings.json fallback.
    bool has_pwd() const;

    // True when only the legacy settings.json value exists (used by the login
    // path to migrate it once).
    bool has_legacy_pwd() const { return !pwd_.empty(); }

    // Transport switches as seen by the connection handlers. They run on their
    // own threads while the panel thread rewrites kv(), so reading the JSON
    // directly would be a data race on a shared object; these two flags are
    // published atomically instead (see Store::set_transport_switches).
    // Facts about the listeners this process actually opened. The subscription
    // generators need them: a port is only TLS if it is the TLS listener, and the
    // panel shows the certificate that goes with it.
    int tls_port() const { return tls_port_; }
    void set_tls_port(int p) { tls_port_ = p; }
    std::string tls_cert_path() const { return tls_cert_path_; }
    void set_tls_cert_path(const std::string& p) { tls_cert_path_ = p; }
    std::string cert_pin() const { return cert_pin_; }
    void set_cert_pin(const std::string& p) { cert_pin_ = p; }

    bool enable_xhttp() const { return enable_xhttp_.load(std::memory_order_relaxed); }
    bool enable_grpc() const { return enable_grpc_.load(std::memory_order_relaxed); }
    void set_transport_switches(bool xhttp, bool grpc) {
        enable_xhttp_.store(xhttp, std::memory_order_relaxed);
        enable_grpc_.store(grpc, std::memory_order_relaxed);
    }

    // Facts about this process that headless code (subscriptions) needs but
    // cannot parse out of argv: whether the listener actually terminates TLS
    // and which port it bound. Published at startup by main().
    void set_listen_facts(const std::string& host, int port, bool tls) {
        listen_host_ = host;
        listen_port_ = port;
        listen_tls_ = tls;
        if (cfg_.directPort <= 0) cfg_.directPort = port;
        if (cfg_.directHost.empty() || cfg_.directHost == "localhost")
            cfg_.directHost = (host.empty() || host == "0.0.0.0" || host == "::") ? "localhost" : host;
    }
    const std::string& listen_host() const { return listen_host_; }
    int listen_port() const { return listen_port_; }
    bool listen_tls() const { return listen_tls_; }

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
    int tls_port_ = 0;
    std::string tls_cert_path_;
    std::string cert_pin_;
    std::string listen_host_ = "0.0.0.0";
    int listen_port_ = 8080;
    bool listen_tls_ = false;
};

} // namespace bpb
