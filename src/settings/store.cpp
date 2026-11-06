#include "settings/store.h"
#include "app/passwd.h"
#include "crypto/crypto.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace bpb {

static const char* kDefaultKvJson = R"({
  "localDNS": "8.8.8.8",
  "antiSanctionDNS": "178.22.122.100",
  "fakeDNS": false,
  "enableIPv6": false,
  "allowLANConnection": false,
  "logLevel": "warning",
  "customDomain": "",
  "protocols": "vless",
  "enableXHTTP": false,
  "enableGRPC": false,
  "remoteDNS": "https://8.8.8.8/dns-query",
  "remoteDnsHost": { "isDomain": false, "host": "8.8.8.8", "ipv4": [], "ipv6": [] },
  "upstreamParams": { "upstreamServer": "", "upstreamPort": 0 },
  "chainProxy": "",
  "chainProxyParams": {},
  "cleanIPs": ["www.speedtest.net"],
  "ports": [443],
  "fingerprint": "chrome",
  "bestPingInterval": 30,
  "enableTFO": false,
  "enableECH": false,
  "echServerName": "",
  "customCdnAddrs": [],
  "customCdnHost": "",
  "customCdnSni": "",
  "fragmentPackets": "tlshello",
  "fragmentLengthMin": 100,
  "fragmentLengthMax": 200,
  "fragmentDelayMin": 1,
  "fragmentDelayMax": 1,
  "fragmentMaxSplitMin": 0,
  "fragmentMaxSplitMax": 0,
  "customSubs": [],
  "customConfigs": [],
  "warpRemoteDNS": "1.1.1.1",
  "warpEndpoints": ["engage.cloudflareclient.com:2408"],
  "warpBestPingInterval": 30,
  "warpReservedBytes": true,
  "warpRegisterDryRun": true,
  "wgOutbound": {
    "enabled": false,
    "binary": "",
    "bindHost": "127.0.0.1",
    "socksPort": 11080,
    "dataDir": "",
    "mtu": 1280,
    "maxConnections": 0
  },
  "cfTunnel": {
    "enabled": false,
    "token": "",
    "edgeHost": "region1.v2.argotunnel.com",
    "edgePort": 7844,
    "originHost": "127.0.0.1",
    "originPort": 8080
  },
  "xrayUdpNoises": [{ "type": "rand", "packet": "50-100", "delay": "1-5", "count": 5 }],
  "knockerNoiseMode": "quic",
  "knockerNoiseCountMin": 10,
  "knockerNoiseCountMax": 15,
  "knockerNoiseSizeMin": 5,
  "knockerNoiseSizeMax": 10,
  "knockerNoiseDelayMin": 1,
  "knockerNoiseDelayMax": 1,
  "amneziaNoiseCount": 5,
  "amneziaNoiseSizeMin": 50,
  "amneziaNoiseSizeMax": 100,
  "bypassIran": false,
  "bypassChina": false,
  "bypassRussia": false,
  "bypassOpenAi": false,
  "bypassGoogleAi": false,
  "bypassMicrosoft": false,
  "bypassOracle": false,
  "bypassDocker": false,
  "bypassAdobe": false,
  "bypassEpicGames": false,
  "bypassIntel": false,
  "bypassAmd": false,
  "bypassNvidia": false,
  "bypassAsus": false,
  "bypassHp": false,
  "bypassLenovo": false,
  "blockAds": false,
  "blockPorn": false,
  "blockUDP443": false,
  "blockMalware": false,
  "blockPhishing": false,
  "blockCryptominers": false,
  "customBypassRules": [],
  "customBlockRules": [],
  "customBypassSanctionRules": [],
  "remoteSettings": "",
  "panelVersion": "1.0.2"
})";

nlohmann::json Store::default_kv() {
    try {
        return nlohmann::json::parse(kDefaultKvJson);
    } catch (const std::exception& e) {
        // Never swallow this: an unparsable default blob silently yields an
        // empty settings object and every panel default disappears.
        std::fprintf(stderr, "fatal: built-in default settings are not valid JSON: %s\n",
                     e.what());
        std::abort();
    }
}

static bool read_file(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

static bool write_file_atomic(const std::string& path, const std::string& data, std::string& error) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            error = "cannot write " + tmp;
            return false;
        }
        f.write(data.data(), static_cast<std::streamsize>(data.size()));
        if (!f.good()) {
            error = "write failed for " + tmp;
            return false;
        }
    }
    std::remove(path.c_str());
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        error = "rename failed for " + path;
        return false;
    }
    return true;
}

bool Store::reload_from_disk(std::string& error) {
    // Everything the files own is reset first: load() only overwrites keys that
    // are present, so a key someone deleted from settings.json would otherwise
    // survive in memory and be written straight back on the next save.
    cfg_ = Config{};
    kv_ = nlohmann::json::object();
    warps_ = nlohmann::json::array();
    pwd_.clear();
    secret_.clear();

    // Process facts, not file facts. load() calls set_listen_facts() with the
    // argv values, and that would overwrite the real listener port with a
    // default if it were ever re-run from here.
    const std::string host = listen_host_;
    const int port = listen_port_;
    const bool tls = listen_tls_;
    const int tls_port = tls_port_;
    const std::string tls_cert = tls_cert_path_;
    const std::string cert_pin = cert_pin_;

    if (!load(dir_, error)) return false;

    listen_host_ = host;
    listen_port_ = port;
    listen_tls_ = tls;
    tls_port_ = tls_port;
    tls_cert_path_ = tls_cert;
    cert_pin_ = cert_pin;
    return true;
}

bool Store::load(const std::string& dir, std::string& error) {
    dir_ = dir;

    // the data directory is created on first run (containers mount it, native runs do not have it)
    std::error_code ec;
    std::filesystem::create_directories(dir_, ec);
    if (ec && !std::filesystem::is_directory(dir_)) {
        error = "cannot create data directory " + dir_ + ": " + ec.message();
        return false;
    }

    std::string cfgPath = dir_ + "/config.json";
    std::string storePath = dir_ + "/settings.json";
    std::string text;

    kv_ = default_kv();

    if (read_file(cfgPath, text)) {
        try {
            auto j = nlohmann::json::parse(text);
            if (j.contains("accID")) cfg_.accID = j["accID"].get<std::string>();
            if (j.contains("accEmail")) cfg_.accEmail = j["accEmail"].get<std::string>();
            if (j.contains("vlUUID")) cfg_.vlUUID = j["vlUUID"].get<std::string>();
            if (j.contains("securePath")) cfg_.securePath = j["securePath"].get<std::string>();
            if (j.contains("mainDomain")) cfg_.mainDomain = j["mainDomain"].get<std::string>();
            if (j.contains("fallback")) cfg_.fallback = j["fallback"].get<std::string>();
            if (j.contains("dohUrl")) cfg_.dohUrl = j["dohUrl"].get<std::string>();
            if (j.contains("proxyIpMode")) cfg_.proxyIpMode = j["proxyIpMode"].get<std::string>();
            if (j.contains("proxyIPs")) cfg_.proxyIPs = j["proxyIPs"].get<std::vector<std::string>>();
            if (j.contains("prefixes")) cfg_.prefixes = j["prefixes"].get<std::vector<std::string>>();
            // Address a client dials when there is no tunnel. Written by the
            // panel; absent in a config.json from before this field existed, in
            // which case set_listen_facts() seeds it at startup.
            if (j.contains("directHost") && j["directHost"].is_string())
                cfg_.directHost = j["directHost"].get<std::string>();
            if (j.contains("directPort")) {
                if (j["directPort"].is_number_integer())
                    cfg_.directPort = j["directPort"].get<int>();
                else if (j["directPort"].is_string())
                    cfg_.directPort = std::atoi(j["directPort"].get<std::string>().c_str());
            }
        } catch (const std::exception& e) {
            error = std::string("invalid config.json: ") + e.what();
            return false;
        }
    }

    if (cfg_.vlUUID.empty()) cfg_.vlUUID = crypto::random_hex(16);

    if (read_file(storePath, text)) {
        try {
            auto j = nlohmann::json::parse(text);
            if (j.contains("proxySettings") && j["proxySettings"].is_object()) {
                auto stored = j["proxySettings"];
                for (auto it = stored.begin(); it != stored.end(); ++it) {
                    if (kv_.contains(it.key())) kv_[it.key()] = it.value();
                }
            }
            if (j.contains("warpAccounts") && j["warpAccounts"].is_array()) warps_ = j["warpAccounts"];
            if (j.contains("pwd") && j["pwd"].is_string()) pwd_ = j["pwd"].get<std::string>();
            if (j.contains("secretKey") && j["secretKey"].is_string()) secret_ = j["secretKey"].get<std::string>();
        } catch (const std::exception& e) {
            error = std::string("invalid settings.json: ") + e.what();
            return false;
        }
    }

    // No placeholder accounts. This used to fall back to two hard-coded WARP
    // registrations, which looked like a working pool but were dead keys: the
    // handshake never completed, the outbound silently stayed down, and every
    // connection quietly used a direct socket while the panel reported
    // "WireGuard 已启用" and a trace still answered warp=off. An empty pool is
    // the honest state -- the panel asks for a registration, and the save path
    // refuses to enable the outbound until one exists.

    if (secret_.empty()) secret_ = crypto::random_hex(32);

    // Publish the transport switches for the connection handlers, which run on
    // other threads and must not read kv_ while the panel writes it.
    set_transport_switches(kv_.value("enableXHTTP", false), kv_.value("enableGRPC", false));
    return true;
}

bool Store::save(std::string& error) {
    set_transport_switches(kv_.value("enableXHTTP", false), kv_.value("enableGRPC", false));
    nlohmann::json j;
    j["proxySettings"] = kv_;
    j["warpAccounts"] = warps_;
    // Only the "a credential exists" marker is ever persisted here; the salted
    // hash lives in <data>/passwd. Writing the plaintext made settings.json a
    // password file that shipped with every settings export.
    j["pwd"] = pwd_.empty() ? std::string() : std::string("\x01");
    j["secretKey"] = secret_;
    if (!write_file_atomic(dir_ + "/settings.json", j.dump(2), error)) return false;

    nlohmann::json cfg;
    cfg["accID"] = cfg_.accID;
    cfg["accEmail"] = cfg_.accEmail;
    cfg["vlUUID"] = cfg_.vlUUID;
    cfg["securePath"] = cfg_.securePath;
    cfg["mainDomain"] = cfg_.mainDomain;
    cfg["fallback"] = cfg_.fallback;
    cfg["dohUrl"] = cfg_.dohUrl;
    cfg["proxyIpMode"] = cfg_.proxyIpMode;
    cfg["proxyIPs"] = cfg_.proxyIPs;
    cfg["prefixes"] = cfg_.prefixes;
    cfg["directHost"] = cfg_.directHost;
    cfg["directPort"] = cfg_.directPort;
    return write_file_atomic(dir_ + "/config.json", cfg.dump(2), error);
}

std::size_t Store::warp_accounts_on_disk() const {
    std::string text;
    if (!read_file(dir_ + "/settings.json", text)) return 0;
    auto j = nlohmann::json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.contains("warpAccounts") || !j["warpAccounts"].is_array()) return 0;
    return j["warpAccounts"].size();
}

std::string Store::secret() {
    // Fresh read: an in-memory copy meant a rotated key was ignored until the
    // next restart, so a stolen cookie kept working after a password change.
    std::ifstream in(dir_ + "/settings.json", std::ios::binary);
    if (in) {
        std::stringstream ss;
        ss << in.rdbuf();
        auto j = nlohmann::json::parse(ss.str(), nullptr, false);
        if (!j.is_discarded() && j.contains("secretKey") && j["secretKey"].is_string()) {
            const std::string fresh = j["secretKey"].get<std::string>();
            if (!fresh.empty()) {
                secret_ = fresh;
                return secret_;
            }
        }
    }
    if (secret_.empty()) secret_ = crypto::random_hex(32);
    return secret_;
}

std::string Store::rotate_secret() {
    secret_ = crypto::random_hex(32);
    return secret_;
}

bool Store::has_pwd() const {
    // Read the file, do not trust memory. 'bpb --passwd' rewrites <data>/passwd
    // at any time and the running process must see it immediately -- both to
    // start demanding a login and to stop accepting the old password.
    bpb::app::passwd::Entry entry;
    if (bpb::app::passwd::load(dir_, entry)) return true;
    // Legacy fallback: installs that predate the file kept the value in
    // settings.json.
    return !pwd_.empty();
}

nlohmann::json Store::merged() const {
    nlohmann::json out = kv_;
    out["vlUUID"] = cfg_.vlUUID;
    out["securePath"] = cfg_.securePath;
    out["mainDomain"] = cfg_.mainDomain;
    out["fallback"] = cfg_.fallback;
    out["dohUrl"] = cfg_.dohUrl;
    out["proxyIpMode"] = cfg_.proxyIpMode;
    out["proxyIPs"] = cfg_.proxyIPs;
    out["prefixes"] = cfg_.prefixes;
    out["accEmail"] = cfg_.accEmail;
    // Where a client dials when the tunnel is off, and what this process can
    // actually terminate. A subscription must not say security=tls on a listener
    // that was started without --tls-cert, and it must not name a
    // *.trycloudflare.com host once the tunnel is asleep.
    out["directHost"] = cfg_.directHost;
    out["directPort"] = cfg_.directPort;
    // The TLS listener, when one was opened: subscriptions must publish that
    // port (and only that port) as security=tls, with the certificate pin.
    out["tlsPort"] = tls_port_;
    // The pin itself is injected by App (it owns the certificate file); keeping
    // OpenSSL out of the settings layer.
    out["certPin"] = cert_pin_;
    out["listenPort"] = listen_port_;
    out["listenTls"] = listen_tls_;
    {
        const bool tunnel_on = out.contains("cfTunnel") && out["cfTunnel"].is_object() &&
                               out["cfTunnel"].value("enabled", false);
        out["accessMode"] = tunnel_on ? "tunnel" : "direct";
    }

    // The panel binds form controls by flat id, so expose the nested objects as
    // flat fields as well.
    if (out.contains("wgOutbound") && out["wgOutbound"].is_object()) {
        const auto& wg = out["wgOutbound"];
        out["wgOutboundEnabled"] = wg.value("enabled", false) ? "true" : "false";
        const std::string bh = wg.value("bindHost", std::string{"127.0.0.1"});
        const int sp = wg.value("socksPort", 11080);
        out["wgOutboundSocks"] = bh + ":" + std::to_string(sp);
    }
    if (out.contains("cfTunnel") && out["cfTunnel"].is_object()) {
        const auto& ct = out["cfTunnel"];
        out["cfTunnelEnabled"] = ct.value("enabled", false) ? "true" : "false";
        out["cfTunnelToken"] = ct.value("token", std::string{});
        // Reported, never accepted: the connector's origin is this process's own
        // listener, so the value shown here is the derived truth the save path
        // writes back, not something the operator can type.
        out["cfTunnelOrigin"] = "127.0.0.1:" + std::to_string(listen_port_);
    }
    return out;
}

} // namespace bpb
