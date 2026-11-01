#include "settings/store.h"
#include "crypto/crypto.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

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
  "remoteDNS": "https://8.8.8.8/dns-query",
  "remoteDnsHost": { "isDomain": false, "host": "8.8.8.8", "ipv4": [], "ipv6": [] },
  "upstreamProxy": "",
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
  "fragmentMode": "custom",
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
    "endpoint": "162.159.192.1:2408",
    "mtu": 1200,
    "keepalive": 25,
    "useWarpAccount": true
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
  "panelVersion": "1.0.0"
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
            if (j.contains("telegramBot") && j["telegramBot"].is_object()) telegram_ = j["telegramBot"];
            if (j.contains("warpAccounts") && j["warpAccounts"].is_array()) warps_ = j["warpAccounts"];
            if (j.contains("pwd") && j["pwd"].is_string()) pwd_ = j["pwd"].get<std::string>();
            if (j.contains("secretKey") && j["secretKey"].is_string()) secret_ = j["secretKey"].get<std::string>();
        } catch (const std::exception& e) {
            error = std::string("invalid settings.json: ") + e.what();
            return false;
        }
    }

    if (warps_.empty()) {
        warps_ = nlohmann::json::parse(R"([
          {"privateKey":"4NyxMUme2zGv5r3QWI0hJBlNglm1J/thoCE55PK29G8=","publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","warpIPv6":"2606:4700:110:8fd2:11f3:8e67:11d4:3704/128","reserved":"N16D"},
          {"privateKey":"aPQwXZBOndL0km0Swo0ArDOoy3bjeZzTu+/d4YHxW04=","publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","warpIPv6":"2606:4700:110:859d:1029:4dfa:bf63:ff08/128","reserved":"SmWi"}
        ])");
    }

    if (secret_.empty()) secret_ = crypto::random_hex(32);
    return true;
}

bool Store::save(std::string& error) {
    nlohmann::json j;
    j["proxySettings"] = kv_;
    j["telegramBot"] = telegram_;
    j["warpAccounts"] = warps_;
    j["pwd"] = pwd_;
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
    return write_file_atomic(dir_ + "/config.json", cfg.dump(2), error);
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

    // The panel binds form controls by flat id, so expose the nested objects as
    // flat fields as well.
    if (out.contains("wgOutbound") && out["wgOutbound"].is_object()) {
        const auto& wg = out["wgOutbound"];
        out["wgOutboundEnabled"] = wg.value("enabled", false) ? "true" : "false";
        out["wgOutboundEndpoint"] = wg.value("endpoint", std::string{});
    }
    if (out.contains("cfTunnel") && out["cfTunnel"].is_object()) {
        const auto& ct = out["cfTunnel"];
        out["cfTunnelEnabled"] = ct.value("enabled", false) ? "true" : "false";
        out["cfTunnelToken"] = ct.value("token", std::string{});
        const std::string oh = ct.value("originHost", std::string{"127.0.0.1"});
        const int op = ct.value("originPort", 8080);
        out["cfTunnelOrigin"] = oh + ":" + std::to_string(op);
    }
    return out;
}

} // namespace bpb
