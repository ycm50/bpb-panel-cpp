#include "sub/common.h"
#include "util/util.h"
#include "util/zip.h"

#include <nlohmann/json.hpp>

namespace bpb::sub {

bool build_wireguard_conf(const nlohmann::json& s, const nlohmann::json& warp_accounts,
                          std::string& out_conf, std::string& error) {
    if (!warp_accounts.is_array() || warp_accounts.empty()) {
        error = "warp accounts are missing";
        return false;
    }
    auto& account = warp_accounts[0];
    std::string endpoint;
    auto endpoints = to_string_list(s, "warpEndpoints");
    if (!endpoints.empty()) endpoint = endpoints.front();
    if (endpoint.empty()) endpoint = "engage.cloudflareclient.com:2408";

    out_conf = "[Interface]\n";
    out_conf += "PrivateKey = " + account.value("privateKey", std::string()) + "\n";
    out_conf += "Address = 172.16.0.2/32, " + account.value("warpIPv6", std::string()) + "\n";
    out_conf += "DNS = " + s.value("warpRemoteDNS", std::string("1.1.1.1")) + "\n";
    out_conf += "MTU = 1280\n";
    out_conf += "\n[Peer]\n";
    out_conf += "PublicKey = " + account.value("publicKey", std::string()) + "\n";
    out_conf += "AllowedIPs = 0.0.0.0/0, ::/0\n";
    out_conf += "Endpoint = " + endpoint + "\n";
    out_conf += "PersistentKeepalive = 25\n";
    return true;
}

bool build_wireguard_zip(const nlohmann::json& s, const nlohmann::json& warp_accounts, bool is_pro,
                         std::string& out_zip, std::string& error) {
    if (!warp_accounts.is_array() || warp_accounts.empty()) {
        error = "warp accounts are missing";
        return false;
    }
    auto& account = warp_accounts[0];
    std::string private_key = account.value("privateKey", std::string());
    std::string public_key = account.value("publicKey", std::string());
    std::string warp_ipv6 = account.value("warpIPv6", std::string());
    std::string warp_dns = s.value("warpRemoteDNS", std::string("1.1.1.1"));
    int noise_count = s.value("amneziaNoiseCount", 5);
    int noise_min = s.value("amneziaNoiseSizeMin", 50);
    int noise_max = s.value("amneziaNoiseSizeMax", 100);

    auto endpoints = to_string_list(s, "warpEndpoints");
    if (endpoints.empty()) {
        error = "no warp endpoints configured";
        return false;
    }

    std::vector<std::pair<std::string, std::string>> entries;
    int index = 1;
    for (auto& endpoint : endpoints) {
        std::string conf = "[Interface]\n";
        conf += "PrivateKey = " + private_key + "\n";
        conf += "Address = 172.16.0.2/32, " + warp_ipv6 + "\n";
        conf += "DNS = " + warp_dns + "\n";
        conf += "MTU = 1280\n";
        if (is_pro) {
            conf += "Jc = " + std::to_string(noise_count) + "\n";
            conf += "Jmin = " + std::to_string(noise_min) + "\n";
            conf += "Jmax = " + std::to_string(noise_max) + "\n";
            conf += "S1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n";
        }
        conf += "\n[Peer]\n";
        conf += "PublicKey = " + public_key + "\n";
        conf += "AllowedIPs = 0.0.0.0/0, ::/0\n";
        conf += "Endpoint = " + endpoint + "\n";
        conf += "PersistentKeepalive = 25\n";
        entries.emplace_back("BPB-Warp-" + std::to_string(index) + ".conf", conf);
        ++index;
    }

    out_zip = zip_store(entries);
    return true;
}

} // namespace bpb::sub
