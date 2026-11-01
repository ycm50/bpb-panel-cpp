#include "sub/raw.h"
#include "sub/common.h"
#include "util/util.h"

#include <cstdlib>

namespace bpb::sub {

static std::string encode_fragment(const std::string& in) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : in) {
        if (c == ' ' || c == '"' || c == '<' || c == '>' || c == 0x60 || c < 0x21) {
            out += '%';
            out += hex[(c >> 4) & 15];
            out += hex[c & 15];
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

static std::string build_config_url(const std::string& protocol, const std::string& address,
                                    int port, const std::string& host, const std::string& sni,
                                    const std::string& remark, bool is_tls, const std::string& client,
                                    const std::string& uuid, const std::string& fingerprint) {
    std::string user = uuid;
    std::string path = generate_ws_path(protocol, uuid);

    std::string url = protocol + "://" + user + "@" + address + ":" + std::to_string(port) + "?";
    std::vector<std::string> params;
    if (protocol == "vless") params.push_back("encryption=none");
    params.push_back("host=" + url_encode(host));
    params.push_back("type=ws");
    params.push_back("security=" + std::string(is_tls ? "tls" : "none"));

    if (client == "sing-box") {
        params.push_back("eh=Sec-WebSocket-Protocol");
        params.push_back("ed=2560");
        params.push_back("path=" + url_encode(path));
    } else {
        params.push_back("path=" + url_encode(path + "?ed=2560"));
    }

    if (is_tls) {
        params.push_back("sni=" + url_encode(sni));
        params.push_back("fp=" + url_encode(fingerprint));
        params.push_back("alpn=" + url_encode("http/1.1"));
    }

    url += join(params, "&");
    url += "#" + encode_fragment(remark);
    return url;
}

// vmess:// share format: base64 of a JSON object, as imported by v2rayN,
// NekoBox and friends. The WebSocket path carries the credential ("<uuid>-vm"),
// which is exactly what this build's dispatcher matches.
static std::string vmess_link(const std::string& address, int port, const SniHost& sni_host,
                              const std::string& remark, bool is_tls, const std::string& uuid,
                              const std::string& fingerprint) {
    std::string clean;
    for (char c : uuid) {
        if (c != '-') clean += c;
    }
    nlohmann::json j;
    j["v"] = "2";
    j["ps"] = remark;
    j["add"] = address;
    j["port"] = std::to_string(port);
    j["id"] = uuid;
    j["aid"] = "0";
    j["scy"] = "auto";
    j["net"] = "ws";
    j["type"] = "none";
    j["host"] = sni_host.host;
    j["path"] = "/" + clean + "-vm";
    j["tls"] = is_tls ? "tls" : "";
    if (is_tls) {
        j["sni"] = sni_host.sni;
        j["alpn"] = "http/1.1";
        j["fp"] = fingerprint;
    }
    return "vmess://" + base64_encode(j.dump());
}

SubResult build_raw_configs(const nlohmann::json& s, const std::string& client) {
    SubResult result;
    std::string fingerprint = s.value("fingerprint", std::string("chrome"));
    std::string custom_domain = s.value("customDomain", std::string());
    std::string main_domain = s.value("mainDomain", std::string("localhost"));
    std::string vl_uuid = s.value("vlUUID", std::string());

    std::string upstream_server;
    int upstream_port = 0;
    if (s.contains("upstreamParams") && s["upstreamParams"].is_object()) {
        upstream_server = s["upstreamParams"].value("upstreamServer", std::string());
        upstream_port = s["upstreamParams"].value("upstreamPort", 0);
    }

    std::vector<int> ports;
    if (s.contains("ports") && s["ports"].is_array()) {
        for (auto& p : s["ports"]) {
            if (p.is_number_integer()) ports.push_back(p.get<int>());
        }
    }

    std::vector<std::string> domains{main_domain};
    if (!custom_domain.empty()) domains.push_back(custom_domain);

    auto protocols = get_protocols(s);
    std::string vl_confs;
    int proxy_index = 1;

    for (auto& domain : domains) {
        std::vector<int> total_ports;
        bool is_workers_dev = ends_with(domain, "workers.dev");
        for (int port : ports) {
            if (is_workers_dev || is_https(s, port)) total_ports.push_back(port);
        }

        std::string error;
        auto addrs = get_config_addresses(s, domain, false, error);
        if (addrs.empty()) {
            result.status = 500;
            result.body = "Failed to resolve " + domain + ": " + error;
            return result;
        }

        if (!upstream_server.empty() && upstream_port) {
            total_ports.insert(total_ports.begin(), upstream_port);
            addrs.insert(addrs.begin(), upstream_server);
        }

        for (int port : total_ports) {
            for (auto& addr : addrs) {
                auto sni_host = select_sni_host(s, addr, domain);
                bool port_is_upstream = (port == upstream_port);
                bool addr_is_upstream = (!upstream_server.empty() && addr == upstream_server);
                if (port_is_upstream != addr_is_upstream) continue;

                bool is_tls = is_https(s, port) || (!upstream_server.empty() && addr == upstream_server);

                for (auto& proto : protocols) {
                    std::string remark =
                        generate_remark(s, proxy_index, port, addr, proto, domain, false, false);
                    if (proto == "vmess") {
                        // VMess has no URI scheme of its own: the client is given an
                        // opaque base64 JSON blob (the "vmess://" share format).
                        vl_confs += vmess_link(addr, port, sni_host, remark, is_tls, vl_uuid,
                                               fingerprint) +
                                    "\n";
                        continue;
                    }
                    if (proto != "vless") continue;
                    std::string url = build_config_url(proto, addr, port, sni_host.host, sni_host.sni,
                                                       remark, is_tls, client, vl_uuid, fingerprint);
                    vl_confs += url + "\n";
                }
                ++proxy_index;
            }
        }
    }

    result.body = vl_confs;
    result.dns = s.value("remoteDNS", std::string());
    result.profile_title = "base64:" + base64_encode(std::string("\xF0\x9F\x92\xA6 BPB Raw"));
    return result;
}

} // namespace bpb::sub
