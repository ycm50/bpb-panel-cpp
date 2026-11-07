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
                                    const std::string& uuid, const std::string& fingerprint,
                                    const std::string& transport = "ws",
                                    const std::string& cert_pin = std::string()) {
    std::string user = uuid;
    std::string path = generate_ws_path(protocol, uuid);
    // gRPC is the only one of the three that rides on HTTP/2; XHTTP and
    // websocket stay on HTTP/1.1, which is what this server answers.
    const bool is_grpc = (transport == "grpc");

    std::string url = protocol + "://" + user + "@" + address + ":" + std::to_string(port) + "?";
    std::vector<std::string> params;
    if (protocol == "vless") params.push_back("encryption=none");
    if (is_grpc) {
        // The service name is the first path segment of the gRPC call; the
        // inbound mounts it as /vlg/Tun (see src/inbound/proto/vless_grpc.cpp).
        params.push_back("type=grpc");
        params.push_back("security=" + std::string(is_tls ? "tls" : "none"));
        params.push_back("serviceName=vlg");
        params.push_back("mode=multi");
    } else if (transport == "xhttp") {
        // XHTTP (SplitHTTP): a chunked GET downlink plus numbered POSTs uplink.
        params.push_back("type=xhttp");
        params.push_back("security=" + std::string(is_tls ? "tls" : "none"));
        params.push_back("host=" + url_encode(host));
        params.push_back("path=" + url_encode("/vlx"));
        params.push_back("mode=packet-up");
    } else {
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
    }

    if (is_tls) {
        if (is_grpc) params.push_back("authority=" + url_encode(host));
        params.push_back("sni=" + url_encode(sni));
        params.push_back("fp=" + url_encode(fingerprint));
        params.push_back("alpn=" + url_encode(is_grpc ? "h2" : "http/1.1"));
        // Self-signed: the client pins this certificate. allowInsecure was
        // removed from Xray 26.x, so the pin is the only way to trust it.
        // The share-link spelling is "pcs"; "pinnedPeerCertSha256" is the name
        // inside a JSON config and is not recognised by v2rayN / v2rayNG /
        // Xray's link importer, which silently ignore the whole line.
        if (!cert_pin.empty()) params.push_back("pcs=" + url_encode(cert_pin));
    }

    url += join(params, "&");
    url += "#" + encode_fragment(remark);
    return url;
}

// trojan:// share format: trojan://<password>@<host>:<port>?<params>#<remark>.
// The password is the panel UUID, used verbatim (see inbound/proto/trojan_ws.cpp:
// "The password is the same credential the panel already manages for VLESS").
static std::string trojan_link(const std::string& address, int port, const SniHost& sni_host,
                              const std::string& remark, bool is_tls, const std::string& password,
                              const std::string& fingerprint) {
    // No "?ed=2560" here: early data is a VLESS/VMess extension that carries the
    // first stream bytes in Sec-WebSocket-Protocol. The Trojan inbound does not
    // implement it (trojan_ws.cpp: "no early data in Trojan: the hash travels as
    // payload"), so a link advertising ed made every client send an empty
    // websocket frame the server never answers -- measured: egress 000 with ed,
    // 200 without, same host and password.
    std::string path = generate_ws_path("trojan", password);
    std::vector<std::string> params;
    params.push_back("type=ws");
    params.push_back("host=" + url_encode(sni_host.host));
    params.push_back("path=" + url_encode(path));
    params.push_back("security=" + std::string(is_tls ? "tls" : "none"));
    if (is_tls) {
        params.push_back("sni=" + url_encode(sni_host.sni));
        params.push_back("fp=" + url_encode(fingerprint));
        params.push_back("alpn=http%2F1.1");
    }
    std::string url = "trojan://" + password + "@" + address + ":" + std::to_string(port) + "?" +
                      join(params, "&");
    url += "#" + encode_fragment(remark);
    return url;
}

// ss:// share format (SIP002): ss://base64url(<method>:<password>)@host:port#remark.
// The method must be the one the inbound fixes, or the client derives a
// different key and every packet fails its tag check.
static std::string shadowsocks_link(const std::string& address, int port, const SniHost& sni_host,
                                    const std::string& remark, bool is_tls,
                                    const std::string& password, const std::string& fingerprint) {
    const std::string userinfo = base64url_encode("aes-256-gcm:" + password);
    // Same reason as trojan above: the Shadowsocks inbound has no early-data
    // support, so an ed= in the path breaks the handshake.
    std::string path = generate_ws_path("shadowsocks", password);
    std::vector<std::string> params;
    params.push_back("type=ws");
    params.push_back("host=" + url_encode(sni_host.host));
    params.push_back("path=" + url_encode(path));
    params.push_back("security=" + std::string(is_tls ? "tls" : "none"));
    if (is_tls) {
        params.push_back("sni=" + url_encode(sni_host.sni));
        params.push_back("fp=" + url_encode(fingerprint));
        params.push_back("alpn=http%2F1.1");
    }
    std::string url = "ss://" + userinfo + "@" + address + ":" + std::to_string(port) + "?" +
                      join(params, "&");
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

    // Direct mode dials the address the panel advertises, not the edge hostname
    // mainDomain may still be holding from a previous tunnel session.
    std::vector<std::string> domains{main_domain};
    if (!custom_domain.empty()) domains.push_back(custom_domain);
    if (access_mode_direct(s)) domains.assign(1, direct_host(s));

    auto protocols = get_protocols(s);
    const std::vector<std::string> transports = get_transports(s);
    std::string vl_confs;
    int proxy_index = 1;

    for (auto& domain : domains) {
        // tunnel: settings.ports intersected with the edge's https ports.
        // direct: exactly the port this process bound.
        std::vector<int> total_ports = effective_ports(s, domain);

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

                bool is_tls = port_uses_tls(s, domain, port) ||
                              (!upstream_server.empty() && addr == upstream_server);

                for (auto& proto : protocols) {
                    std::string remark =
                        generate_remark(s, proxy_index, port, addr, proto, domain, false, false);
                    // Each protocol has its own share format. The old code only
                    // handled vless and vmess and dropped everything else, so a
                    // Trojan-only or Shadowsocks-only build returned an empty
                    // subscription instead of a link.
                    if (proto == "vmess") {
                        // VMess has no URI scheme of its own: the client is given an
                        // opaque base64 JSON blob (the "vmess://" share format).
                        vl_confs += vmess_link(addr, port, sni_host, remark, is_tls, vl_uuid,
                                               fingerprint) +
                                    "\n";
                        continue;
                    }
                    if (proto == "trojan") {
                        vl_confs += trojan_link(addr, port, sni_host, remark, is_tls, vl_uuid,
                                                fingerprint) +
                                    "\n";
                        continue;
                    }
                    if (proto == "shadowsocks") {
                        vl_confs += shadowsocks_link(addr, port, sni_host, remark, is_tls, vl_uuid,
                                                     fingerprint) +
                                    "\n";
                        continue;
                    }
                    // XHTTP/gRPC are transports on VLESS and are emitted below by
                    // the transport loop; a raw subscription has no way to express
                    // them as separate lines, so nothing else is accepted here.
                    if (proto != "vless") continue;
                    for (const std::string& tr : transports) {
                        std::string url = build_config_url(proto, addr, port, sni_host.host,
                                                           sni_host.sni, remark + transport_suffix(tr),
                                                           is_tls, client, vl_uuid, fingerprint, tr,
                                                           pinned_cert(s));
                        vl_confs += url + "\n";
                    }
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
