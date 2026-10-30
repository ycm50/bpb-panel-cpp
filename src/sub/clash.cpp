#include "sub/clash.h"
#include "sub/common.h"
#include "util/util.h"

#include <algorithm>
#include <cstdlib>
#include <map>

namespace bpb::sub {

using json = nlohmann::json;

namespace {

const char* FLASH = "\xF0\x9F\x92\xA6";
const char* LINK = "\xF0\x9F\x94\x97";
const char* ROCKET = "\xF0\x9F\x9A\x80";
const char* IRAN = "\xF0\x9F\x87\xAE\xF0\x9F\x87\xB7";
const char* GLOBE = "\xF0\x9F\x8C\x8D";
const char* CHECK = "\xE2\x9C\x85";

std::string str(const json& s, const char* key, const char* fallback = "") {
    if (s.contains(key) && s[key].is_string()) return s[key].get<std::string>();
    return fallback;
}

bool flag(const json& s, const char* key) {
    return s.contains(key) && s[key].is_boolean() && s[key].get<bool>();
}

int num(const json& s, const char* key, int fallback = 0) {
    if (s.contains(key) && s[key].is_number()) return s[key].get<int>();
    return fallback;
}

struct GeoEntry {
    const char* rule;
    const char* type;
    const char* dns;
    const char* format;
    const char* geosite;
    const char* geosite_url;
    const char* geoip;
    const char* geoip_url;
};

const GeoEntry GEO_TABLE[] = {
    {"blockMalware", "block", "", "text", "malware", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware.txt", "malware-cidr", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/malware-ip.txt"},
    {"blockPhishing", "block", "", "text", "phishing", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing.txt", "phishing-cidr", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/phishing-ip.txt"},
    {"blockCryptominers", "block", "", "text", "cryptominers", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/cryptominers.txt", "", ""},
    {"blockAds", "block", "", "text", "category-ads-all", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt", "", ""},
    {"blockPorn", "block", "", "text", "nsfw", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/nsfw.txt", "", ""},
    {"bypassIran", "direct", "local", "text", "ir", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt", "ir-cidr", "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt"},
    {"bypassChina", "direct", "local", "yaml", "cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.yaml", "cn-cidr", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.yaml"},
    {"bypassRussia", "direct", "local", "yaml", "ru", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ru.yaml", "ru-cidr", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ru.yaml"},
    {"bypassOpenAi", "direct", "sanction", "yaml", "openai", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.yaml", "", ""},
    {"bypassGoogleAi", "direct", "sanction", "yaml", "googleai", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google-deepmind.yaml", "", ""},
    {"bypassMicrosoft", "direct", "sanction", "yaml", "microsoft", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.yaml", "", ""},
    {"bypassOracle", "direct", "sanction", "yaml", "oracle", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/oracle.yaml", "", ""},
    {"bypassDocker", "direct", "sanction", "yaml", "docker", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/docker.yaml", "", ""},
    {"bypassAdobe", "direct", "sanction", "yaml", "adobe", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/adobe.yaml", "", ""},
    {"bypassEpicGames", "direct", "sanction", "yaml", "epicgames", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/epicgames.yaml", "", ""},
    {"bypassIntel", "direct", "sanction", "yaml", "intel", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/intel.yaml", "", ""},
    {"bypassAmd", "direct", "sanction", "yaml", "amd", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/amd.yaml", "", ""},
    {"bypassNvidia", "direct", "sanction", "yaml", "nvidia", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/nvidia.yaml", "", ""},
    {"bypassAsus", "direct", "sanction", "yaml", "asus", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/asus.yaml", "", ""},
    {"bypassHp", "direct", "sanction", "yaml", "hp", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/hp.yaml", "", ""},
    {"bypassLenovo", "direct", "sanction", "yaml", "lenovo", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/lenovo.yaml", "", ""},
};

struct GeoRule {
    std::string type, geosite, geoip, dns, format, geosite_url, geoip_url;
};

std::vector<GeoRule> geo_assets(const json& s) {
    std::string local_dns = str(s, "localDNS");
    std::string sanction = str(s, "antiSanctionDNS");
    std::vector<GeoRule> out;
    for (auto& e : GEO_TABLE) {
        if (!flag(s, e.rule)) continue;
        GeoRule g;
        g.type = e.type;
        g.format = e.format;
        g.geosite = e.geosite;
        g.geosite_url = e.geosite_url;
        g.geoip = e.geoip;
        g.geoip_url = e.geoip_url;
        if (std::string(e.dns) == "local") g.dns = local_dns;
        else if (std::string(e.dns) == "sanction") g.dns = sanction;
        out.push_back(g);
    }
    return out;
}

struct RoutingAcc {
    std::vector<std::string> block_geosites, block_domains, block_geoips, block_ips;
    std::vector<std::string> bypass_geosites, bypass_domains, bypass_geoips, bypass_ips;
};

RoutingAcc acc_routing_rules(const json& s, const std::vector<GeoRule>& geos) {
    RoutingAcc out;
    for (auto& g : geos) {
        if (g.type == "block") {
            out.block_geosites.push_back(g.geosite);
            if (!g.geoip.empty()) out.block_geoips.push_back(g.geoip);
        } else if (g.type == "direct") {
            out.bypass_geosites.push_back(g.geosite);
            if (!g.geoip.empty()) out.bypass_geoips.push_back(g.geoip);
        }
    }
    auto add_list = [&](const std::string& key, std::vector<std::string>& domains,
                        std::vector<std::string>& ips) {
        for (auto& r : to_string_list(s, key.c_str())) {
            if (is_domain(r)) domains.push_back(r);
            else ips.push_back(r);
        }
    };
    add_list("customBypassRules", out.bypass_domains, out.bypass_ips);
    add_list("customBypassSanctionRules", out.bypass_domains, out.bypass_ips);
    add_list("customBlockRules", out.block_domains, out.block_ips);
    return out;
}

struct DnsAcc {
    std::vector<std::pair<std::string, std::string>> local_geosite_geoip;
    std::vector<std::string> local_geosites, local_domains, sanction_geosites, sanction_domains;
    std::vector<std::string> block_geosites, block_domains;
};

DnsAcc acc_dns_rules(const json& s, const std::vector<GeoRule>& geos) {
    DnsAcc out;
    std::string local_dns = str(s, "localDNS");
    std::string sanction = str(s, "antiSanctionDNS");
    for (auto& g : geos) {
        if (g.type == "direct") {
            if (!g.geoip.empty() && g.dns == local_dns) out.local_geosite_geoip.emplace_back(g.geosite, g.geoip);
            else if (g.geoip.empty() && g.dns == local_dns) out.local_geosites.push_back(g.geosite);
            if (!g.dns.empty() && g.dns == sanction) out.sanction_geosites.push_back(g.geosite);
        } else if (g.type == "block") {
            out.block_geosites.push_back(g.geosite);
        }
    }
    for (auto& r : to_string_list(s, "customBypassRules"))
        if (is_domain(r)) out.local_domains.push_back(r);
    for (auto& r : to_string_list(s, "customBypassSanctionRules"))
        if (is_domain(r)) out.sanction_domains.push_back(r);
    for (auto& r : to_string_list(s, "customBlockRules"))
        if (is_domain(r)) out.block_domains.push_back(r);
    return out;
}

std::string host_of(const std::string& value) {
    std::string host = value;
    auto scheme = host.find("://");
    if (scheme != std::string::npos) host = host.substr(scheme + 3);
    auto slash = host.find('/');
    if (slash != std::string::npos) host = host.substr(0, slash);
    auto hash = host.find('#');
    if (hash != std::string::npos) host = host.substr(0, hash);
    auto colon = host.rfind(':');
    if (colon != std::string::npos && host.find(']') == std::string::npos) host = host.substr(0, colon);
    return host;
}

json build_tls(const json& s, const std::string& protocol, const std::string& security,
               bool allow_insecure, const std::string& sni, bool enable_ech,
               const std::string& ech_name, const std::string& alpn, const std::string& fp,
               const std::string& public_key = "", const std::string& short_id = "") {
    json out = json::object();
    if (security != "tls" && security != "reality") return out;

    out["tls"] = true;
    out[protocol == "trojan" ? "sni" : "servername"] = sni;
    if (!fp.empty()) out["client-fingerprint"] = (fp == "randomized") ? "random" : fp;
    out["skip-cert-verify"] = allow_insecure;

    if (security == "tls") {
        if (!alpn.empty()) {
            std::vector<std::string> alpns;
            for (auto& a : split(alpn, ',')) alpns.push_back(a);
            out["alpn"] = alpns;
        }
        if (enable_ech) {
            json ech = {{"enable", true}};
            if (!ech_name.empty()) ech["query-server-name"] = ech_name;
            out["ech-opts"] = ech;
        }
        return out;
    }
    if (security == "reality" && !public_key.empty() && !short_id.empty()) {
        out["reality-opts"] = {{"public-key", public_key}, {"short-id", short_id}};
        return out;
    }
    return json::object();
}

json build_transport(const std::string& type, const std::string& header_type,
                     const std::string& raw_path, const std::string& host,
                     const std::string& service_name, int early_data) {
    std::string path = raw_path.empty() ? "/" : raw_path;
    auto q = path.find('?');
    if (q != std::string::npos) path = path.substr(0, q);

    if (type == "tcp") {
        if (header_type == "http") {
            std::vector<std::string> hosts, paths;
            if (!host.empty()) {
                for (auto& h : split(host, ',')) hosts.push_back(h);
            }
            for (auto& p : split(path, ',')) paths.push_back(p);
            json headers = {{"Host", hosts},
                            {"Connection", json::array({"keep-alive"})},
                            {"Content-Type", json::array({"application/octet-stream"})}};
            return {{"network", "http"},
                    {"http-opts", {{"method", "GET"}, {"path", paths}, {"headers", headers}}}};
        }
        return {{"network", "tcp"}};
    }
    if (type == "ws" || type.empty()) {
        json ws = json::object();
        ws["path"] = path;
        if (early_data > 0) {
            ws["max-early-data"] = early_data;
            ws["early-data-header-name"] = "Sec-WebSocket-Protocol";
        }
        if (!host.empty()) ws["headers"] = {{"Host", host}};
        return {{"network", "ws"}, {"ws-opts", ws}};
    }
    if (type == "httpupgrade") {
        json ws = json::object();
        ws["v2ray-http-upgrade"] = true;
        ws["v2ray-http-upgrade-fast-open"] = true;
        ws["path"] = path;
        if (!host.empty()) ws["headers"] = {{"Host", host}};
        return {{"network", "ws"}, {"ws-opts", ws}};
    }
    if (type == "grpc") {
        return {{"network", "grpc"}, {"grpc-opts", {{"grpc-service-name", service_name}}}};
    }
    return json::object();
}

json build_outbound(const std::string& name, const std::string& type, const std::string& server,
                    int port, bool enable_ipv6, bool tfo, const json& tls, const json& transport,
                    const json& fields) {
    json out = json::object();
    out["name"] = name;
    out["type"] = type;
    std::string clean_server;
    for (char c : server) {
        if (c != '[' && c != ']') clean_server += c;
    }
    out["server"] = clean_server;
    out["port"] = port;
    out["ip-version"] = enable_ipv6 ? "ipv4-prefer" : "ipv4";
    out["tfo"] = tfo;
    out["udp"] = false;
    for (auto& [k, v] : fields.items()) out[k] = v;
    for (auto& [k, v] : tls.items()) out[k] = v;
    for (auto& [k, v] : transport.items()) out[k] = v;
    return out;
}

json build_ws_outbound(const json& s, const std::string& protocol, const std::string& remark,
                       const std::string& address, int port, const std::string& domain) {
    std::string upstream_server;
    if (s.contains("upstreamParams") && s["upstreamParams"].is_object()) {
        upstream_server = s["upstreamParams"].value("upstreamServer", std::string());
    }
    bool is_tls = is_https(s, port) || (!upstream_server.empty() && address == upstream_server);
    if (protocol == "trojan" && !is_tls) return json();

    auto sni_host = select_sni_host(s, address, domain);
    json tls = is_tls ? build_tls(s, protocol, "tls", sni_host.allow_insecure, sni_host.sni,
                                  flag(s, "enableECH"), str(s, "echServerName"), "http/1.1",
                                  str(s, "fingerprint", "chrome"))
                      : json::object();
    json transport = build_transport("ws", "", generate_ws_path(protocol), sni_host.host, "", 2560);

    json fields = json::object();
    if (protocol == "vless") {
        fields["uuid"] = str(s, "vlUUID");
        fields["packet-encoding"] = "";
        fields["encryption"] = "";
    } else {
        fields["password"] = str(s, "trPass");
    }
    return build_outbound(remark, protocol, address, port, flag(s, "enableIPv6"), flag(s, "enableTFO"),
                          tls, transport, fields);
}

json build_warp_outbound(const json& s, const json& account, const std::string& remark,
                         const std::string& endpoint, const std::string& chain, bool is_pro) {
    std::string host = endpoint;
    int port = 2408;
    auto colon = endpoint.rfind(':');
    if (colon != std::string::npos) {
        host = endpoint.substr(0, colon);
        port = std::atoi(endpoint.substr(colon + 1).c_str());
    }
    std::vector<int> reserved;
    if (flag(s, "warpReservedBytes")) {
        std::string raw = base64_decode(account.value("reserved", std::string()));
        for (unsigned char c : raw) reserved.push_back(c);
    } else {
        reserved = {0, 0, 0};
    }

    json out = json::object();
    out["name"] = remark;
    out["type"] = "wireguard";
    out["ip"] = "172.16.0.2/32";
    out["ipv6"] = account.value("warpIPv6", std::string());
    out["ip-version"] = flag(s, "enableIPv6") ? "ipv4-prefer" : "ipv4";
    out["private-key"] = account.value("privateKey", std::string());
    out["server"] = chain.empty() ? host : std::string("162.159.192.1");
    out["port"] = chain.empty() ? port : 2408;
    out["public-key"] = account.value("publicKey", std::string());
    out["allowed-ips"] = json::array({"0.0.0.0/0", "::/0"});
    out["reserved"] = reserved;
    out["udp"] = true;
    out["mtu"] = 1280;
    if (!chain.empty()) out["dialer-proxy"] = chain;
    if (is_pro) {
        out["amnezia-wg-option"] = {{"jc", num(s, "amneziaNoiseCount", 5)},
                                    {"jmin", num(s, "amneziaNoiseSizeMin", 50)},
                                    {"jmax", num(s, "amneziaNoiseSizeMax", 100)},
                                    {"H1", 1},
                                    {"H2", 2},
                                    {"H3", 3},
                                    {"H4", 4}};
    }
    return out;
}

json build_chain_outbound(const json& s) {
    if (!s.contains("chainProxyParams") || !s["chainProxyParams"].is_object()) return json();
    auto& cp = s["chainProxyParams"];
    std::string protocol = cp.value("protocol", std::string());
    std::string server = cp.value("server", std::string());
    int port = cp.value("port", 0);
    if (protocol.empty() || server.empty()) return json();

    std::string security = cp.value("security", std::string());
    std::string type = cp.value("type", std::string("tcp"));
    std::string sni = cp.value("sni", std::string());
    std::string fp = cp.value("fp", std::string());
    std::string host = cp.value("host", std::string());
    std::string path = cp.value("path", std::string());
    std::string alpn = cp.value("alpn", std::string());
    std::string pbk = cp.value("pbk", std::string());
    std::string sid = cp.value("sid", std::string());

    json tls = build_tls(s, protocol, security, false, sni.empty() ? server : sni, false, "", alpn, fp,
                         pbk, sid);
    json transport = build_transport(type, cp.value("headerType", std::string()), path, host,
                                     cp.value("serviceName", std::string()), 0);

    json fields = json::object();
    std::string clash_type;
    if (protocol == "http") {
        clash_type = "http";
        fields["username"] = cp.value("user", std::string());
        fields["password"] = cp.value("pass", std::string());
    } else if (protocol == "socks") {
        clash_type = "socks5";
        fields["username"] = cp.value("user", std::string());
        fields["password"] = cp.value("pass", std::string());
    } else if (protocol == "shadowsocks") {
        clash_type = "ss";
        fields["cipher"] = cp.value("method", std::string());
        fields["password"] = cp.value("password", std::string());
    } else if (protocol == "vless") {
        clash_type = "vless";
        fields["uuid"] = cp.value("uuid", std::string());
        if (cp.contains("flow")) fields["flow"] = cp["flow"];
        fields["encryption"] = "";
    } else if (protocol == "vmess") {
        clash_type = "vmess";
        fields["uuid"] = cp.value("uuid", std::string());
        fields["cipher"] = "auto";
        fields["alterId"] = cp.value("aid", 0);
    } else if (protocol == "trojan") {
        if (security == "none") return json();
        clash_type = "trojan";
        fields["password"] = cp.value("password", std::string());
    } else {
        return json();
    }
    return build_outbound("", clash_type, server, port, false, false, tls, transport, fields);
}

json build_url_test(const json& s, const std::string& name, const std::vector<std::string>& proxies,
                    bool is_warp) {
    int interval = is_warp ? num(s, "warpBestPingInterval", 30) : num(s, "bestPingInterval", 30);
    return {{"name", name},
            {"type", "url-test"},
            {"proxies", proxies},
            {"url", "https://www.gstatic.com/generate_204"},
            {"interval", interval},
            {"tolerance", 50}};
}

json build_dns(const json& s, bool is_chain, bool is_warp, bool is_pro) {
    std::string local_dns = str(s, "localDNS");
    std::string remote_dns = str(s, "remoteDNS");
    std::string warp_remote_dns = str(s, "warpRemoteDNS");
    std::string sanction = str(s, "antiSanctionDNS");
    bool enable_ipv6 = flag(s, "enableIPv6");
    bool fake_dns = flag(s, "fakeDNS");
    bool allow_lan = flag(s, "allowLANConnection");

    std::string final_local = (local_dns == "localhost") ? "system" : (local_dns + "#DIRECT");
    std::string pro_sign = is_pro ? "Pro " : "";
    std::string remote_detour = is_warp ? (std::string(FLASH) + " Warp " + pro_sign + "- Best Ping " + ROCKET)
                                        : (is_chain ? (std::string(FLASH) + " Best Ping " + ROCKET)
                                                    : (std::string(CHECK) + " Selector"));
    std::string final_remote = (is_warp ? warp_remote_dns : remote_dns) + "#" + remote_detour;

    json hosts = json::object();
    json policy = json::object();

    if (is_chain && !is_warp && s.contains("chainProxyParams") && s["chainProxyParams"].is_object()) {
        std::string server = s["chainProxyParams"].value("server", std::string());
        if (is_domain(server)) policy[server] = final_remote;
    }

    if (s.contains("remoteDnsHost") && s["remoteDnsHost"].is_object() &&
        s["remoteDnsHost"].value("isDomain", false) && !is_warp) {
        auto& rdh = s["remoteDnsHost"];
        std::vector<std::string> ips = to_string_list(rdh, "ipv4");
        if (enable_ipv6) {
            for (auto& ip : to_string_list(rdh, "ipv6")) ips.push_back(ip);
        }
        hosts[rdh.value("host", std::string())] = ips;
    }

    auto geos = geo_assets(s);
    auto acc = acc_dns_rules(s, geos);

    for (auto& g : acc.block_geosites) hosts["rule-set:" + g] = "rcode://refused";
    for (auto& d : acc.block_domains) hosts["+." + d] = "rcode://refused";

    std::vector<std::string> sanction_domains;
    for (auto& g : acc.sanction_geosites) sanction_domains.push_back("rule-set:" + g);
    for (auto& d : acc.sanction_domains) sanction_domains.push_back("+." + d);

    std::vector<std::string> bypass_domains;
    for (auto& [geosite, geoip] : acc.local_geosite_geoip) bypass_domains.push_back("rule-set:" + geosite);
    for (auto& g : acc.local_geosites) bypass_domains.push_back("rule-set:" + g);
    for (auto& d : acc.local_domains) bypass_domains.push_back("+." + d);

    if (!sanction_domains.empty()) {
        for (auto& v : sanction_domains) policy[v] = sanction + "#DIRECT";
        std::string host = host_of(sanction);
        if (is_domain(host)) bypass_domains.push_back(host);
    }
    for (auto& v : bypass_domains) policy[v] = final_local;

    json dns = json::object();
    dns["enable"] = true;
    dns["respect-rules"] = true;
    dns["use-system-hosts"] = false;
    dns["listen"] = std::string(allow_lan ? "0.0.0.0" : "127.0.0.1") + ":1053";
    dns["ipv6"] = enable_ipv6;
    if (!hosts.empty()) dns["hosts"] = hosts;
    dns["nameserver"] = json::array({final_remote});
    dns["proxy-server-nameserver"] = json::array({final_local});
    dns["direct-nameserver"] = json::array({final_local});
    dns["direct-nameserver-follow-policy"] = true;
    if (!policy.empty()) dns["nameserver-policy"] = policy;
    if (fake_dns) {
        dns["enhanced-mode"] = "fake-ip";
        dns["fake-ip-range"] = "198.18.0.1/16";
        dns["fake-ip-filter-mode"] = "blacklist";
        dns["fake-ip-filter"] = json::array({"+.lan", "+.local"});
    } else {
        dns["enhanced-mode"] = "redir-host";
    }
    return dns;
}

std::string ip_cidr_rule(const std::string& raw_ip, const std::string& proxy) {
    std::string ip = raw_ip;
    if (is_ipv6(ip)) {
        std::string clean;
        for (char c : ip) {
            if (c != '[' && c != ']') clean += c;
        }
        ip = clean;
    }
    std::string cidr;
    if (ip.find('/') == std::string::npos) cidr = is_ipv4(ip) ? "/32" : "/128";
    return "IP-CIDR," + ip + cidr + "," + proxy;
}

json build_routing_rules(const json& s, bool is_warp) {
    json rules = json::array();
    rules.push_back("GEOIP,lan,DIRECT,no-resolve");
    if (!is_warp) rules.push_back("NETWORK,udp,REJECT");
    else if (flag(s, "blockUDP443")) rules.push_back("AND,((NETWORK,udp),(DST-PORT,443)),REJECT");

    auto geos = geo_assets(s);
    auto acc = acc_routing_rules(s, geos);
    for (auto& g : acc.block_geosites) rules.push_back("RULE-SET," + g + ",REJECT");
    for (auto& d : acc.block_domains) rules.push_back("DOMAIN-SUFFIX," + d + ",REJECT");
    for (auto& g : acc.block_geoips) rules.push_back("RULE-SET," + g + ",REJECT");
    for (auto& ip : acc.block_ips) rules.push_back(ip_cidr_rule(ip, "REJECT"));
    for (auto& g : acc.bypass_geosites) rules.push_back("RULE-SET," + g + ",DIRECT");
    for (auto& d : acc.bypass_domains) rules.push_back("DOMAIN-SUFFIX," + d + ",DIRECT");
    for (auto& g : acc.bypass_geoips) rules.push_back("RULE-SET," + g + ",DIRECT");
    for (auto& ip : acc.bypass_ips) rules.push_back(ip_cidr_rule(ip, "DIRECT"));
    rules.push_back(std::string("MATCH,") + CHECK + " Selector");
    return rules;
}

json build_rule_providers(const json& s) {
    json providers = json::object();
    for (auto& g : geo_assets(s)) {
        auto add = [&](const std::string& geo, const std::string& behavior, const std::string& url) {
            if (url.empty()) return;
            std::string ext = (g.format == "text") ? "txt" : g.format;
            providers[geo] = {{"type", "http"},
                              {"format", g.format},
                              {"behavior", behavior},
                              {"path", "./ruleset/" + geo + "." + ext},
                              {"interval", 86400},
                              {"url", url}};
        };
        add(g.geosite, "domain", g.geosite_url);
        if (!g.geoip.empty()) add(g.geoip, "ipcidr", g.geoip_url);
    }
    return providers;
}

json build_config(const json& s, const json& outbounds,
                  const std::vector<std::pair<std::string, std::vector<std::string>>>& tag_groups,
                  bool is_chain, bool is_warp, bool is_pro) {
    std::string log_level = str(s, "logLevel", "warning");
    bool allow_lan = flag(s, "allowLANConnection");

    std::vector<std::pair<std::string, std::vector<std::string>>> groups;
    std::vector<std::string> selector_tags;
    for (auto& g : tag_groups) {
        if (g.second.empty()) continue;
        groups.push_back(g);
        selector_tags.push_back(g.first);
        for (auto& t : g.second) selector_tags.push_back(t);
    }

    json config = json::object();
    config["mixed-port"] = 7890;
    config["ipv6"] = true;
    config["allow-lan"] = allow_lan;
    config["unified-delay"] = false;
    std::string clash_log = log_level == "none" ? "silent" : log_level;
    config["log-level"] = clash_log;
    config["mode"] = "rule";
    if (!is_warp) {
        config["disable-keep-alive"] = false;
        config["keep-alive-idle"] = 10;
        config["keep-alive-interval"] = 15;
        config["tcp-concurrent"] = true;
    }
    config["geo-auto-update"] = true;
    config["geo-update-interval"] = 168;
    config["external-controller"] = "127.0.0.1:9090";
    config["external-controller-cors"] = {{"allow-origins", json::array({"*"})},
                                          {"allow-private-network", true}};
    config["external-ui"] = "ui";
    config["external-ui-url"] =
        "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip";
    config["profile"] = {{"store-selected", true}, {"store-fake-ip", true}};
    config["dns"] = build_dns(s, is_chain, is_warp, is_pro);

    json tun = {{"enable", true},
                {"stack", "mixed"},
                {"auto-route", true},
                {"strict-route", true},
                {"auto-detect-interface", true},
                {"dns-hijack", json::array({"any:53", "tcp://any:53"})},
                {"mtu", 9000}};
    json sniffer = {{"enable", true},
                    {"force-dns-mapping", true},
                    {"parse-pure-ip", true},
                    {"override-destination", true},
                    {"sniff",
                     {{"HTTP", {{"ports", json::array({80, 8080, 8880, 2052, 2082, 2086, 2095})}}},
                      {"TLS", {{"ports", json::array({443, 8443, 2053, 2083, 2087, 2096})}}}}}};
    config["tun"] = tun;
    config["sniffer"] = sniffer;
    config["proxies"] = outbounds;
    config["proxy-groups"] = json::array(
        {{{"name", std::string(CHECK) + " Selector"}, {"type", "select"}, {"proxies", selector_tags}}});

    json providers = build_rule_providers(s);
    if (!providers.empty()) config["rule-providers"] = providers;
    config["rules"] = build_routing_rules(s, is_warp);
    config["ntp"] = {{"enable", true},
                     {"server", "time.cloudflare.com"},
                     {"port", 123},
                     {"interval", 30}};

    for (auto& g : groups) {
        config["proxy-groups"].push_back(build_url_test(s, g.first, g.second, is_warp));
    }
    return config;
}

} // namespace

bool build_clash_custom(const json& s, std::string& out_json, std::string& error) {
    std::string chain_raw = str(s, "chainProxy");
    json chain_outbound = chain_raw.empty() ? json() : build_chain_outbound(s);
    bool is_chain = !chain_outbound.is_null();

    std::string main_domain = str(s, "mainDomain");
    std::string custom_domain = str(s, "customDomain");
    std::vector<std::string> domains{main_domain};
    if (!custom_domain.empty()) domains.push_back(custom_domain);

    auto protocols = get_protocols(s);
    std::vector<int> ports;
    if (s.contains("ports") && s["ports"].is_array()) {
        for (auto& p : s["ports"]) {
            if (p.is_number_integer()) ports.push_back(p.get<int>());
        }
    }
    std::string upstream_server;
    int upstream_port = 0;
    if (s.contains("upstreamParams") && s["upstreamParams"].is_object()) {
        upstream_server = s["upstreamParams"].value("upstreamServer", std::string());
        upstream_port = s["upstreamParams"].value("upstreamPort", 0);
    }

    std::string best_ping = std::string(FLASH) + " Best Ping " + ROCKET;
    std::string best_ping_chain = std::string(FLASH) + " " + LINK + " Best Ping " + ROCKET;
    std::string best_ping_d = std::string(FLASH) + " Best Ping D " + ROCKET;
    std::string best_ping_d_chain = std::string(FLASH) + " " + LINK + " Best Ping D " + ROCKET;
    std::vector<std::pair<std::string, std::vector<std::string>>> tag_group = {
        {best_ping, {}}, {best_ping_chain, {}}, {best_ping_d, {}}, {best_ping_d_chain, {}}};

    json outbounds = json::array();

    for (auto& domain : domains) {
        std::vector<int> total_ports;
        bool is_workers_dev = ends_with(domain, "workers.dev");
        for (int port : ports) {
            if (is_workers_dev || is_https(s, port)) total_ports.push_back(port);
        }
        auto hosts = get_config_addresses(s, domain, false, error);
        if (hosts.empty()) return false;

        if (!upstream_server.empty() && upstream_port) {
            total_ports.insert(total_ports.begin(), upstream_port);
            hosts.insert(hosts.begin(), upstream_server);
        }

        bool is_custom = (!custom_domain.empty() && domain == custom_domain);

        for (auto& protocol : protocols) {
            if (protocol != "vless" && protocol != "trojan") continue;
            int protocol_index = 1;
            for (int port : total_ports) {
                for (auto& host : hosts) {
                    bool port_is_upstream = (port == upstream_port);
                    bool host_is_upstream = (!upstream_server.empty() && host == upstream_server);
                    if (port_is_upstream != host_is_upstream) continue;

                    std::string tag =
                        generate_remark(s, protocol_index, port, host, protocol, domain, false, false);
                    json outbound = build_ws_outbound(s, protocol, tag, host, port, domain);
                    if (outbound.is_null()) continue;

                    outbounds.push_back(outbound);
                    for (auto& g : tag_group) {
                        if (g.first == (is_custom ? best_ping_d : best_ping)) g.second.push_back(tag);
                    }

                    if (is_chain) {
                        std::string chain_tag = generate_remark(s, protocol_index, port, host, protocol,
                                                                domain, false, true);
                        json chain = chain_outbound;
                        chain["name"] = chain_tag;
                        chain["dialer-proxy"] = tag;
                        outbounds.push_back(chain);
                        for (auto& g : tag_group) {
                            if (g.first == (is_custom ? best_ping_d_chain : best_ping_chain))
                                g.second.push_back(chain_tag);
                        }
                    }
                    ++protocol_index;
                }
            }
        }
    }

    json config = build_config(s, outbounds, tag_group, is_chain, false, false);
    out_json = config.dump(4);
    return true;
}

bool build_clash_warp(const json& s, const json& warp_accounts, bool is_pro, std::string& out_json,
                      std::string& error) {
    if (!warp_accounts.is_array() || warp_accounts.size() < 2) {
        error = "warp accounts are missing";
        return false;
    }
    auto endpoints = to_string_list(s, "warpEndpoints");
    if (endpoints.empty()) {
        error = "no warp endpoints configured";
        return false;
    }

    std::string pro_sign = is_pro ? "Pro " : "";
    std::string warp_group = std::string(FLASH) + " Warp " + pro_sign + "- Best Ping " + ROCKET;
    std::string wow_group = std::string(FLASH) + " WoW " + pro_sign + "- Best Ping " + ROCKET;
    std::vector<std::pair<std::string, std::vector<std::string>>> tag_group = {{warp_group, {}},
                                                                               {wow_group, {}}};

    json outbounds = json::array();
    int index = 0;
    for (auto& endpoint : endpoints) {
        std::string warp_tag = std::string(FLASH) + " " + std::to_string(index + 1) + ". Warp " + pro_sign + IRAN;
        std::string wow_tag = std::string(FLASH) + " " + std::to_string(index + 1) + ". WoW " + pro_sign + GLOBE;
        tag_group[0].second.push_back(warp_tag);
        tag_group[1].second.push_back(wow_tag);

        outbounds.push_back(build_warp_outbound(s, warp_accounts[0], warp_tag, endpoint, "", is_pro));
        outbounds.push_back(build_warp_outbound(s, warp_accounts[1], wow_tag, endpoint, warp_tag, false));
        ++index;
    }

    json config = build_config(s, outbounds, tag_group, false, true, is_pro);
    out_json = config.dump(4);
    return true;
}

} // namespace bpb::sub
