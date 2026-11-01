#include "sub/xray.h"
#include "net/http_client.h"
#include "sub/common.h"
#include "util/util.h"

#include <algorithm>
#include <cstdlib>
#include <set>

namespace bpb::sub {

using json = nlohmann::json;

namespace {

const char* FLASH = "\xF0\x9F\x92\xA6";      // 💦
const char* LINK = "\xF0\x9F\x94\x97";       // 🔗
const char* ROCKET = "\xF0\x9F\x9A\x80";     // 🚀
const char* BRAIN = "\xF0\x9F\xA7\xA0";      // 🧠
const char* IRAN = "\xF0\x9F\x87\xAE\xF0\x9F\x87\xB7";  // 🇮🇷
const char* GLOBE = "\xF0\x9F\x8C\x8D";      // 🌍
const char* STAR = "\xF0\x9F\x8C\x9F";       // 🌟

struct GeoAsset {
    std::string type;
    std::string geosite;
    std::string geoip;
    std::string dns;
};

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

std::string to_range(int lo, int hi) {
    if (!lo || !hi) return "";
    if (lo == hi) return std::to_string(lo);
    return std::to_string(lo) + "-" + std::to_string(hi);
}

std::vector<GeoAsset> geo_assets(const json& s) {
    std::string local_dns = str(s, "localDNS");
    std::string sanction = str(s, "antiSanctionDNS");
    std::vector<GeoAsset> out;
    auto add = [&](const char* key, const char* type, const char* geosite, const char* geoip,
                   const char* dns) {
        if (!flag(s, key)) return;
        GeoAsset g;
        g.type = type;
        g.geosite = geosite;
        g.geoip = geoip ? geoip : "";
        if (dns) {
            g.dns = std::string(dns) == "@local" ? local_dns : sanction;
        }
        out.push_back(g);
    };
    add("blockAds", "block", "geosite:category-ads-all", nullptr, nullptr);
    add("blockAds", "block", "geosite:category-ads-ir", nullptr, nullptr);
    add("blockPorn", "block", "geosite:category-porn", nullptr, nullptr);
    add("blockMalware", "block", "geosite:malware", "geoip:malware", nullptr);
    add("blockPhishing", "block", "geosite:phishing", "geoip:phishing", nullptr);
    add("blockCryptominers", "block", "geosite:cryptominers", nullptr, nullptr);
    add("bypassIran", "direct", "geosite:category-ir", "geoip:ir", "@local");
    add("bypassChina", "direct", "geosite:cn", "geoip:cn", "@local");
    add("bypassRussia", "direct", "geosite:category-ru", "geoip:ru", "@local");
    add("bypassOpenAi", "direct", "geosite:openai", nullptr, "@sanction");
    add("bypassGoogleAi", "direct", "geosite:google-deepmind", nullptr, "@sanction");
    add("bypassMicrosoft", "direct", "geosite:microsoft", nullptr, "@sanction");
    add("bypassOracle", "direct", "geosite:oracle", nullptr, "@sanction");
    add("bypassDocker", "direct", "geosite:docker", nullptr, "@sanction");
    add("bypassAdobe", "direct", "geosite:adobe", nullptr, "@sanction");
    add("bypassEpicGames", "direct", "geosite:epicgames", nullptr, "@sanction");
    add("bypassIntel", "direct", "geosite:intel", nullptr, "@sanction");
    add("bypassAmd", "direct", "geosite:amd", nullptr, "@sanction");
    add("bypassNvidia", "direct", "geosite:nvidia", nullptr, "@sanction");
    add("bypassAsus", "direct", "geosite:asus", nullptr, "@sanction");
    add("bypassHp", "direct", "geosite:hp", nullptr, "@sanction");
    add("bypassLenovo", "direct", "geosite:lenovo", nullptr, "@sanction");
    return out;
}

json build_sockopt(bool happy, bool tfo, const std::string& domain_strategy,
                   const std::string& dialer) {
    json j = json::object();
    if (!domain_strategy.empty()) j["domainStrategy"] = domain_strategy;
    if (!dialer.empty()) j["dialerProxy"] = dialer;
    if (tfo) j["tcpFastOpen"] = true;
    if (happy) {
        j["happyEyeballs"] = {{"tryDelayMs", 250},
                              {"prioritizeIPv6", false},
                              {"interleave", 2},
                              {"maxConcurrentTry", 4}};
    }
    return j;
}

json build_tls_settings(const json& s, const std::string& server_name, const std::string& fp,
                        const std::string& alpn, bool ech, const std::string& ech_name) {
    json j = json::object();
    j["serverName"] = server_name;
    j["fingerprint"] = fp;
    if (!alpn.empty()) {
        std::vector<std::string> parts;
        for (auto& p : split(alpn, ',')) parts.push_back(p);
        j["alpn"] = parts;
    }
    if (ech) {
        std::string local = str(s, "localDNS", "8.8.8.8");
        if (local == "localhost") local = "8.8.8.8";
        j["echConfigList"] = ech_name.empty() ? ("udp://" + local) : (ech_name + "+udp://" + local);
    }
    return j;
}

json build_transport(const std::string& type, const std::string& header_type,
                     const std::string& path, const std::string& host,
                     const std::string& service_name, const std::string& mode,
                     const std::string& authority) {
    if (type == "tcp" || type == "raw" || type.empty()) {
        json raw = json::object();
        if (header_type == "http") {
            std::vector<std::string> hosts, paths;
            if (!host.empty()) {
                for (auto& h : split(host, ',')) hosts.push_back(h);
            }
            for (auto& p : split(path.empty() ? "/" : path, ',')) paths.push_back(p);
            json req = json::object();
            json headers = json::object();
            headers["Host"] = hosts;
            headers["Accept-Encoding"] = json::array({"gzip, deflate"});
            headers["Connection"] = json::array({"keep-alive"});
            headers["Pragma"] = "no-cache";
            req["headers"] = headers;
            req["path"] = paths;
            req["method"] = "GET";
            req["version"] = "1.1";
            raw["header"] = {{"type", "http"}, {"request", req}};
        } else {
            raw["header"] = {{"type", "none"}};
        }
        return {{"rawSettings", raw}};
    }
    if (type == "ws") {
        json ws = json::object();
        if (!host.empty()) ws["host"] = host;
        ws["path"] = path.empty() ? "/" : path;
        return {{"wsSettings", ws}};
    }
    if (type == "httpupgrade") {
        json hs = json::object();
        if (!host.empty()) hs["host"] = host;
        hs["path"] = path.empty() ? "/" : path;
        return {{"httpupgradeSettings", hs}};
    }
    if (type == "grpc") {
        json g = json::object();
        if (!authority.empty()) g["authority"] = authority;
        g["multiMode"] = (mode == "multi");
        g["serviceName"] = service_name;
        return {{"grpcSettings", g}};
    }
    if (type == "xhttp") {
        json x = json::object();
        if (!host.empty()) x["host"] = host;
        x["path"] = path.empty() ? "/" : path;
        x["mode"] = mode.empty() ? "auto" : mode;
        x["extra"] = json::object();
        return {{"xhttpSettings", x}};
    }
    return json::object();
}

json build_udp_noises(const json& s) {
    json list = json::array();
    if (!s.contains("xrayUdpNoises") || !s["xrayUdpNoises"].is_array()) return list;
    for (auto& noise : s["xrayUdpNoises"]) {
        json entry = json::object();
        std::string type = noise.value("type", "rand");
        if (type == "rand") {
            entry["rand"] = noise.value("packet", std::string());
            entry["randRange"] = "0-255";
            entry["delay"] = noise.value("delay", std::string());
        } else {
            entry["type"] = type;
            if (type == "array") {
                std::vector<int> values;
                for (auto& v : split(noise.value("packet", std::string()), ',')) values.push_back(std::atoi(v.c_str()));
                entry["packet"] = values;
            } else {
                entry["packet"] = noise.value("packet", std::string());
            }
            entry["delay"] = noise.value("delay", std::string());
        }
        int count = noise.value("count", 1);
        for (int i = 0; i < count; ++i) list.push_back(entry);
    }
    return list;
}

json build_final_mask(const json& s, bool is_fragment, bool is_udp_noise, const std::string& frag_length,
                      const std::string& frag_delay) {
    if (!is_fragment && !is_udp_noise) return json();
    json out = json::object();
    if (is_fragment) {
        json settings = json::object();
        settings["packets"] = str(s, "fragmentPackets", "tlshello");
        settings["length"] = !frag_length.empty() ? frag_length
                                                  : to_range(num(s, "fragmentLengthMin"),
                                                             num(s, "fragmentLengthMax"));
        settings["delay"] = !frag_delay.empty()
                                ? frag_delay
                                : to_range(num(s, "fragmentDelayMin"), num(s, "fragmentDelayMax"));
        std::string max_split = to_range(num(s, "fragmentMaxSplitMin"), num(s, "fragmentMaxSplitMax"));
        if (!max_split.empty()) settings["maxSplit"] = max_split;
        out["tcp"] = json::array({{{"type", "fragment"}, {"settings", settings}}});
    }
    if (is_udp_noise) {
        out["udp"] = json::array({{{"type", "noise"},
                                   {"settings",
                                    {{"reset", "30-60"}, {"noise", build_udp_noises(s)}}}}});
    }
    return out;
}

json build_ws_outbound(const json& s, const std::string& tag, const std::string& protocol,
                       const std::string& address, int port, const std::string& domain,
                       bool is_fragment, const std::string& frag_length = "",
                       const std::string& frag_interval = "") {
    std::string upstream_server;
    if (s.contains("upstreamParams") && s["upstreamParams"].is_object()) {
        upstream_server = s["upstreamParams"].value("upstreamServer", std::string());
    }
    bool is_tls = is_https(s, port) || (!upstream_server.empty() && address == upstream_server);
    auto sni_host = select_sni_host(s, address, domain);

    bool enable_ech = flag(s, "enableECH") && !is_fragment;
    json stream = json::object();
    stream["network"] = "ws";
    json transport = build_transport("ws", "", generate_ws_path(protocol, s.value("vlUUID", std::string())) + "?ed=2560", sni_host.host,
                                     "", "", "");
    for (auto& [k, v] : transport.items()) stream[k] = v;
    stream["security"] = is_tls ? "tls" : "none";
    if (is_tls) {
        stream["tlsSettings"] = build_tls_settings(s, sni_host.sni, str(s, "fingerprint", "chrome"),
                                                   "http/1.1", enable_ech, str(s, "echServerName"));
    }
    stream["sockopt"] = build_sockopt(true, flag(s, "enableTFO"), "UseIP", "");
    json final_mask = build_final_mask(s, is_fragment, false, frag_length, frag_interval);
    if (!final_mask.is_null()) stream["finalmask"] = final_mask;

    // VMess authenticates with the same UUID but its own user object: alterId 0
    // and security "auto" (AES-128-GCM), which is what this inbound speaks.
    const json user = (protocol == "vmess")
                          ? json{{"id", str(s, "vlUUID")}, {"alterId", 0}, {"security", "auto"}}
                          : json{{"id", str(s, "vlUUID")}, {"encryption", "none"}};
    json out = json::object();
    out["protocol"] = protocol;
    out["settings"] = {{"vnext",
                        json::array({{{"address", address},
                                      {"port", port},
                                      {"users", json::array({user})}}})}};
    out["streamSettings"] = stream;
    out["tag"] = tag;
    return out;
}

json build_freedom_outbound(const json& s, bool is_fragment, bool is_udp_noise, const std::string& tag,
                            const std::string& length = "", const std::string& interval = "") {
    json settings = json::object();
    if (!is_fragment) {
        settings["domainStrategy"] = flag(s, "enableIPv6") ? "UseIPv4v6" : "UseIPv4";
    }
    json stream = json::object();
    if (is_fragment) stream["sockopt"] = build_sockopt(true, flag(s, "enableTFO"), "UseIP", "");
    json final_mask = build_final_mask(s, is_fragment, is_udp_noise, length, interval);
    if (!final_mask.is_null()) stream["finalmask"] = final_mask;

    json out = json::object();
    out["protocol"] = "freedom";
    out["settings"] = settings;
    if (!stream.empty()) out["streamSettings"] = stream;
    out["tag"] = tag;
    return out;
}

std::vector<int> base64_to_decimal(const std::string& b64) {
    std::string raw = base64_decode(b64);
    std::vector<int> out;
    for (unsigned char c : raw) out.push_back(c);
    return out;
}

std::string endpoint_host(const std::string& endpoint) {
    auto pos = endpoint.rfind(':');
    std::string host = (pos == std::string::npos) ? endpoint : endpoint.substr(0, pos);
    if (!host.empty() && host.front() == '[') {
        auto close = host.find(']');
        if (close != std::string::npos) host = host.substr(1, close - 1);
    }
    return host;
}

json build_warp_outbound(const json& s, const json& account, const std::string& endpoint, bool is_wow,
                         bool is_pro, bool is_knocker) {
    std::string warp_ipv6 = account.value("warpIPv6", std::string());
    std::string reserved = account.value("reserved", std::string());
    std::string public_key = account.value("publicKey", std::string());
    std::string private_key = account.value("privateKey", std::string());

    json reserved_bytes = json::array({0, 0, 0});
    if (flag(s, "warpReservedBytes")) {
        reserved_bytes = base64_to_decimal(reserved);
    }

    json settings = json::object();
    settings["address"] = json::array({"172.16.0.2/32", warp_ipv6});
    settings["mtu"] = 1280;
    settings["peers"] = json::array(
        {{{"endpoint", is_wow ? std::string("162.159.192.1:2408") : endpoint},
          {"publicKey", public_key},
          {"keepAlive", 5}}});
    settings["reserved"] = reserved_bytes;
    settings["secretKey"] = private_key;

    json stream = json::object();
    if (is_wow) {
        stream["sockopt"] = build_sockopt(false, false, "", "proxy");
    } else if (is_pro) {
        if (is_knocker) {
            settings["wnoise"] = str(s, "knockerNoiseMode", "quic");
            settings["wnoisecount"] = to_range(num(s, "knockerNoiseCountMin"), num(s, "knockerNoiseCountMax"));
            settings["wpayloadsize"] = to_range(num(s, "knockerNoiseSizeMin"), num(s, "knockerNoiseSizeMax"));
            settings["wnoisedelay"] = to_range(num(s, "knockerNoiseDelayMin"), num(s, "knockerNoiseDelayMax"));
        } else {
            json fm = build_final_mask(s, false, true, "", "");
            if (!fm.is_null()) stream["finalmask"] = fm;
        }
    }

    json out = json::object();
    out["protocol"] = "wireguard";
    out["settings"] = settings;
    if (!stream.empty()) out["streamSettings"] = stream;
    out["tag"] = is_wow ? "chain" : "proxy";
    return out;
}

json modify_outbound(json outbound, const std::string& tag, const std::string& dialer = "") {
    outbound["tag"] = tag;
    if (!dialer.empty() && outbound.contains("streamSettings") &&
        outbound["streamSettings"].contains("sockopt")) {
        outbound["streamSettings"]["sockopt"]["dialerProxy"] = dialer;
    }
    return outbound;
}

} // namespace (outbound helpers, part 1)

namespace {

struct RoutingAcc {
    std::vector<std::string> block_geosites;
    std::vector<std::string> block_domains;
    std::vector<std::string> block_geoips;
    std::vector<std::string> block_ips;
    std::vector<std::string> bypass_geosites;
    std::vector<std::string> bypass_domains;
    std::vector<std::string> bypass_geoips;
    std::vector<std::string> bypass_ips;
};

RoutingAcc acc_routing_rules(const json& s, const std::vector<GeoAsset>& geos) {
    RoutingAcc out;
    auto bypass_rules = to_string_list(s, "customBypassRules");
    auto sanction_rules = to_string_list(s, "customBypassSanctionRules");
    auto block_rules = to_string_list(s, "customBlockRules");

    for (auto& g : geos) {
        if (g.type == "block") {
            out.block_geosites.push_back(g.geosite);
            if (!g.geoip.empty()) out.block_geoips.push_back(g.geoip);
        } else if (g.type == "direct") {
            out.bypass_geosites.push_back(g.geosite);
            if (!g.geoip.empty()) out.bypass_geoips.push_back(g.geoip);
        }
    }
    for (auto& r : bypass_rules) {
        if (is_domain(r)) out.bypass_domains.push_back(r);
        else out.bypass_ips.push_back(r);
    }
    for (auto& r : sanction_rules) {
        if (is_domain(r)) out.bypass_domains.push_back(r);
        else out.bypass_ips.push_back(r);
    }
    for (auto& r : block_rules) {
        if (is_domain(r)) out.block_domains.push_back(r);
        else out.block_ips.push_back(r);
    }
    return out;
}

struct DnsAcc {
    std::vector<std::pair<std::string, std::string>> local_geosite_geoip;
    std::vector<std::string> local_geosites;
    std::vector<std::string> local_domains;
    std::vector<std::string> sanction_geosites;
    std::vector<std::string> sanction_domains;
    std::vector<std::string> block_geosites;
    std::vector<std::string> block_domains;
};

DnsAcc acc_dns_rules(const json& s, const std::vector<GeoAsset>& geos) {
    DnsAcc out;
    std::string local_dns = str(s, "localDNS");
    std::string sanction = str(s, "antiSanctionDNS");
    auto bypass_rules = to_string_list(s, "customBypassRules");
    auto sanction_rules = to_string_list(s, "customBypassSanctionRules");
    auto block_rules = to_string_list(s, "customBlockRules");

    for (auto& g : geos) {
        if (g.type == "direct") {
            if (!g.geoip.empty() && g.dns == local_dns) {
                out.local_geosite_geoip.emplace_back(g.geosite, g.geoip);
            } else if (g.geoip.empty() && g.dns == local_dns) {
                out.local_geosites.push_back(g.geosite);
            }
            if (!g.dns.empty() && g.dns == sanction) out.sanction_geosites.push_back(g.geosite);
        } else if (g.type == "block") {
            out.block_geosites.push_back(g.geosite);
        }
    }
    for (auto& r : bypass_rules) {
        if (is_domain(r)) out.local_domains.push_back(r);
    }
    for (auto& r : sanction_rules) {
        if (is_domain(r)) out.sanction_domains.push_back(r);
    }
    for (auto& r : block_rules) {
        if (is_domain(r)) out.block_domains.push_back(r);
    }
    return out;
}

json dns_server(const std::string& address, const std::vector<std::string>& domains,
                const std::vector<std::string>& expect_ips, bool skip_fallback, bool final_query,
                const std::string& tag) {
    json j = json::object();
    j["address"] = address;
    if (!domains.empty()) j["domains"] = domains;
    if (!expect_ips.empty()) j["expectIPs"] = expect_ips;
    if (skip_fallback) j["skipFallback"] = true;
    if (final_query) j["finalQuery"] = true;
    if (!tag.empty()) j["tag"] = tag;
    return j;
}

json build_dns(const json& s, const std::vector<std::string>& outbound_addrs, bool is_workerless,
               bool is_warp, const std::string& domain_to_static_ips,
               const std::string& custom_dns = "", const std::vector<std::string>& custom_dns_hosts = {}) {
    std::string local_dns = str(s, "localDNS");
    std::string remote_dns = str(s, "remoteDNS");
    std::string warp_remote_dns = str(s, "warpRemoteDNS");
    std::string sanction = str(s, "antiSanctionDNS");
    bool enable_ipv6 = flag(s, "enableIPv6");
    bool fake_dns = flag(s, "fakeDNS");

    json hosts = json::object();
    json servers = json::array();
    std::vector<std::string> fake_dns_domains;

    if (s.contains("remoteDnsHost") && s["remoteDnsHost"].is_object()) {
        auto& rdh = s["remoteDnsHost"];
        bool is_domain_host = rdh.value("isDomain", false);
        if (is_domain_host && !is_workerless && !is_warp) {
            std::vector<std::string> ips = to_string_list(rdh, "ipv4");
            if (enable_ipv6) {
                for (auto& ip : to_string_list(rdh, "ipv6")) ips.push_back(ip);
            }
            hosts[rdh.value("host", std::string())] = ips;
        }
    }

    if (!domain_to_static_ips.empty()) {
        DnsResult resolved;
        std::string error;
        if (resolve_dns(domain_to_static_ips, !enable_ipv6, resolved, error)) {
            std::vector<std::string> ips = resolved.ipv4;
            for (auto& ip : resolved.ipv6) ips.push_back(ip);
            hosts[domain_to_static_ips] = ips;
        }
    }

    bool skip_fallback = true;
    std::string final_remote_dns = is_warp ? warp_remote_dns : remote_dns;

    if (is_workerless) {
        final_remote_dns = "https://" + custom_dns + "/dns-query";
        if (!custom_dns.empty() && !custom_dns_hosts.empty()) hosts[custom_dns] = custom_dns_hosts;
        skip_fallback = false;
    }

    servers.push_back(dns_server(final_remote_dns, {}, {}, false, false, "remote-dns"));

    auto geos = geo_assets(s);
    auto dns_rules = acc_dns_rules(s, geos);

    std::vector<std::string> block_domains = dns_rules.block_geosites;
    for (auto& d : dns_rules.block_domains) block_domains.push_back("domain:" + d);
    for (auto& d : block_domains) hosts[d] = "#3";

    for (auto& [geosite, geoip] : dns_rules.local_geosite_geoip) {
        servers.push_back(dns_server(local_dns, {geosite}, {geoip}, skip_fallback, false, ""));
        fake_dns_domains.push_back(geosite);
    }

    std::vector<std::string> sanction_domains = dns_rules.sanction_geosites;
    for (auto& d : dns_rules.sanction_domains) sanction_domains.push_back("domain:" + d);

    std::vector<std::string> bypass_domains = dns_rules.local_geosites;
    for (auto& d : dns_rules.local_domains) bypass_domains.push_back("domain:" + d);
    for (auto& addr : outbound_addrs) {
        if (is_domain(addr)) bypass_domains.push_back("full:" + addr);
    }

    if (!sanction_domains.empty()) {
        servers.push_back(dns_server(sanction, sanction_domains, {}, skip_fallback, true, ""));
        std::string host = sanction;
        auto scheme = host.find("://");
        if (scheme != std::string::npos) host = host.substr(scheme + 3);
        auto slash = host.find('/');
        if (slash != std::string::npos) host = host.substr(0, slash);
        if (is_domain(host)) bypass_domains.push_back("full:" + host);
    }

    for (auto& host : custom_dns_hosts) {
        if (is_domain(host)) bypass_domains.push_back("full:" + host);
    }

    if (!bypass_domains.empty()) {
        servers.push_back(dns_server(local_dns, bypass_domains, {}, skip_fallback, false, ""));
        for (auto& d : bypass_domains) fake_dns_domains.push_back(d);
    }

    if (fake_dns || is_workerless) {
        json fake_server = fake_dns_domains.empty()
                               ? json("fakedns")
                               : dns_server("fakedns", fake_dns_domains, {}, false, false, "");
        json rebuilt = json::array();
        rebuilt.push_back(fake_server);
        for (auto& server : servers) rebuilt.push_back(server);
        servers = rebuilt;
    }

    json out = json::object();
    if (!hosts.empty()) out["hosts"] = hosts;
    out["servers"] = servers;
    out["queryStrategy"] = (is_warp && !enable_ipv6) ? "UseIPv4" : "UseIP";
    out["tag"] = "dns";
    return out;
}

json routing_rule(const std::vector<std::string>& inbound_tag, const std::vector<std::string>& domain,
                  const std::vector<std::string>& ip, const std::string& port, const std::string& network,
                  const std::vector<std::string>& protocol, const std::string& outbound_tag,
                  bool is_balancer) {
    json j = json::object();
    if (!inbound_tag.empty()) j["inboundTag"] = inbound_tag;
    if (!domain.empty()) j["domain"] = domain;
    if (!ip.empty()) j["ip"] = ip;
    if (!port.empty()) j["port"] = port;
    if (!network.empty()) j["network"] = network;
    if (!protocol.empty()) j["protocol"] = protocol;
    if (is_balancer) j["balancerTag"] = outbound_tag;
    else j["outboundTag"] = outbound_tag;
    j["type"] = "field";
    return j;
}

json build_routing_rules(const json& s, bool is_chain, bool is_balancer, bool is_workerless,
                         bool is_warp) {
    json rules = json::array();
    rules.push_back(routing_rule({"mixed-in"}, {}, {}, "53", "", {}, "dns-out", false));
    rules.push_back(routing_rule({"dns-in"}, {}, {}, "", "", {}, "dns-out", false));

    std::string final_outbound_tag = is_chain ? "chain" : (is_workerless ? "direct" : "proxy");
    std::string out_tag = is_balancer ? (is_chain ? "all-chains" : "all-proxies") : final_outbound_tag;
    std::string remote_dns_proxy = is_balancer ? "all-proxies" : "proxy";

    rules.push_back(routing_rule({"remote-dns"}, {}, {}, "", "", {}, remote_dns_proxy, is_balancer));
    rules.push_back(routing_rule({"dns"}, {}, {}, "", "", {}, "direct", false));
    rules.push_back(routing_rule({}, {"geosite:private"}, {}, "", "", {}, "direct", false));
    rules.push_back(routing_rule({}, {}, {"geoip:private"}, "", "", {}, "direct", false));

    if (!(is_warp || is_workerless)) {
        rules.push_back(routing_rule({}, {}, {}, "", "udp", {}, "block", false));
    } else if (flag(s, "blockUDP443")) {
        rules.push_back(routing_rule({}, {}, {}, "443", "udp", {}, "block", false));
    }

    auto geos = geo_assets(s);
    auto acc = acc_routing_rules(s, geos);

    std::vector<std::string> block_domains = acc.block_geosites;
    for (auto& d : acc.block_domains) block_domains.push_back("domain:" + d);
    if (!block_domains.empty()) {
        rules.push_back(routing_rule({}, block_domains, {}, "", "", {}, "block", false));
    }

    std::vector<std::string> block_ips = acc.block_geoips;
    for (auto& ip : acc.block_ips) block_ips.push_back(ip);
    if (!block_ips.empty()) {
        rules.push_back(routing_rule({}, {}, block_ips, "", "", {}, "block", false));
    }

    std::vector<std::string> bypass_domains = acc.bypass_geosites;
    for (auto& d : acc.bypass_domains) bypass_domains.push_back("domain:" + d);
    if (!bypass_domains.empty()) {
        rules.push_back(routing_rule({}, bypass_domains, {}, "", "", {}, "direct", false));
    }

    std::vector<std::string> bypass_ips = acc.bypass_geoips;
    for (auto& ip : acc.bypass_ips) bypass_ips.push_back(ip);
    if (!bypass_ips.empty()) {
        rules.push_back(routing_rule({}, {}, bypass_ips, "", "", {}, "direct", false));
    }

    if (is_workerless) {
        rules.push_back(routing_rule({}, {}, {}, "", "tcp", {"tls"}, "proxy", false));
        rules.push_back(routing_rule({}, {}, {}, "", "tcp", {"http"}, "http-fragment", false));
        rules.push_back(routing_rule({}, {}, {}, "", "udp", {"quic"}, "udp-noise", false));
        rules.push_back(routing_rule({}, {}, {}, "443,2053,2083,2087,2096,8443", "udp", {}, "udp-noise", false));
    }

    std::string network = (is_warp || is_workerless) ? "tcp,udp" : "tcp";
    rules.push_back(routing_rule({}, {}, {}, "", network, {}, out_tag, is_balancer));
    return rules;
}

json build_balancer(const std::string& tag, const std::string& selector, bool has_fallback) {
    json j = json::object();
    j["tag"] = tag;
    j["selector"] = json::array({selector});
    j["strategy"] = {{"type", "leastPing"}};
    if (has_fallback) j["fallbackTag"] = "proxy-2";
    return j;
}

json build_config(const json& s, const std::string& remark, const json& outbounds, bool is_balancer,
                  bool is_chain, bool balancer_fallback, bool is_warp, bool is_workerless,
                  const std::vector<std::string>& outbound_addrs,
                  const std::string& domain_to_static_ips = "",
                  const std::string& custom_dns = "",
                  const std::vector<std::string>& custom_dns_hosts = {}) {
    json config = json::object();
    config["remarks"] = remark;
    config["version"] = {{"min", "26.2.6"}};
    config["log"] = {{"loglevel", str(s, "logLevel", "warning")}};

    config["dns"] = build_dns(s, outbound_addrs, is_workerless, is_warp, domain_to_static_ips,
                              custom_dns, custom_dns_hosts);

    json mixed = json::object();
    bool allow_lan = flag(s, "allowLANConnection");
    bool fake_dns = flag(s, "fakeDNS");
    std::vector<std::string> dest_override{"http", "tls"};
    if (is_workerless) dest_override.push_back("quic");
    if (is_workerless || fake_dns) dest_override.push_back("fakedns");
    mixed["listen"] = allow_lan ? "0.0.0.0" : "127.0.0.1";
    mixed["port"] = 10808;
    mixed["protocol"] = "mixed";
    mixed["settings"] = {{"auth", "noauth"}, {"udp", true}};
    mixed["sniffing"] = {{"destOverride", dest_override}, {"enabled", true}, {"routeOnly", true}};
    mixed["tag"] = "mixed-in";

    json dohodemo = json::object();
    dohodemo["listen"] = allow_lan ? "0.0.0.0" : "127.0.0.1";
    dohodemo["port"] = 10853;
    dohodemo["protocol"] = "dokodemo-door";
    dohodemo["settings"] = {{"address", "1.1.1.1"}, {"network", "tcp,udp"}, {"port", 53}};
    dohodemo["tag"] = "dns-in";

    config["inbounds"] = json::array({mixed, dohodemo});

    json outs = json::array();
    for (auto& o : outbounds) outs.push_back(o);
    outs.push_back({{"protocol", "dns"}, {"settings", {{"rules", json::array({{{"action", "hijack"}}})}}}, {"tag", "dns-out"}});
    outs.push_back({{"protocol", "freedom"}, {"settings", {{"domainStrategy", "UseIP"}}}, {"tag", "direct"}});
    outs.push_back({{"protocol", "blackhole"}, {"settings", {{"response", {{"type", "http"}}}}}, {"tag", "block"}});
    config["outbounds"] = outs;

    json routing = json::object();
    routing["domainStrategy"] = "IPIfNonMatch";
    routing["rules"] = build_routing_rules(s, is_chain, is_balancer, is_workerless, is_warp);
    if (is_balancer) {
        json balancers = json::array({build_balancer("all-proxies", "proxy", balancer_fallback)});
        if (is_chain) balancers.push_back(build_balancer("all-chains", "chain", false));
        routing["balancers"] = balancers;
    }
    config["routing"] = routing;

    if (is_balancer) {
        int probe = is_warp ? num(s, "warpBestPingInterval", 30) : num(s, "bestPingInterval", 30);
        json observatory = json::object();
        observatory["subjectSelector"] = is_chain ? json::array({"chain", "proxy"}) : json::array({"proxy"});
        observatory["probeUrl"] = "https://www.gstatic.com/generate_204";
        observatory["probeInterval"] = std::to_string(probe) + "s";
        observatory["enableConcurrency"] = true;
        config["observatory"] = observatory;
    }

    config["policy"] = {
        {"levels", {{"0", {{"connIdle", 300}, {"handshake", 4}, {"uplinkOnly", 1}, {"downlinkOnly", 1}}}}},
        {"system", {{"statsOutboundUplink", true}, {"statsOutboundDownlink", true}}}};
    config["stats"] = json::object();
    return config;
}

} // namespace (outbound helpers)

namespace {

struct ChainParams {
    std::string protocol, address, user, pass, password, method, uuid, flow, security, type, sni, fp;
    std::string host, path, alpn, pbk, sid, spx, header_type, service_name, mode, authority, encryption;
    int port = 0;
    bool valid = false;
};

ChainParams parse_chain_params(const json& s) {
    ChainParams p;
    std::string raw = str(s, "chainProxy");
    if (raw.empty()) return p;
    if (s.contains("chainProxyParams") && s["chainProxyParams"].is_object()) {
        auto& cp = s["chainProxyParams"];
        p.protocol = cp.value("protocol", std::string());
        p.address = cp.value("server", std::string());
        p.port = cp.value("port", 0);
        p.user = cp.value("user", std::string());
        p.pass = cp.value("pass", std::string());
        p.password = cp.value("password", std::string());
        p.method = cp.value("method", std::string());
        p.uuid = cp.value("uuid", std::string());
        p.flow = cp.value("flow", std::string());
        p.security = cp.value("security", std::string());
        p.type = cp.value("type", std::string());
        p.sni = cp.value("sni", std::string());
        p.fp = cp.value("fp", std::string());
        p.host = cp.value("host", std::string());
        p.path = cp.value("path", std::string());
        p.alpn = cp.value("alpn", std::string());
        p.pbk = cp.value("pbk", std::string());
        p.sid = cp.value("sid", std::string());
        p.spx = cp.value("spx", std::string());
        p.header_type = cp.value("headerType", std::string());
        p.service_name = cp.value("serviceName", std::string());
        p.mode = cp.value("mode", std::string());
        p.authority = cp.value("authority", std::string());
        p.encryption = cp.value("encryption", std::string());
        p.valid = !p.protocol.empty() && !p.address.empty();
        return p;
    }

    net::httpc::Url url;
    std::string error;
    if (!net::httpc::parse_url(raw, url, error)) return p;

    p.protocol = url.scheme;
    if (p.protocol == "socks5") p.protocol = "socks";
    if (p.protocol == "ss") p.protocol = "shadowsocks";
    p.address = url.host;
    p.port = url.port;
    p.type = "tcp";
    p.valid = true;

    std::string target = url.path;
    auto qpos = target.find('?');
    std::string query = qpos == std::string::npos ? "" : target.substr(qpos + 1);
    if (qpos != std::string::npos) target = target.substr(0, qpos);
    auto params = parse_query(query);

    auto get = [&](const char* key) -> std::string {
        auto it = params.find(key);
        return it == params.end() ? std::string() : it->second;
    };

    if (p.protocol == "vless") p.uuid = get("uuid");
    if (p.protocol == "trojan") p.password = get("password");
    if (p.protocol == "shadowsocks") {
        std::string auth = base64_decode(url.host);
        (void)auth;
    }
    p.host = get("host");
    p.path = get("path");
    p.sni = get("sni");
    p.fp = get("fp");
    p.alpn = get("alpn");
    p.security = get("security");
    p.service_name = get("serviceName");
    p.mode = get("mode");
    p.authority = get("authority");
    p.header_type = get("headerType");
    std::string net_type = get("type");
    if (!net_type.empty()) p.type = net_type;
    return p;
}

json build_chain_outbound(const json& s) {
    ChainParams p = parse_chain_params(s);
    if (!p.valid) return json();

    json stream = json::object();
    std::string network = p.type.empty() ? "raw" : p.type;
    stream["network"] = network;
    json transport = build_transport(network, p.header_type, p.path, p.host, p.service_name, p.mode,
                                     p.authority);
    for (auto& [k, v] : transport.items()) stream[k] = v;
    if (!p.security.empty()) stream["security"] = p.security;
    if (p.security == "tls") {
        stream["tlsSettings"] = build_tls_settings(s, p.sni.empty() ? p.address : p.sni,
                                                   p.fp.empty() ? "chrome" : p.fp, p.alpn, false, "");
    } else if (p.security == "reality") {
        json reality = json::object();
        reality["serverName"] = p.sni;
        reality["fingerprint"] = p.fp;
        reality["publicKey"] = p.pbk;
        reality["shortId"] = p.sid;
        reality["spiderX"] = p.spx;
        reality["show"] = false;
        reality["allowInsecure"] = false;
        stream["realitySettings"] = reality;
    }
    stream["sockopt"] = build_sockopt(false, false, "UseIPv4", "proxy");

    bool enable_mux = !(p.security == "reality" || p.type == "grpc" || p.type == "xhttp");

    json out = json::object();
    out["protocol"] = p.protocol;
    if (enable_mux) {
        out["mux"] = {{"enabled", true},
                      {"concurrency", 8},
                      {"xudpConcurrency", 16},
                      {"xudpProxyUDP443", "reject"}};
    }

    if (p.protocol == "http" || p.protocol == "socks") {
        out["settings"] = {{"servers",
                            json::array({{{"address", p.address},
                                          {"port", p.port},
                                          {"users", json::array({{{"user", p.user}, {"pass", p.pass}}})}}})}};
    } else if (p.protocol == "shadowsocks") {
        out["settings"] = {{"servers",
                            json::array({{{"address", p.address},
                                          {"port", p.port},
                                          {"method", p.method},
                                          {"password", p.password}}})}};
    } else if (p.protocol == "vless") {
        json user = {{"id", p.uuid}, {"encryption", p.encryption.empty() ? "none" : p.encryption}};
        if (!p.flow.empty()) user["flow"] = p.flow;
        out["settings"] = {{"vnext",
                            json::array({{{"address", p.address},
                                          {"port", p.port},
                                          {"users", json::array({user})}}})}};
    } else if (p.protocol == "trojan") {
        out["settings"] = {{"servers",
                            json::array({{{"address", p.address},
                                          {"port", p.port},
                                          {"password", p.password}}})}};
    } else {
        return json();
    }

    out["streamSettings"] = stream;
    out["tag"] = "chain";
    return out;
}

void add_best_ping_configs(json& configs, const std::string& s_json, const json& s,
                           std::vector<std::string> total_addresses, const json& proxy_outbounds,
                           const json& chain_outbounds, bool is_fragment, bool is_custom_domain) {
    std::set<std::string> seen;
    std::vector<std::string> unique;
    for (auto& a : total_addresses) {
        if (seen.insert(a).second) unique.push_back(a);
    }

    bool is_chain = !chain_outbounds.empty();
    std::string chain_sign = is_chain ? std::string(LINK) + " " : "";
    std::string fragment_sign = is_fragment ? "F " : "";
    std::string custom_domain_sign = is_custom_domain ? "D " : "";
    std::string remark = std::string(FLASH) + " " + chain_sign + "Best Ping " + fragment_sign +
                         custom_domain_sign + ROCKET;

    json outbounds = json::array();
    for (auto& o : chain_outbounds) outbounds.push_back(o);
    for (auto& o : proxy_outbounds) outbounds.push_back(o);

    configs.push_back(build_config(s, remark, outbounds, true, is_chain, true, false, false, unique));

    if (is_chain) {
        add_best_ping_configs(configs, s_json, s, unique, proxy_outbounds, json::array(), is_fragment,
                              is_custom_domain);
    }
}

void add_best_fragment_configs(json& configs, const json& s, const json& chain_proxy) {
    std::string main_domain = str(s, "mainDomain");
    int delay_min = num(s, "fragmentDelayMin", 1);
    int delay_max = num(s, "fragmentDelayMax", 1);
    bool is_chain = !chain_proxy.is_null();
    json outbounds = json::array();

    static const char* frags[] = {"1-5",   "1-10",  "10-20", "20-30", "30-40", "40-50", "50-60",
                                  "60-70", "70-80", "80-90", "90-100", "10-30", "20-40", "30-50",
                                  "40-60", "50-70", "60-80", "70-90", "80-100", "100-200"};

    for (int i = 0; i < 20; ++i) {
        std::string tag = "proxy-" + std::to_string(i + 1);
        if (is_chain) {
            outbounds.push_back(modify_outbound(chain_proxy, "chain-" + std::to_string(i + 1), tag));
        }
        outbounds.push_back(build_ws_outbound(s, tag, "vless", main_domain, 443, main_domain, true,
                                              frags[i],
                                              std::to_string(delay_min) + "-" + std::to_string(delay_max)));
    }

    std::string chain_sign = is_chain ? std::string(LINK) + " " : "";
    configs.push_back(build_config(s, std::string(FLASH) + " " + chain_sign + "Smart Fragment " + BRAIN,
                                   outbounds, true, is_chain, false, false, false, {}, main_domain));

    if (is_chain) add_best_fragment_configs(configs, s, json());
}

void add_workerless_configs(json& configs, const json& s) {
    json tls_fragment = build_freedom_outbound(s, true, false, "proxy");
    json udp_noise = build_freedom_outbound(s, false, true, "udp-noise");
    json http_fragment = build_freedom_outbound(s, true, false, "http-fragment", "1-1");
    json outbounds = json::array({tls_fragment, http_fragment, udp_noise});

    configs.push_back(build_config(s, std::string(FLASH) + " 1 - Serverless " + STAR, outbounds, false,
                                   false, false, false, true, {}, "", "cloudflare-dns.com",
                                   {"cloudflare.com"}));
    configs.push_back(build_config(s, std::string(FLASH) + " 2 - Serverless " + STAR, outbounds, false,
                                   false, false, false, true, {}, "", "dns.google",
                                   {"8.8.8.8", "8.8.4.4"}));
}

} // namespace

bool build_xray_custom(const json& s, bool is_fragment, std::string& out_json, std::string& error) {
    std::string chain_raw = str(s, "chainProxy");
    json chain_outbound = chain_raw.empty() ? json() : build_chain_outbound(s);

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

    json configs = json::array();
    int index = 1;

    for (auto& domain : domains) {
        std::vector<std::string> total_hosts;
        json proxies = json::array();
        json chains = json::array();

        std::vector<int> total_ports;
        bool is_workers_dev = ends_with(domain, "workers.dev");
        for (int port : ports) {
            if ((!is_fragment && is_workers_dev) || is_https(s, port)) total_ports.push_back(port);
        }

        auto hosts = get_config_addresses(s, domain, is_fragment, error);
        if (hosts.empty()) return false;

        if (!upstream_server.empty() && upstream_port && !is_fragment) {
            total_ports.insert(total_ports.begin(), upstream_port);
            hosts.insert(hosts.begin(), upstream_server);
        }

        for (auto& h : hosts) total_hosts.push_back(h);

        for (auto& protocol : protocols) {
            if (protocol != "vless" && protocol != "vmess") continue;
            int protocol_index = 1;
            for (int port : total_ports) {
                for (auto& host : hosts) {
                    bool port_is_upstream = (port == upstream_port);
                    bool host_is_upstream = (!upstream_server.empty() && host == upstream_server);
                    if (port_is_upstream != host_is_upstream) continue;

                    json outbound = build_ws_outbound(s, "proxy", protocol, host, port, domain, is_fragment);
                    json proxy = modify_outbound(outbound, "proxy-" + std::to_string(index));
                    proxies.push_back(proxy);

                    std::string remark =
                        generate_remark(s, protocol_index, port, host, protocol, domain, is_fragment, false);
                    configs.push_back(build_config(s, remark, json::array({outbound}), false, false, false,
                                                   false, false, {host}));

                    if (!chain_outbound.is_null()) {
                        std::string chain_remark =
                            generate_remark(s, protocol_index, port, host, protocol, domain, is_fragment, true);
                        configs.push_back(build_config(s, chain_remark,
                                                       json::array({chain_outbound, outbound}), false, true,
                                                       false, false, false, {host}));
                        chains.push_back(modify_outbound(chain_outbound, "chain-" + std::to_string(index),
                                                         "proxy-" + std::to_string(index)));
                    }

                    ++protocol_index;
                    ++index;
                }
            }
        }

        bool is_custom_domain = (!custom_domain.empty() && domain == custom_domain);
        add_best_ping_configs(configs, "", s, total_hosts, proxies, chains, is_fragment, is_custom_domain);
    }

    if (is_fragment) {
        add_best_fragment_configs(configs, s, chain_outbound.is_null() ? json() : chain_outbound);
        add_workerless_configs(configs, s);
    }

    out_json = configs.dump(4);
    return true;
}

std::vector<std::string> warp_endpoint_hosts(const json& s) {
    std::vector<std::string> out;
    for (auto& endpoint : to_string_list(s, "warpEndpoints")) {
        std::string host = endpoint_host(endpoint);
        if (is_domain(host)) out.push_back(host);
    }
    return out;
}

bool build_xray_warp(const json& s, const json& warp_accounts, bool is_pro, bool is_knocker,
                     std::string& out_json, std::string& error) {
    if (!warp_accounts.is_array() || warp_accounts.size() < 2) {
        error = "warp accounts are missing";
        return false;
    }
    auto endpoints = to_string_list(s, "warpEndpoints");
    if (endpoints.empty()) {
        error = "no warp endpoints configured";
        return false;
    }

    std::string pro_indicator = is_pro ? " Pro " : " ";
    json configs = json::array();
    json proxies = json::array();
    json chains = json::array();
    std::vector<std::string> outbound_domains = warp_endpoint_hosts(s);

    int i = 0;
    for (auto& endpoint : endpoints) {
        json warp_outbound = build_warp_outbound(s, warp_accounts[0], endpoint, false, is_pro, is_knocker);
        json wow_outbound = build_warp_outbound(s, warp_accounts[1], endpoint, true, is_pro, is_knocker);
        std::string host = endpoint_host(endpoint);

        configs.push_back(build_config(s,
                                       std::string(FLASH) + " " + std::to_string(i + 1) + " - Warp" +
                                           pro_indicator + IRAN,
                                       json::array({warp_outbound}), false, false, false, true, false, {host}));
        configs.push_back(build_config(s,
                                       std::string(FLASH) + " " + std::to_string(i + 1) + " - WoW" +
                                           pro_indicator + GLOBE,
                                       json::array({wow_outbound, warp_outbound}), false, true, false, true,
                                       false, {host}));

        proxies.push_back(modify_outbound(warp_outbound, "proxy-" + std::to_string(i + 1)));
        chains.push_back(modify_outbound(wow_outbound, "chain-" + std::to_string(i + 1),
                                         "proxy-" + std::to_string(i + 1)));
        ++i;
    }

    json warp_best = build_config(s, std::string(FLASH) + " Warp" + pro_indicator + "- Best Ping " + ROCKET,
                                  proxies, true, false, false, true, false, outbound_domains);
    json all = json::array();
    for (auto& c : chains) all.push_back(c);
    for (auto& c : proxies) all.push_back(c);
    json wow_best = build_config(s, std::string(FLASH) + " WoW" + pro_indicator + "- Best Ping " + ROCKET,
                                 all, true, true, false, true, false, outbound_domains);

    configs.push_back(warp_best);
    configs.push_back(wow_best);

    out_json = configs.dump(4);
    return true;
}

} // namespace bpb::sub
