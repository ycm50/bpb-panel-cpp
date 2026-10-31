#include "sub/singbox.h"
#include "sub/common.h"
#include "util/util.h"

#include <algorithm>
#include <cstdlib>
#include <set>

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

struct GeoRule {
    std::string type;
    std::string geosite;
    std::string geoip;
    std::string dns;
    std::string geosite_url;
    std::string geoip_url;
};

const char* RULES_BASE = "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/";

std::vector<GeoRule> geo_assets(const json& s) {
    std::string local_dns = str(s, "localDNS");
    std::string sanction = str(s, "antiSanctionDNS");
    std::vector<GeoRule> out;
    auto add = [&](const char* key, const char* type, const char* geosite, const char* geoip,
                   const char* dns) {
        if (!flag(s, key)) return;
        GeoRule g;
        g.type = type;
        g.geosite = geosite;
        g.geoip = geoip ? geoip : "";
        if (dns) g.dns = std::string(dns) == "@local" ? local_dns : sanction;
        g.geosite_url = std::string(RULES_BASE) + geosite + ".srs";
        if (geoip) g.geoip_url = std::string(RULES_BASE) + geoip + ".srs";
        out.push_back(g);
    };
    add("blockMalware", "block", "geosite-malware", "geoip-malware", nullptr);
    add("blockPhishing", "block", "geosite-phishing", "geoip-phishing", nullptr);
    add("blockCryptominers", "block", "geosite-cryptominers", nullptr, nullptr);
    add("blockAds", "block", "geosite-category-ads-all", nullptr, nullptr);
    add("blockPorn", "block", "geosite-nsfw", nullptr, nullptr);
    add("bypassIran", "direct", "geosite-ir", "geoip-ir", "@local");
    add("bypassChina", "direct", "geosite-cn", "geoip-cn", "@local");
    add("bypassRussia", "direct", "geosite-category-ru", "geoip-ru", "@local");
    add("bypassOpenAi", "direct", "geosite-openai", nullptr, "@sanction");
    add("bypassGoogleAi", "direct", "geosite-google-deepmind", nullptr, "@sanction");
    add("bypassMicrosoft", "direct", "geosite-microsoft", nullptr, "@sanction");
    add("bypassOracle", "direct", "geosite-oracle", nullptr, "@sanction");
    add("bypassDocker", "direct", "geosite-docker", nullptr, "@sanction");
    add("bypassAdobe", "direct", "geosite-adobe", nullptr, "@sanction");
    add("bypassEpicGames", "direct", "geosite-epicgames", nullptr, "@sanction");
    add("bypassIntel", "direct", "geosite-intel", nullptr, "@sanction");
    add("bypassAmd", "direct", "geosite-amd", nullptr, "@sanction");
    add("bypassNvidia", "direct", "geosite-nvidia", nullptr, "@sanction");
    add("bypassAsus", "direct", "geosite-asus", nullptr, "@sanction");
    add("bypassHp", "direct", "geosite-hp", nullptr, "@sanction");
    add("bypassLenovo", "direct", "geosite-lenovo", nullptr, "@sanction");
    return out;
}

struct RoutingAcc {
    std::vector<std::string> block_geosites, block_domains, block_geoips, block_ips;
    std::vector<std::string> bypass_geosites, bypass_domains, bypass_geoips, bypass_ips;
};

RoutingAcc acc_routing_rules(const json& s, const std::vector<GeoRule>& geos) {
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

std::string host_of_url(const std::string& url) {
    std::string host = url;
    auto scheme = host.find("://");
    if (scheme != std::string::npos) host = host.substr(scheme + 3);
    auto slash = host.find('/');
    if (slash != std::string::npos) host = host.substr(0, slash);
    auto colon = host.rfind(':');
    if (colon != std::string::npos && host.find(']') == std::string::npos) host = host.substr(0, colon);
    return host;
}

json build_tls(const json& s, const std::string& security, bool is_fragment, bool allow_insecure,
               const std::string& sni, bool enable_ech, const std::string& ech_name,
               const std::string& alpn, const std::string& fingerprint,
               const std::string& public_key = "", const std::string& short_id = "") {
    if (security != "tls" && security != "reality") return json();

    json tls = json::object();
    tls["enabled"] = true;
    tls["server_name"] = sni;
    tls["record_fragment"] = is_fragment;
    tls["insecure"] = allow_insecure;
    if (!alpn.empty()) {
        std::vector<std::string> alpns;
        for (auto& a : split(alpn, ',')) {
            if (a != "h2") alpns.push_back(a);
        }
        tls["alpn"] = alpns;
    }
    json utls = json::object();
    utls["enabled"] = !fingerprint.empty();
    if (!fingerprint.empty()) utls["fingerprint"] = fingerprint;
    tls["utls"] = utls;
    if (enable_ech) {
        json ech = json::object();
        ech["enabled"] = true;
        if (!ech_name.empty()) ech["query_server_name"] = ech_name;
        tls["ech"] = ech;
    }
    if (security == "tls") return tls;
    if (security == "reality" && !public_key.empty() && !short_id.empty()) {
        tls["reality"] = {{"enabled", true}, {"public_key", public_key}, {"short_id", short_id}};
        return tls;
    }
    return tls;
}

json build_transport(const std::string& type, const std::string& header_type,
                     const std::string& raw_path, const std::string& host,
                     const std::string& service_name, int early_data) {
    std::string path = raw_path.empty() ? "/" : raw_path;
    auto q = path.find('?');
    if (q != std::string::npos) path = path.substr(0, q);

    if (type == "tcp") {
        if (header_type == "http") {
            json t = json::object();
            t["type"] = "http";
            if (!host.empty()) {
                std::vector<std::string> hosts;
                for (auto& h : split(host, ',')) hosts.push_back(h);
                t["host"] = hosts;
            }
            t["path"] = path;
            t["method"] = "GET";
            t["headers"] = {{"Connection", json::array({"keep-alive"})},
                            {"Content-Type", json::array({"application/octet-stream"})}};
            return t;
        }
        return json();
    }
    if (type == "ws") {
        json t = json::object();
        t["type"] = "ws";
        t["path"] = path;
        if (early_data > 0) {
            t["max_early_data"] = early_data;
            t["early_data_header_name"] = "Sec-WebSocket-Protocol";
        }
        if (!host.empty()) t["headers"] = {{"Host", host}};
        return t;
    }
    if (type == "httpupgrade") {
        json t = json::object();
        t["type"] = "httpupgrade";
        if (!host.empty()) t["host"] = host;
        t["path"] = path;
        return t;
    }
    if (type == "grpc") {
        return json{{"type", "grpc"}, {"service_name", service_name}};
    }
    return json();
}

json build_outbound_base(const std::string& tag, const std::string& type, const std::string& server,
                         int port, bool tfo, const json& fields, const json& tls,
                         const json& transport, bool is_chain) {
    json out = json::object();
    out["tag"] = tag;
    out["type"] = type;
    out["server"] = server;
    out["server_port"] = port;
    out["tcp_fast_open"] = tfo;
    for (auto& [k, v] : fields.items()) out[k] = v;
    if (!tls.is_null()) out["tls"] = tls;
    if (!transport.is_null()) out["transport"] = transport;
    if (is_domain(server)) out["domain_resolver"] = is_chain ? "dns-remote" : "dns-direct";
    return out;
}

json build_ws_outbound(const json& s, const std::string& protocol, const std::string& remark,
                       const std::string& address, int port, const std::string& domain,
                       bool is_fragment) {
    std::string upstream_server;
    if (s.contains("upstreamParams") && s["upstreamParams"].is_object()) {
        upstream_server = s["upstreamParams"].value("upstreamServer", std::string());
    }
    auto sni_host = select_sni_host(s, address, domain);
    json transport = build_transport("ws", "none", generate_ws_path(protocol), sni_host.host, "", 2560);
    bool is_tls = is_https(s, port) || (!upstream_server.empty() && address == upstream_server);
    json tls = is_tls ? build_tls(s, "tls", is_fragment, sni_host.allow_insecure, sni_host.sni,
                                  flag(s, "enableECH") && !is_fragment, str(s, "echServerName"),
                                  "http/1.1", str(s, "fingerprint", "chrome"))
                      : json();

    json fields = json::object();
    fields["uuid"] = str(s, "vlUUID");
    fields["packet_encoding"] = "";
    fields["network"] = "tcp";
    return build_outbound_base(remark, protocol, address, port, flag(s, "enableTFO"), fields, tls,
                               transport, false);
}

json build_warp_endpoint(const json& s, const json& account, const std::string& remark,
                         const std::string& endpoint, const std::string& chain = "") {
    std::string host = endpoint;
    int port = 2408;
    auto colon = endpoint.rfind(':');
    if (colon != std::string::npos) {
        host = endpoint.substr(0, colon);
        port = std::atoi(endpoint.substr(colon + 1).c_str());
    }
    if (!host.empty() && host.front() == '[') {
        auto close = host.find(']');
        if (close != std::string::npos) host = host.substr(1, close - 1);
    }

    std::vector<int> reserved;
    if (flag(s, "warpReservedBytes")) {
        std::string raw = base64_decode(account.value("reserved", std::string()));
        for (unsigned char c : raw) reserved.push_back(c);
    } else {
        reserved = {0, 0, 0};
    }

    std::string address = chain.empty() ? host : std::string("162.159.192.1");
    json j = json::object();
    j["tag"] = remark;
    if (!chain.empty()) j["detour"] = chain;
    j["type"] = "wireguard";
    j["address"] = json::array({"172.16.0.2/32", account.value("warpIPv6", std::string())});
    j["mtu"] = 1280;
    j["peers"] = json::array(
        {{{"address", address},
          {"port", chain.empty() ? port : 2408},
          {"public_key", account.value("publicKey", std::string())},
          {"reserved", reserved},
          {"allowed_ips", json::array({"0.0.0.0/0", "::/0"})},
          {"persistent_keepalive_interval", 5}}});
    j["private_key"] = account.value("privateKey", std::string());
    if (is_domain(address)) j["domain_resolver"] = "dns-direct";
    return j;
}

json build_dns(const json& s, bool is_warp, bool is_chain) {
    std::string local_dns = str(s, "localDNS");
    std::string remote_dns = str(s, "remoteDNS");
    std::string warp_remote_dns = str(s, "warpRemoteDNS");
    std::string sanction = str(s, "antiSanctionDNS");
    bool enable_ipv6 = flag(s, "enableIPv6");
    bool fake_dns = flag(s, "fakeDNS");

    std::string protocol = "https";
    auto scheme = remote_dns.find("://");
    if (scheme != std::string::npos) protocol = remote_dns.substr(0, scheme);

    json servers = json::array();
    json remote = json::object();
    remote["type"] = is_warp ? "udp" : protocol;
    std::string remote_host = str(s, "remoteDnsHost");
    if (s.contains("remoteDnsHost") && s["remoteDnsHost"].is_object()) {
        remote_host = s["remoteDnsHost"].value("host", std::string());
    }
    remote["server"] = is_warp ? warp_remote_dns : remote_host;
    remote["detour"] = is_warp ? (std::string(FLASH) + " Warp - Best Ping " + ROCKET)
                               : (is_chain ? (std::string(FLASH) + " Best Ping " + ROCKET)
                                           : (std::string(CHECK) + " Selector"));
    remote["tag"] = "dns-remote";
    servers.push_back(remote);

    if (local_dns == "localhost") {
        servers.push_back({{"type", "local"}, {"tag", "dns-direct"}});
    } else {
        servers.push_back({{"type", "udp"}, {"server", local_dns}, {"tag", "dns-direct"}});
    }

    json rules = json::array();
    rules.push_back({{"clash_mode", "Direct"}, {"server", "dns-direct"}});
    rules.push_back({{"clash_mode", "Global"}, {"server", "dns-remote"}});

    if (flag(s, "enableECH")) {
        std::vector<std::string> names;
        std::string ech_name = str(s, "echServerName");
        if (!ech_name.empty()) names.push_back(ech_name);
        else {
            names.push_back(str(s, "mainDomain"));
            std::string custom = str(s, "customDomain");
            if (!custom.empty()) names.push_back(custom);
        }
        json rule = {{"domain", names}, {"query_type", json::array({"HTTPS"})},
                     {"action", "route"}, {"server", "dns-direct"}};
        rules.push_back(rule);
    }

    if (s.contains("remoteDnsHost") && s["remoteDnsHost"].is_object() &&
        s["remoteDnsHost"].value("isDomain", false) && !is_warp) {
        auto& rdh = s["remoteDnsHost"];
        std::string host = rdh.value("host", std::string());
        std::vector<std::string> ips = to_string_list(rdh, "ipv4");
        if (enable_ipv6) {
            for (auto& ip : to_string_list(rdh, "ipv6")) ips.push_back(ip);
        }
        json hosts = json::object();
        hosts[host] = ips;
        servers.push_back({{"type", "hosts"}, {"predefined", hosts}, {"tag", "hosts"}});
        json new_rule = {{"ip_accept_any", true}, {"server", "hosts"}};
        json rebuilt = json::array();
        rebuilt.push_back(new_rule);
        for (auto& r : rules) rebuilt.push_back(r);
        rules = rebuilt;
    }

    auto geos = geo_assets(s);
    auto dns_acc = acc_dns_rules(s, geos);

    std::vector<std::string> block_domains = dns_acc.block_geosites;
    for (auto& d : dns_acc.block_domains) block_domains.push_back(d);
    if (!block_domains.empty()) {
        json rule = json::object();
        if (!dns_acc.block_geosites.empty()) rule["rule_set"] = dns_acc.block_geosites;
        if (!dns_acc.block_domains.empty()) rule["domain_suffix"] = dns_acc.block_domains;
        rule["action"] = "reject";
        rules.push_back(rule);
    }

    for (auto& [geosite, geoip] : dns_acc.local_geosite_geoip) {
        json rule = json::object();
        rule["type"] = "logical";
        rule["mode"] = "and";
        rule["rules"] = json::array({{{"rule_set", json::array({geosite})}},
                                     {{"rule_set", json::array({geoip})}}});
        rule["action"] = "route";
        rule["server"] = "dns-direct";
        rules.push_back(rule);
    }

    if (!dns_acc.local_geosites.empty() || !dns_acc.local_domains.empty()) {
        json rule = json::object();
        if (!dns_acc.local_geosites.empty()) rule["rule_set"] = dns_acc.local_geosites;
        if (!dns_acc.local_domains.empty()) rule["domain_suffix"] = dns_acc.local_domains;
        rule["action"] = "route";
        rule["server"] = "dns-direct";
        rules.push_back(rule);
    }

    if (!dns_acc.sanction_geosites.empty() || !dns_acc.sanction_domains.empty()) {
        json rule = json::object();
        if (!dns_acc.sanction_geosites.empty()) rule["rule_set"] = dns_acc.sanction_geosites;
        if (!dns_acc.sanction_domains.empty()) rule["domain_suffix"] = dns_acc.sanction_domains;
        rule["action"] = "route";
        rule["server"] = "dns-anti-sanction";
        rules.push_back(rule);

        std::string host = host_of_url(sanction);
        if (is_domain(host)) {
            servers.push_back({{"type", "https"},
                               {"server", host},
                               {"tag", "dns-anti-sanction"},
                               {"domain_resolver", {{"server", "dns-direct"}, {"strategy", "ipv4_only"}}}});
        } else {
            servers.push_back({{"type", "udp"}, {"server", sanction}, {"tag", "dns-anti-sanction"}});
        }
    }

    if (fake_dns) {
        json fake = {{"type", "fakeip"},
                     {"tag", "dns-fake"},
                     {"inet4_range", "198.18.0.0/15"}};
        if (enable_ipv6) fake["inet6_range"] = "fc00::/18";
        servers.push_back(fake);
        rules.push_back({{"inbound", "tun-in"},
                         {"query_type", json::array({"A", "AAAA"})},
                         {"action", "route"},
                         {"server", "dns-fake"}});
    }

    json dns = json::object();
    dns["servers"] = servers;
    dns["rules"] = rules;
    dns["strategy"] = enable_ipv6 ? "prefer_ipv4" : "ipv4_only";
    dns["independent_cache"] = true;
    return dns;
}

json build_routing(const json& s, bool is_warp) {
    json rules = json::array();
    rules.push_back({{"ip_cidr", "172.19.0.2"}, {"action", "hijack-dns"}});
    rules.push_back({{"clash_mode", "Direct"}, {"outbound", "direct"}});
    rules.push_back({{"clash_mode", "Global"}, {"outbound", std::string(CHECK) + " Selector"}});
    rules.push_back({{"action", "sniff"}});
    rules.push_back({{"protocol", "dns"}, {"action", "hijack-dns"}});
    rules.push_back({{"ip_is_private", true}, {"outbound", "direct"}});

    if (!is_warp) {
        rules.push_back({{"network", "udp"}, {"action", "reject"}});
    } else if (flag(s, "blockUDP443")) {
        rules.push_back({{"network", "udp"}, {"protocol", "quic"}, {"port", 443}, {"action", "reject"}});
    }

    auto geos = geo_assets(s);
    auto acc = acc_routing_rules(s, geos);

    if (!acc.block_geosites.empty() || !acc.block_domains.empty()) {
        json rule = json::object();
        if (!acc.block_geosites.empty()) rule["rule_set"] = acc.block_geosites;
        if (!acc.block_domains.empty()) rule["domain_suffix"] = acc.block_domains;
        rule["action"] = "reject";
        rules.push_back(rule);
    }
    if (!acc.block_geoips.empty() || !acc.block_ips.empty()) {
        json rule = json::object();
        if (!acc.block_geoips.empty()) rule["rule_set"] = acc.block_geoips;
        if (!acc.block_ips.empty()) rule["ip_cidr"] = acc.block_ips;
        rule["action"] = "reject";
        rules.push_back(rule);
    }
    if (!acc.bypass_geosites.empty() || !acc.bypass_domains.empty()) {
        json rule = json::object();
        if (!acc.bypass_geosites.empty()) rule["rule_set"] = acc.bypass_geosites;
        if (!acc.bypass_domains.empty()) rule["domain_suffix"] = acc.bypass_domains;
        rule["outbound"] = "direct";
        rules.push_back(rule);
    }
    if (!acc.bypass_geoips.empty() || !acc.bypass_ips.empty()) {
        json rule = json::object();
        if (!acc.bypass_geoips.empty()) rule["rule_set"] = acc.bypass_geoips;
        if (!acc.bypass_ips.empty()) rule["ip_cidr"] = acc.bypass_ips;
        rule["outbound"] = "direct";
        rules.push_back(rule);
    }

    json rule_sets = json::array();
    std::set<std::string> seen;
    for (auto& g : geos) {
        auto push = [&](const std::string& geo, const std::string& url) {
            if (url.empty() || !seen.insert(geo).second) return;
            rule_sets.push_back(
                {{"type", "remote"}, {"tag", geo}, {"format", "binary"}, {"url", url},
                 {"download_detour", "direct"}});
        };
        push(g.geosite, g.geosite_url);
        if (!g.geoip.empty()) push(g.geoip, g.geoip_url);
    }

    json route = json::object();
    route["rules"] = rules;
    if (!rule_sets.empty()) route["rule_set"] = rule_sets;
    route["auto_detect_interface"] = true;
    route["final"] = std::string(CHECK) + " Selector";
    return route;
}

json build_urltest(const json& s, const std::string& tag, const std::vector<std::string>& tags,
                   bool is_warp) {
    int interval = is_warp ? num(s, "warpBestPingInterval", 30) : num(s, "bestPingInterval", 30);
    return {{"type", "urltest"},
            {"tag", tag},
            {"outbounds", tags},
            {"url", "https://www.gstatic.com/generate_204"},
            {"interrupt_exist_connections", false},
            {"interval", std::to_string(interval) + "s"}};
}

json build_config(const json& s, const json& outbounds, const json& endpoints,
                  const std::vector<std::pair<std::string, std::vector<std::string>>>& tag_groups,
                  bool is_warp, bool is_chain) {
    std::string log_level = str(s, "logLevel", "warning");

    std::vector<std::pair<std::string, std::vector<std::string>>> groups;
    std::vector<std::string> selector_tags;
    for (auto& g : tag_groups) {
        if (g.second.empty()) continue;
        groups.push_back(g);
        selector_tags.push_back(g.first);
        for (auto& t : g.second) selector_tags.push_back(t);
    }

    json config = json::object();
    json log = json::object();
    log["disabled"] = (log_level == "none");
    if (log_level != "none") log["level"] = (log_level == "warning") ? "warn" : log_level;
    log["timestamp"] = true;
    config["log"] = log;
    config["dns"] = build_dns(s, is_warp, is_chain);

    json tun = {{"type", "tun"},
                {"tag", "tun-in"},
                {"address", json::array({"172.19.0.1/28"})},
                {"mtu", 9000},
                {"auto_route", true},
                {"strict_route", true},
                {"stack", "mixed"}};
    json mixed = {{"type", "mixed"},
                  {"tag", "mixed-in"},
                  {"listen", flag(s, "allowLANConnection") ? "0.0.0.0" : "127.0.0.1"},
                  {"listen_port", 2080}};
    config["inbounds"] = json::array({tun, mixed});

    json outs = json::array();
    for (auto& o : outbounds) outs.push_back(o);
    outs.push_back({{"type", "selector"},
                    {"tag", std::string(CHECK) + " Selector"},
                    {"outbounds", selector_tags},
                    {"interrupt_exist_connections", false}});
    outs.push_back({{"type", "direct"}, {"tag", "direct"}, {"domain_resolver", "dns-direct"}});
    config["outbounds"] = outs;

    if (!endpoints.empty()) config["endpoints"] = endpoints;

    config["route"] = build_routing(s, is_warp);
    config["ntp"] = {{"enabled", true},
                     {"server", "time.cloudflare.com"},
                     {"server_port", 123},
                     {"domain_resolver", "dns-direct"},
                     {"interval", "30m"},
                     {"write_to_system", false}};
    config["experimental"] = {
        {"cache_file", {{"enabled", true}, {"store_fakeip", true}}},
        {"clash_api", {{"external_controller", "127.0.0.1:9090"},
                       {"external_ui", "ui"},
                       {"default_mode", "Rule"},
                       {"external_ui_download_url",
                        "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"},
                       {"external_ui_download_detour", "direct"}}}};

    for (auto& g : groups) {
        config["outbounds"].push_back(build_urltest(s, g.first, g.second, is_warp));
    }
    return config;
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

    json tls = build_tls(s, security, false, false, sni.empty() ? server : sni, false, "", alpn, fp, pbk, sid);
    json transport = build_transport(type, cp.value("headerType", std::string()), path, host,
                                     cp.value("serviceName", std::string()), 0);

    json fields = json::object();
    if (protocol == "http") {
        fields["username"] = cp.value("user", std::string());
        fields["password"] = cp.value("pass", std::string());
    } else if (protocol == "socks") {
        fields["username"] = cp.value("user", std::string());
        fields["password"] = cp.value("pass", std::string());
        fields["version"] = "5";
        fields["network"] = "tcp";
    } else if (protocol == "shadowsocks") {
        fields["method"] = cp.value("method", std::string());
        fields["password"] = cp.value("password", std::string());
        fields["network"] = "tcp";
    } else if (protocol == "vless") {
        fields["uuid"] = cp.value("uuid", std::string());
        if (cp.contains("flow")) fields["flow"] = cp["flow"];
        fields["network"] = "tcp";
    } else if (protocol == "vmess") {
        fields["uuid"] = cp.value("uuid", std::string());
        fields["security"] = "auto";
        fields["alter_id"] = cp.value("aid", 0);
        fields["network"] = "tcp";
    } else if (protocol == "trojan") {
        fields["password"] = cp.value("password", std::string());
        fields["network"] = "tcp";
    } else {
        return json();
    }

    json out = build_outbound_base("", protocol, server, port, false, fields, tls, transport, true);
    return out;
}

} // namespace

bool build_sb_custom(const json& s, bool is_fragment, std::string& out_json, std::string& error) {
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
            if ((!is_fragment && is_workers_dev) || is_https(s, port)) total_ports.push_back(port);
        }
        auto hosts = get_config_addresses(s, domain, is_fragment, error);
        if (hosts.empty()) return false;

        if (!upstream_server.empty() && upstream_port) {
            total_ports.insert(total_ports.begin(), upstream_port);
            hosts.insert(hosts.begin(), upstream_server);
        }

        bool is_custom = (!custom_domain.empty() && domain == custom_domain);

        for (auto& protocol : protocols) {
            if (protocol != "vless") continue;
            int protocol_index = 1;
            for (int port : total_ports) {
                for (auto& host : hosts) {
                    bool port_is_upstream = (port == upstream_port);
                    bool host_is_upstream = (!upstream_server.empty() && host == upstream_server);
                    if (port_is_upstream != host_is_upstream) continue;

                    std::string tag = generate_remark(s, protocol_index, port, host, protocol, domain,
                                                      is_fragment, false);
                    outbounds.push_back(build_ws_outbound(s, protocol, tag, host, port, domain, is_fragment));

                    for (auto& g : tag_group) {
                        if (g.first == (is_custom ? best_ping_d : best_ping)) g.second.push_back(tag);
                    }

                    if (is_chain) {
                        std::string chain_tag = generate_remark(s, protocol_index, port, host, protocol,
                                                                domain, is_fragment, true);
                        json chain = chain_outbound;
                        chain["tag"] = chain_tag;
                        chain["detour"] = tag;
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

    json config = build_config(s, outbounds, json::array(), tag_group, false, is_chain);
    out_json = config.dump(4);
    return true;
}

bool build_sb_warp(const json& s, const json& warp_accounts, std::string& out_json,
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

    std::string warp_best = std::string(FLASH) + " Warp - Best Ping " + ROCKET;
    std::string wow_best = std::string(FLASH) + " WoW - Best Ping " + ROCKET;
    std::vector<std::pair<std::string, std::vector<std::string>>> tag_group = {{warp_best, {}},
                                                                               {wow_best, {}}};

    json endpoints_json = json::array();
    int index = 0;
    for (auto& endpoint : endpoints) {
        std::string warp_tag = std::string(FLASH) + " " + std::to_string(index + 1) + ". Warp " + IRAN;
        std::string wow_tag = std::string(FLASH) + " " + std::to_string(index + 1) + ". WoW " + GLOBE;
        tag_group[0].second.push_back(warp_tag);
        tag_group[1].second.push_back(wow_tag);

        endpoints_json.push_back(build_warp_endpoint(s, warp_accounts[0], warp_tag, endpoint));
        endpoints_json.push_back(build_warp_endpoint(s, warp_accounts[1], wow_tag, endpoint, warp_tag));
        ++index;
    }

    json config = build_config(s, json::array(), endpoints_json, tag_group, true, false);
    out_json = config.dump(4);
    return true;
}

} // namespace bpb::sub
