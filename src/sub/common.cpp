#include "sub/common.h"
#include "crypto/crypto.h"
#include "inbound/inbound.h"
#include "net/http_client.h"
#include "util/util.h"

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>
#include <random>

namespace bpb::sub {

static std::mt19937& rng() {
    static std::mt19937 gen(std::random_device{}());
    return gen;
}

std::vector<std::string> to_string_list(const nlohmann::json& j, const std::string& key) {
    std::vector<std::string> out;
    if (!j.contains(key) || !j[key].is_array()) return out;
    for (auto& item : j[key]) {
        if (item.is_string()) out.push_back(item.get<std::string>());
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string random_upper_case(const std::string& in) {
    std::uniform_int_distribution<int> coin(0, 1);
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (coin(rng())) {
            out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        } else {
            out += c;
        }
    }
    return out;
}

std::string get_random_string(int length_min, int length_max) {
    static const char* charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::uniform_int_distribution<int> dist(length_min, length_max);
    std::uniform_int_distribution<int> pick(0, 61);
    int length = dist(rng());
    std::string out;
    out.reserve(static_cast<std::size_t>(length));
    for (int i = 0; i < length; ++i) out += charset[pick(rng())];
    return out;
}

std::string generate_ws_path(const std::string& protocol, const std::string& credential) {
    // A fixed path: the credential is the UUID/password, so a random per-request
    // suffix protected nothing and only made every restart invalidate the
    // subscription links. The segment comes from the compiled-in table, so a
    // protocol cannot advertise a path its own dispatcher does not serve.
    if (const inbound::Inbound* in = inbound::by_id(protocol)) {
        if (in->path) return std::string("/") + in->path;
        // VMess: the client-side convention is "/<uuid>-vm" (see the deployment
        // snippet the protocol was specified with).
        std::string clean;
        for (char c : credential) {
            if (c != '-') clean += c;
        }
        return "/" + clean + "-vm";
    }
    return "/" + protocol;
}

bool is_domain(const std::string& address) {
    if (address.empty()) return false;
    if (address.find('.') == std::string::npos) return false;
    for (char c : address) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-')) return false;
    }
    auto labels = split(address, '.');
    if (labels.size() < 2) return false;
    std::string tld = labels.back();
    if (tld.size() < 2 || tld.size() > 63) return false;
    for (char c : tld) {
        if (!std::isalpha(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

bool is_ipv4(const std::string& address) {
    std::string host = address;
    auto slash = host.find('/');
    if (slash != std::string::npos) host = host.substr(0, slash);
    auto parts = split(host, '.');
    if (parts.size() != 4) return false;
    for (auto& p : parts) {
        if (p.empty() || p.size() > 3) return false;
        for (char c : p) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        int v = std::atoi(p.c_str());
        if (v < 0 || v > 255) return false;
    }
    return true;
}

bool is_ipv6(const std::string& address) {
    if (address.size() < 3) return false;
    if (address.front() != '[') return false;
    auto close = address.find(']');
    if (close == std::string::npos) return false;
    std::string inside = address.substr(1, close - 1);
    if (inside.find(':') == std::string::npos) return false;
    for (char c : inside) {
        if (!(std::isxdigit(static_cast<unsigned char>(c)) || c == ':' || c == '.')) return false;
    }
    return true;
}

bool is_base64(const std::string& str) {
    if (str.empty() || str.size() % 4 != 0) return false;
    for (char c : str) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '=' || c == '\r' ||
              c == '\n'))
            return false;
    }
    return true;
}

// ---- access model -------------------------------------------------------
// The single source of truth for "tunnel or direct". settings.accessMode is
// written by Store::merged(); when a settings blob predates it (or came from
// share-settings) fall back to the cfTunnel switch, which is the same thing the
// tunnel supervisor reads.
bool access_mode_direct(const nlohmann::json& s) {
    if (s.contains("accessMode") && s["accessMode"].is_string())
        return s["accessMode"].get<std::string>() == "direct";
    if (s.contains("cfTunnel") && s["cfTunnel"].is_object())
        return !s["cfTunnel"].value("enabled", false);
    if (s.contains("cfTunnelEnabled")) {
        if (s["cfTunnelEnabled"].is_boolean()) return !s["cfTunnelEnabled"].get<bool>();
        if (s["cfTunnelEnabled"].is_string())
            return s["cfTunnelEnabled"].get<std::string>() != "true";
    }
    return true;
}

bool access_mode_tunnel(const nlohmann::json& s) { return !access_mode_direct(s); }

std::string pinned_cert(const nlohmann::json& s) {
    // Tunnel mode: the Cloudflare edge terminates TLS with its own certificate,
    // so the self-signed leaf of this process is never what the client sees.
    if (!access_mode_direct(s)) return std::string();
    return s.value("certPin", std::string());
}

std::string direct_host(const nlohmann::json& s) {
    std::string host = s.value("directHost", std::string());
    // A tunnel hostname must never leak into direct mode: it is a name only the
    // Cloudflare edge can resolve, so a client dialing it with no tunnel behind
    // it gets either NXDOMAIN or a 530 from the edge.
    if (host.empty() || host == "localhost" || ends_with(host, ".trycloudflare.com")) {
        const std::string custom = s.value("customDomain", std::string());
        if (!custom.empty()) return custom;
        // Never hand a client the edge hostname: with no tunnel behind it the
        // name resolves at Cloudflare to a 530, which looks like "the panel is
        // down" instead of "you have not set the public address yet".
        return "localhost";
    }
    return host;
}

std::vector<int> effective_ports(const nlohmann::json& s, const std::string& domain) {
    std::vector<int> out;
    if (access_mode_direct(s)) {
        // Exactly one truth: the port this process bound. Anything else is a
        // port nothing is listening on, which is what made direct mode look
        // "almost usable" -- the config imported, then timed out.
        // A TLS listener wins: it is the only port that both listens and
        // satisfies Xray's "no plaintext VLESS to a public address" rule.
        //
        // The port published is the PUBLIC one. With a NAT/port-mapping in
        // front, the TLS listener's bind port and the port a client dials are
        // different numbers (the test box maps public 45566 -> local 8080);
        // directPort carries the public value, derived from the Host header of
        // the request that fetched the subscription.
        if (s.contains("tlsPort") && s["tlsPort"].is_number_integer() &&
            s["tlsPort"].get<int>() > 0) {
            int port = s["tlsPort"].get<int>();
            if (s.contains("directPort") && s["directPort"].is_number_integer()) {
                const int pub = s["directPort"].get<int>();
                if (pub > 0) port = pub;
            }
            out.push_back(port);
            return out;
        }
        int port = 0;
        if (s.contains("directPort") && s["directPort"].is_number_integer())
            port = s["directPort"].get<int>();
        if (port <= 0 && s.contains("listenPort") && s["listenPort"].is_number_integer())
            port = s["listenPort"].get<int>();
        if (port <= 0) {
            // Last resort: the first configured port, so an import still yields
            // something rather than an empty subscription.
            for (const std::string& p : to_string_list(s, "ports")) {
                port = std::atoi(p.c_str());
                if (port > 0) break;
            }
            if (port <= 0 && s.contains("ports") && s["ports"].is_array()) {
                for (auto& p : s["ports"]) {
                    if (p.is_number_integer()) { port = p.get<int>(); break; }
                }
            }
        }
        if (port > 0) out.push_back(port);
        return out;
    }

    const bool is_workers_dev = ends_with(domain, "workers.dev");
    if (s.contains("ports") && s["ports"].is_array()) {
        for (auto& p : s["ports"]) {
            if (!p.is_number_integer()) continue;
            const int port = p.get<int>();
            if (is_workers_dev || is_https(s, port)) out.push_back(port);
        }
    }
    return out;
}

bool port_uses_tls(const nlohmann::json& s, const std::string& domain, int port) {
    if (access_mode_direct(s)) {
        // Xray 26.x refuses a VLESS outbound with security=none to any public
        // address ("vless without TLS or other encryption is prohibited unless
        // the server address is a private IP or domain"), so the TLS listener
        // port and the panel port are not interchangeable: only the port that
        // actually terminates TLS may be published. tlsPort says which.
        if (s.contains("tlsPort") && s["tlsPort"].is_number_integer()) {
            const int tls_port = s["tlsPort"].get<int>();
            if (tls_port <= 0) return false;
            // The published port may be the public one (NAT mapping), not the
            // bind port, so both count as "this is the TLS listener".
            if (port == tls_port) return true;
            if (s.contains("directPort") && s["directPort"].is_number_integer() &&
                s["directPort"].get<int>() == port)
                return true;
            return false;
        }
        if (s.contains("listenTls") && s["listenTls"].is_boolean())
            return s["listenTls"].get<bool>();
        return false;
    }
    (void)domain;
    return is_https(s, port);
}

bool is_https(const nlohmann::json& s, int port) {
    std::vector<int> https_ports = {443, 8443, 2053, 2083, 2087, 2096};
    if (s.contains("ports") && s["ports"].is_array() && !s["ports"].empty()) {
        // keep parity with the TS defaults: https ports come from the runtime, not settings
    }
    for (int p : https_ports) {
        if (p == port) return true;
    }
    return false;
}

std::vector<std::string> get_protocols(const nlohmann::json& s) {
    // Only protocols compiled into this binary can actually be served, so the
    // configured list is intersected with the compile-time table. A settings file
    // copied from another build (or from upstream) may name protocols this
    // binary does not have; handing those to a client produces dead links.
    std::vector<std::string> out;
    for (const std::string& p : split(s.value("protocols", std::string("vless")), ',')) {
        if (inbound::has(p)) out.push_back(p);
    }
    if (out.empty() && !inbound::all().empty()) {
        // An empty set would render an empty subscription and a panel with no
        // protocol to tick; fall back to the first compiled-in one.
        out.push_back(inbound::all().front()->id);
    }
    return out;
}

std::vector<std::string> get_transports(const nlohmann::json& s) {
    // WebSocket is unconditional: it is what this project has always emitted and
    // what the panel's "default" answer means. The other two are opt-in switches
    // because a client that does not understand them silently fails to connect,
    // and because the inbounds may not even be compiled into this binary.
    std::vector<std::string> out{"ws"};
    auto enabled = [&](const char* key) {
        return s.contains(key) && s[key].is_boolean() && s[key].get<bool>();
    };
    if (enabled("enableXHTTP") && inbound::has("vless-xhttp")) out.push_back("xhttp");
    if (enabled("enableGRPC") && inbound::has("vless-grpc")) out.push_back("grpc");
    return out;
}

std::string transport_suffix(const std::string& transport) {
    if (transport == "xhttp") return " XHTTP";
    if (transport == "grpc") return " gRPC";
    return "";
}

struct CachedDns {
    DnsResult result;
    std::int64_t expires_at = 0;
};

static std::map<std::string, CachedDns>& dns_cache() {
    static std::map<std::string, CachedDns> cache;
    return cache;
}

bool resolve_dns(const std::string& domain, bool only_ipv4, DnsResult& out, std::string& error) {
    // A literal address or a loopback name has nothing to resolve. Sending it to
    // DoH used to fail the whole subscription on a box with no outbound DNS (a
    // fresh panel defaults mainDomain to "localhost"), which made every
    // subscription return 500 even though the answer was already known.
    if (domain.empty() || is_ipv4(domain) || is_ipv6(domain) || domain == "localhost" ||
        ends_with(domain, ".localhost")) {
        out = DnsResult{};
        return true;
    }
    std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    std::string cache_key = domain + (only_ipv4 ? "|4" : "|46");
    auto& cache = dns_cache();
    auto it = cache.find(cache_key);
    if (it != cache.end() && it->second.expires_at > now) {
        out = it->second.result;
        return true;
    }
    auto query = [&](const std::string& type, std::vector<std::string>& target) -> bool {
        std::string url = "https://cloudflare-dns.com/dns-query?name=" + url_encode(domain) +
                          "&type=" + type;
        net::httpc::Response res;
        std::string err;
        if (!net::httpc::get(url, res, err, 8000, {{"Accept", "application/dns-json"}})) {
            error = "DoH failed for " + domain + ": " + err;
            return false;
        }
        if (res.status != 200) {
            error = "DoH status " + std::to_string(res.status) + " for " + domain;
            return false;
        }
        try {
            auto j = nlohmann::json::parse(res.body);
            if (!j.contains("Answer") || !j["Answer"].is_array()) return true;
            int want = (type == "A") ? 1 : 28;
            for (auto& rec : j["Answer"]) {
                if (rec.value("type", 0) == want && rec.contains("data") && rec["data"].is_string()) {
                    target.push_back(rec["data"].get<std::string>());
                }
            }
            return true;
        } catch (const std::exception& e) {
            error = std::string("DoH json parse failed: ") + e.what();
            return false;
        }
    };

    if (!query("A", out.ipv4)) return false;
    if (!only_ipv4) {
        if (!query("AAAA", out.ipv6)) return false;
    }
    CachedDns entry;
    entry.result = out;
    entry.expires_at = now + 300;
    cache[cache_key] = entry;
    return true;
}

std::vector<std::string> get_config_addresses(const nlohmann::json& s, const std::string& domain,
                                              bool is_fragment, std::string& error) {
    // Direct mode has no Cloudflare edge to dial back through. cleanIPs and
    // customCdnAddrs are *edge* addresses: the client connects to a Cloudflare
    // PoP and the edge routes it to us by the Host/SNI header. With no tunnel
    // there is no edge, so those entries are third-party hosts that can never
    // reach this server -- publishing them produced nodes that look fine in an
    // import and always time out. Exactly one address is real here.
    if (access_mode_direct(s)) return {direct_host(s)};

    bool enable_ipv6 = s.value("enableIPv6", false);
    auto clean_ips = to_string_list(s, "cleanIPs");
    auto custom_cdn = to_string_list(s, "customCdnAddrs");

    DnsResult dns;
    if (!resolve_dns(domain, !enable_ipv6, dns, error)) return {};

    std::vector<std::string> addrs;
    addrs.push_back(domain);
    for (auto& ip : dns.ipv4) addrs.push_back(ip);
    for (auto& ip : dns.ipv6) addrs.push_back("[" + ip + "]");
    for (auto& ip : clean_ips) addrs.push_back(ip);
    if (!is_fragment) {
        for (auto& ip : custom_cdn) addrs.push_back(ip);
    }
    return addrs;
}

SniHost select_sni_host(const nlohmann::json& s, const std::string& address,
                        const std::string& domain) {
    auto custom_cdn = to_string_list(s, "customCdnAddrs");
    bool is_custom = false;
    for (auto& a : custom_cdn) {
        if (a == address) {
            is_custom = true;
            break;
        }
    }
    SniHost out;
    if (is_custom) {
        out.sni = s.value("customCdnSni", std::string());
        out.host = s.value("customCdnHost", std::string());
        out.allow_insecure = true;
    } else if (access_mode_direct(s)) {
        // Direct transport: there is no Cloudflare edge in front, so the
        // randomly-cased hostname that exists to dodge SNI blocklists only made
        // the config look fronted and sent every bug report chasing a TLS
        // problem that does not exist.
        out.sni = domain;
        out.host = domain;
        out.allow_insecure = false;
    } else {
        out.sni = random_upper_case(domain);
        out.host = domain;
        out.allow_insecure = false;
    }
    return out;
}

std::string generate_remark(const nlohmann::json& s, int index, int port, const std::string& address,
                            const std::string& protocol, const std::string& domain,
                            bool is_fragment, bool is_chain) {
    auto clean_ips = to_string_list(s, "cleanIPs");
    auto custom_cdn = to_string_list(s, "customCdnAddrs");
    std::string custom_domain = s.value("customDomain", std::string());
    std::string upstream_server;
    if (s.contains("upstreamParams") && s["upstreamParams"].is_object()) {
        upstream_server = s["upstreamParams"].value("upstreamServer", std::string());
    }

    std::string chain_sign = is_chain ? "\xF0\x9F\x94\x97 " : "";
    std::string proto_sign = "VLESS";
    std::string fragment_sign = is_fragment ? "F " : "";
    std::string custom_domain_sign = (!custom_domain.empty() && domain == custom_domain) ? "D " : "";
    std::string custom_cdn_sign;
    for (auto& a : custom_cdn) {
        if (a == address) custom_cdn_sign = "C ";
    }
    std::string config_type = fragment_sign + custom_domain_sign + custom_cdn_sign;

    std::string address_type;
    bool is_clean = false;
    for (auto& a : clean_ips) {
        if (a == address) is_clean = true;
    }
    if (is_clean) address_type = "Clean IP";
    else if (is_domain(address)) address_type = "Domain";
    else if (is_ipv4(address)) address_type = "IPv4";
    else if (is_ipv6(address)) address_type = "IPv6";

    std::string prefix = "\xF0\x9F\x92\xA6 " + std::to_string(index) + ". " + chain_sign +
                         proto_sign + " " + config_type;
    if (!upstream_server.empty() && address == upstream_server) {
        return prefix + "- Upstream Proxy";
    }
    return prefix + "- " + address_type + " : " + std::to_string(port);
}

} // namespace bpb::sub
