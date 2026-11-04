#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace bpb::sub {

struct DnsResult {
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
};

bool resolve_dns(const std::string& domain, bool only_ipv4, DnsResult& out, std::string& error);
std::vector<std::string> get_config_addresses(const nlohmann::json& s, const std::string& domain,
                                              bool is_fragment, std::string& error);
std::vector<std::string> get_protocols(const nlohmann::json& s);

std::string generate_remark(const nlohmann::json& s, int index, int port, const std::string& address,
                            const std::string& protocol, const std::string& domain,
                            bool is_fragment, bool is_chain);
// WebSocket path a client must use for this protocol. VMess encodes the
// credential in the path, so the caller has to hand it over.
std::string generate_ws_path(const std::string& protocol, const std::string& credential = "");

// Transports a subscription must emit. WebSocket always comes first: it is the
// default and the only transport every client understands. XHTTP and gRPC are
// appended when the panel switches (enableXHTTP / enableGRPC) are on, so turning
// them on *adds* entries instead of replacing the websocket ones — a client that
// cannot do either still has something to import.
std::vector<std::string> get_transports(const nlohmann::json& s);

// Suffix that keeps names/remarks unique when one server is emitted once per
// transport: "" for websocket, " XHTTP", " gRPC".
std::string transport_suffix(const std::string& transport);

std::string random_upper_case(const std::string& in);
std::string get_random_string(int length_min, int length_max);

// ---- access model -------------------------------------------------------
// A subscription has to answer three questions that used to be hard-coded:
// which host a client dials, on which port, and whether that port speaks TLS.
// The answers differ completely between the two ways this panel can be reached:
//
//   tunnel : a Cloudflare edge terminates TLS on 443 and relays to us. The host
//            is the edge hostname (*.trycloudflare.com or a custom domain), the
//            port is an edge https port, and security is always tls.
//   direct : nothing in between. The host is whatever address the VPS answers
//            on, the port is the one this process actually bound, and security
//            is none unless the process was started with --tls-cert/--tls-key.
//
// The mode is explicit (settings.accessMode), never inferred from a leftover
// domain: a stale *.trycloudflare.com value used to keep every generated config
// pointing at a hostname whose tunnel had been asleep for hours.
bool access_mode_direct(const nlohmann::json& s);
bool access_mode_tunnel(const nlohmann::json& s);

// Ports a client should be told about for this domain. In tunnel mode this is
// settings.ports intersected with the ports the edge serves TLS on; in direct
// mode it is exactly the port this process bound (settings.directPort, else the
// live listenPort), because that is the only one anything is listening on.
std::vector<int> effective_ports(const nlohmann::json& s, const std::string& domain);

// Whether a client reaching this port must use TLS. In direct mode this is the
// process's own capability (--tls-cert given or not), NOT a port whitelist: a
// listener without a certificate cannot answer a TLS ClientHello at all.
bool port_uses_tls(const nlohmann::json& s, const std::string& domain, int port);

// Host a client dials when the tunnel is not the entrance.
std::string direct_host(const nlohmann::json& s);

bool is_domain(const std::string& address);
bool is_ipv4(const std::string& address);
bool is_ipv6(const std::string& address);
bool is_https(const nlohmann::json& s, int port);
bool is_base64(const std::string& str);

struct SniHost {
    std::string host;
    std::string sni;
    bool allow_insecure = false;
};
SniHost select_sni_host(const nlohmann::json& s, const std::string& address, const std::string& domain);

// Certificate to pin, or empty.
//
// Only a direct (no-tunnel) deployment terminates TLS itself, and only then is
// the certificate a self-signed one the client has no other way to trust. Behind
// a Cloudflare tunnel the edge presents its OWN publicly trusted certificate, so
// pinning our self-signed leaf there makes every client reject the handshake --
// the pin has no business appearing in a tunnel-mode subscription.
std::string pinned_cert(const nlohmann::json& s);

std::vector<std::string> to_string_list(const nlohmann::json& j, const std::string& key);
std::string join(const std::vector<std::string>& parts, const std::string& sep);

} // namespace bpb::sub
