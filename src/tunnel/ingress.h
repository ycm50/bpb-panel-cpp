#pragma once
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace bpb::tunnel {

// The edge pushes the tunnel's ingress configuration on a dedicated HTTP/2
// stream (cf-cloudflared-proxy-connection-upgrade: update-configuration). The
// body is the same ConfigurationUpdateBody cloudflared decodes:
//
//   {"version":2,"config":{"ingress":[
//       {"hostname":"bytevirt.5704524.xyz","service":"http://localhost:23456"},
//       {"service":"http_status:404"}],
//     "warp-routing":{"enabled":false}}}
//
// This is the only place the public hostname of a *named* tunnel is available
// to us: the connector token (base64 {"a","t","s"}) carries the account, the
// tunnel UUID and the secret, but never the hostname, and the Cloudflare API
// that would answer that question (cfd_tunnel/<id>/configurations) needs a
// separate account API token. The control stream hands it to us for free.
//
// Exposed as pure functions so the parsing can be tested without a live edge.

// Public hostnames in the ingress rules, in the order the edge listed them.
// Wildcard rules ("*.example.com") are kept: they are valid ingress entries
// even though they cannot be used directly as a subscription domain.
inline std::vector<std::string> ingress_hostnames(const std::string& body) {
    std::vector<std::string> out;
    auto j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return out;
    auto cfg = j.find("config");
    if (cfg == j.end() || !cfg->is_object()) return out;
    auto rules = cfg->find("ingress");
    if (rules == cfg->end() || !rules->is_array()) return out;
    for (const auto& rule : *rules) {
        if (!rule.is_object()) continue;
        auto host = rule.find("hostname");
        if (host == rule.end() || !host->is_string()) continue;
        std::string h = host->get<std::string>();
        if (h.empty()) continue;
        out.push_back(std::move(h));
    }
    return out;
}

// Version counter the edge uses to order configuration updates; echoed back in
// the acknowledgement so the edge knows which revision was applied.
inline int ingress_version(const std::string& body) {
    auto j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return 0;
    auto v = j.find("version");
    if (v == j.end() || !v->is_number_integer()) return 0;
    return v->get<int>();
}

// First hostname that can be used as a subscription domain: a wildcard entry
// describes a rule, not an address a client can dial.
inline std::string first_usable_hostname(const std::vector<std::string>& hosts) {
    for (const auto& h : hosts) {
        if (h.rfind("*.", 0) != 0) return h;
    }
    return std::string();
}

// Acknowledgement body, matching cloudflared's pogs.UpdateConfigurationResponse.
inline std::string config_update_ack(int version) {
    return "{\"lastAppliedVersion\":" + std::to_string(version) + "}";
}

} // namespace bpb::tunnel
